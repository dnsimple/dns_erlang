-module(dnssec_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-record(dnssec_test_sample, {
    zonename,
    alg,
    nsec3,
    inception,
    expiration,
    zsk_pl,
    ksk_pl,
    rr_src,
    rr_clean
}).

-record(key_info, {
    priv_key,
    alg,
    tag,
    rr
}).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            zone,
            gen_nsec,
            gen_nsec_badarg,
            gen_nsec3_badarg,
            gen_nsec3_validation,
            gen_nsec_name_order,
            pubkey_gen,
            verify_rrset,
            verify_rrsig_expiry,
            sign_rr_and_rrset_5arg,
            add_keytag_to_cdnskey_test,
            canonical_rrdata_form_test,
            ih_custom_hash_test,
            dsa_sign_verify_test,
            ecdsa_sign_verify_test,
            sample_keys,
            ed25519_basic_test,
            ed448_basic_test
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Terms = data_samples:dnssec(),
    Samples = helper_test_samples(Terms),
    [{dnssec_samples, Samples} | Config].

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    Config.

gen_nsec(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    %% Only process samples where nsec3 is undefined
    [
        validate_nsec_generation(Config, Sample)
     || #dnssec_test_sample{nsec3 = undefined} = Sample <- Samples
    ].

validate_nsec_generation(Config, Sample) ->
    SourceRRs = Sample#dnssec_test_sample.rr_src,
    %% 1. Separate existing NSEC records from the "Clean" zone data
    CleanRRs = [RR || #dns_rr{type = T} = RR <- SourceRRs, T =/= ?DNS_TYPE_NSEC],
    ExpectedNSECs = [RR || #dns_rr{type = T} = RR <- SourceRRs, T =:= ?DNS_TYPE_NSEC],
    %% 2. Generate new NSEC records based on the clean data
    GeneratedNSECs = dnssec:gen_nsec(CleanRRs),
    %% 3. Normalize the generated records (Cycle encoding to match internal format)
    NormalizedNSECs = cycle_nsec_encoding(Config, GeneratedNSECs),
    %% 4. Compare
    ?assertEqual(lists:sort(ExpectedNSECs), lists:sort(NormalizedNSECs)).

gen_nsec_badarg(_Config) ->
    %% gen_nsec/1 requires a SOA in the list
    ?assertError(badarg, dnssec:gen_nsec([])),
    ?assertError(
        badarg,
        dnssec:gen_nsec([
            #dns_rr{
                name = ~"example",
                type = ?DNS_TYPE_A,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
            }
        ])
    ).

gen_nsec3_badarg(_Config) ->
    SOA = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_SOA,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = ~"ns.example",
            rname = ~"hostmaster.example",
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 3600
        }
    },
    NSEC3Param = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_NSEC3PARAM,
        class = ?DNS_CLASS_IN,
        ttl = 0,
        data = #dns_rrdata_nsec3param{
            hash_alg = 1,
            flags = 0,
            iterations = 0,
            salt = <<>>
        }
    },
    %% No SOA
    ?assertError(badarg, dnssec:gen_nsec3([#dns_rr{type = ?DNS_TYPE_A}])),
    %% SOA but no NSEC3PARAM
    ?assertError(badarg, dnssec:gen_nsec3([SOA])),
    %% Name not under zone -> name_mismatch
    ?assertError(
        name_mismatch,
        dnssec:gen_nsec3([
            SOA,
            NSEC3Param,
            #dns_rr{
                name = ~"foo.bar.other",
                type = ?DNS_TYPE_A,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {1, 1, 1, 1}}
            }
        ])
    ).

gen_nsec3_validation(Config) ->
    %% Use a sample that has NSEC3 (nsec3rsasha1 or nsec3dsa)
    Samples = proplists:get_value(dnssec_samples, Config),
    [Sample | _] = [
        S
     || #dnssec_test_sample{nsec3 = N3} = S <- Samples,
        N3 =/= undefined
    ],
    SourceRRs = Sample#dnssec_test_sample.rr_src,
    Generated = dnssec:gen_nsec3(SourceRRs),
    ?assert(length(Generated) >= 1).

gen_nsec_name_order(_Config) ->
    %% Exercise name_order by generating NSEC for zone with
    %% a.example and b.example (different first labels)
    ZoneName = ~"example",
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = ~"ns.example",
            rname = ~"hostmaster.example",
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 3600
        }
    },
    RRs = [
        SOA,
        #dns_rr{
            name = ~"a.example",
            type = ?DNS_TYPE_A,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {1, 1, 1, 1}}
        },
        #dns_rr{
            name = ~"b.example",
            type = ?DNS_TYPE_A,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {2, 2, 2, 2}}
        }
    ],
    Generated = dnssec:gen_nsec(RRs),
    ?assertEqual(3, length(Generated)),
    NSECs = [RR || #dns_rr{type = ?DNS_TYPE_NSEC} = RR <- Generated],
    ?assertEqual(3, length(NSECs)).

%% Simulates wire encoding/decoding to ensure the 'data' field
%% matches the format expected by the test comparison.
cycle_nsec_encoding(_Config, RRs) ->
    lists:map(
        fun(#dns_rr{data = Data} = RR) ->
            Bin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
            NewData = dns_decode:decode_rrdata(Bin, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC),
            RR#dns_rr{data = NewData}
        end,
        RRs
    ).

verify_rrset(Config) ->
    [
        ?assert(dnssec:verify_rrsig(RRSig, RRSet, DNSKeys, Opts))
     || {RRSig, RRSet, DNSKeys, Opts} <- helper_verify_rrset_test_cases(Config)
    ].

verify_rrsig_expiry(_Config) ->
    %% Build a valid-looking RRSIG with inception in the future -> false
    Now = erlang:system_time(second),
    Future = Now + 86400,
    Past = Now - 86400,
    RRSigFuture = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_RRSIG,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_rrsig{
            type_covered = ?DNS_TYPE_SOA,
            alg = ?DNS_ALG_RSASHA256,
            labels = 1,
            original_ttl = 3600,
            inception = Future,
            expiration = Future + 3600,
            keytag = 12345,
            signers_name = ~"example",
            signature = <<0>>
        }
    },
    RRSigExpired = RRSigFuture#dns_rr{
        data = (RRSigFuture#dns_rr.data)#dns_rrdata_rrsig{
            inception = Past,
            expiration = Past
        }
    },
    RR = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_SOA,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = ~"ns.example",
            rname = ~"hostmaster.example",
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 3600
        }
    },
    DNSKey = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = ?DNS_ALG_RSASHA256, public_key = <<>>
        }
    },
    ?assertEqual(false, dnssec:verify_rrsig(RRSigFuture, [RR], [DNSKey], #{now => Now})),
    ?assertEqual(false, dnssec:verify_rrsig(RRSigExpired, [RR], [DNSKey], #{now => Now})).

sign_rr_and_rrset_5arg(_Config) ->
    %% 5-arg sign_rr and sign_rrset (no opts map)
    {_Ed25519Pub, Ed25519Priv} = crypto:generate_key(eddsa, ed25519),
    RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    _ = dnssec:sign_rr([RR], ~"example", 12345, ?DNS_ALG_ED25519, Ed25519Priv),
    _ = dnssec:sign_rrset([RR], ~"example", 12345, ?DNS_ALG_ED25519, Ed25519Priv),
    ok.

add_keytag_to_cdnskey_test(_Config) ->
    CDNSKEY = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_CDNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_cdnskey{
            flags = 0,
            protocol = 3,
            alg = ?DNS_ALG_RSASHA256,
            public_key = <<0, 1, 2, 3>>
        }
    },
    Result = dnssec:add_keytag_to_cdnskey(CDNSKEY),
    ?assertMatch(#dns_rr{type = ?DNS_TYPE_CDNSKEY, data = #dns_rrdata_cdnskey{keytag = _}}, Result).

canonical_rrdata_form_test(_Config) ->
    %% Hit canonical_rrdata_form for record types that lower-case domain names
    ?assertMatch(
        #dns_rrdata_afsdb{hostname = ~"host.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_afsdb{subtype = 1, hostname = ~"HOST.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_cname{dname = ~"cname.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_cname{dname = ~"CNAME.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_dname{dname = ~"dname.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_dname{dname = ~"DNAME.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_dsync{target = ~"target.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_dsync{
            rrtype = 1,
            scheme = 0,
            port = 443,
            target = ~"TARGET.EXAMPLE"
        })
    ),
    ?assertMatch(
        #dns_rrdata_ipseckey{gateway = ~"gateway.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_ipseckey{
            precedence = 10,
            alg = 0,
            gateway = ~"GATEWAY.EXAMPLE",
            public_key = <<>>
        })
    ),
    ?assertMatch(
        #dns_rrdata_ipseckey{gateway = {1, 2, 3, 4}},
        dnssec:canonical_rrdata_form(#dns_rrdata_ipseckey{
            precedence = 10,
            alg = 1,
            gateway = {1, 2, 3, 4},
            public_key = <<>>
        })
    ),
    ?assertMatch(
        #dns_rrdata_kx{exchange = ~"kx.example", preference = 10},
        dnssec:canonical_rrdata_form(#dns_rrdata_kx{preference = 10, exchange = ~"KX.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mb{madname = ~"mb.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_mb{madname = ~"MB.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mg{madname = ~"mg.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_mg{madname = ~"MG.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_minfo{rmailbx = ~"a.example", emailbx = ~"b.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_minfo{
            rmailbx = ~"A.EXAMPLE", emailbx = ~"B.EXAMPLE"
        })
    ),
    ?assertMatch(
        #dns_rrdata_mr{newname = ~"mr.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_mr{newname = ~"MR.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mx{exchange = ~"mx.example", preference = 10},
        dnssec:canonical_rrdata_form(#dns_rrdata_mx{preference = 10, exchange = ~"MX.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_naptr{
            replacement = ~"naptr.example",
            order = 1,
            preference = 1,
            flags = <<>>,
            services = <<>>,
            regexp = <<>>
        },
        dnssec:canonical_rrdata_form(#dns_rrdata_naptr{
            order = 1,
            preference = 1,
            flags = <<>>,
            services = <<>>,
            regexp = <<>>,
            replacement = ~"NAPTR.EXAMPLE"
        })
    ),
    ?assertMatch(
        #dns_rrdata_ns{dname = ~"ns.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_ns{dname = ~"NS.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_nsec{next_dname = ~"next.example", types = []},
        dnssec:canonical_rrdata_form(#dns_rrdata_nsec{next_dname = ~"NEXT.EXAMPLE", types = []})
    ),
    ?assertMatch(
        #dns_rrdata_nxt{dname = ~"nxt.example", types = []},
        dnssec:canonical_rrdata_form(#dns_rrdata_nxt{dname = ~"NXT.EXAMPLE", types = []})
    ),
    ?assertMatch(
        #dns_rrdata_ptr{dname = ~"ptr.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_ptr{dname = ~"PTR.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_rp{mbox = ~"m.example", txt = ~"t.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_rp{mbox = ~"M.EXAMPLE", txt = ~"T.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_rrsig{signers_name = ~"sig.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_rrsig{
            type_covered = ?DNS_TYPE_A,
            alg = 1,
            labels = 1,
            original_ttl = 3600,
            inception = 0,
            expiration = 0,
            keytag = 0,
            signers_name = ~"SIG.EXAMPLE",
            signature = <<>>
        })
    ),
    ?assertMatch(
        #dns_rrdata_rt{host = ~"rt.example", preference = 10},
        dnssec:canonical_rrdata_form(#dns_rrdata_rt{preference = 10, host = ~"RT.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_soa{mname = ~"mname.example", rname = ~"rname.example"},
        dnssec:canonical_rrdata_form(#dns_rrdata_soa{
            mname = ~"MNAME.EXAMPLE",
            rname = ~"RNAME.EXAMPLE",
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 3600
        })
    ),
    ?assertMatch(
        #dns_rrdata_srv{target = ~"srv.example", priority = 0, weight = 0, port = 0},
        dnssec:canonical_rrdata_form(#dns_rrdata_srv{
            priority = 0, weight = 0, port = 0, target = ~"SRV.EXAMPLE"
        })
    ),
    ?assertMatch(
        #dns_rrdata_svcb{target_name = ~"svcb.example", svc_priority = 1},
        dnssec:canonical_rrdata_form(#dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"SVCB.EXAMPLE",
            svc_params = #{}
        })
    ),
    ?assertMatch(
        #dns_rrdata_https{target_name = ~"https.example", svc_priority = 1},
        dnssec:canonical_rrdata_form(#dns_rrdata_https{
            svc_priority = 1,
            target_name = ~"HTTPS.EXAMPLE",
            svc_params = #{}
        })
    ),
    %% Passthrough for unknown type
    ?assertEqual(~"binary", dnssec:canonical_rrdata_form(~"binary")).

ih_custom_hash_test(_Config) ->
    %% ih/4 with custom hash function (not default SHA1)
    CustomHash = fun(Data) -> crypto:hash(sha, Data) end,
    Salt = ~"salt",
    NameWire = <<"example", 0>>,
    Result = dnssec:ih(CustomHash, Salt, NameWire, 2),
    ?assert(is_binary(Result)),
    ?assert(byte_size(Result) =:= 20).

dsa_sign_verify_test(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    DSASample = [S || #dnssec_test_sample{alg = dsa} = S <- Samples],
    [#dnssec_test_sample{zonename = ZoneName, zsk_pl = ZskProps} | _] = DSASample,
    PrivKey = helper_samplekeypl_to_privkey(ZskProps),
    PubKeyRR = generate_key_struct(ZskProps, dsa, ZoneName),
    DNSKeyWithTag = PubKeyRR#key_info.rr,
    RR = #dns_rr{
        name = <<"test.", ZoneName/binary>>,
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    RRSig = dnssec:sign_rrset(
        [RR],
        ZoneName,
        PubKeyRR#key_info.tag,
        PubKeyRR#key_info.alg,
        PrivKey,
        #{inception => 1000000, expiration => 2000000}
    ),
    ?assert(
        dnssec:verify_rrsig(RRSig, [RR], [DNSKeyWithTag], #{now => 1500000})
    ).

ecdsa_sign_verify_test(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    [#dnssec_test_sample{zonename = ZoneName, zsk_pl = ZskProps, alg = Alg} | _] = [
        S
     || #dnssec_test_sample{alg = Alg} = S <- Samples,
        Alg =:= ecdsap256 orelse Alg =:= ecdsap384
    ],
    PrivKey = helper_samplekeypl_to_privkey(ZskProps),
    PubKeyRR = generate_key_struct(ZskProps, Alg, ZoneName),
    DNSKeyWithTag = PubKeyRR#key_info.rr,
    RR = #dns_rr{
        name = <<"test.", ZoneName/binary>>,
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    RRSig = dnssec:sign_rrset(
        [RR],
        ZoneName,
        PubKeyRR#key_info.tag,
        PubKeyRR#key_info.alg,
        PrivKey,
        #{inception => 1000000, expiration => 2000000}
    ),
    ?assert(
        dnssec:verify_rrsig(RRSig, [RR], [DNSKeyWithTag], #{now => 1500000})
    ).

zone(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    %% Run the validation for every sample in the config
    [validate_zone_sample(Config, Sample) || #dnssec_test_sample{alg = rsa} = Sample <- Samples].

generate_key_struct(Props, Alg, ZoneName) ->
    AlgNo = proplists:get_value(alg, Props),
    Flags = proplists:get_value(flags, Props),
    PubKey = helper_samplekeypl_to_pubkey(Props),
    PubKeyForRR = helper_pubkey_to_dnskey_pubkey(Alg, PubKey),
    Data0 = #dns_rrdata_dnskey{
        flags = Flags,
        protocol = 3,
        alg = AlgNo,
        public_key = PubKeyForRR
    },
    %% Calculate Key Tag
    #dns_rrdata_dnskey{keytag = KeyTag} = Data = helper_add_keytag_to_dnskey(Data0),
    %% Create the RR Record
    RR = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = Data
    },
    #key_info{
        priv_key = helper_samplekeypl_to_privkey(Props),
        alg = AlgNo,
        tag = KeyTag,
        rr = RR
    }.

apply_nsec_policies(RRs, _ZoneName, undefined) ->
    %% Standard NSEC
    dnssec:gen_nsec(RRs) ++ RRs;
apply_nsec_policies(RRs, ZoneName, #dns_rrdata_nsec3param{} = Param) ->
    %% NSEC3
    ParamRR = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_NSEC3PARAM,
        ttl = 0,
        data = Param
    },
    RRsWithParam = [ParamRR | RRs],
    dnssec:gen_nsec3(RRsWithParam) ++ RRsWithParam.

%% Simulates encoding to binary and back to ensure data is canonical
cycle_encoding(#dns_rr{class = Class, type = Type, data = Data} = RR) ->
    Bin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
    NewData = dns_decode:decode_rrdata(Bin, Class, Type),
    RR#dns_rr{data = NewData}.

sign_zone_data(RRs, ZoneName, ZSK, KSK, Inception, Expiration) ->
    Opts = #{inception => Inception, expiration => Expiration},
    %% ZSK signs everything
    ZskSigs = dnssec:sign_rr(
        RRs,
        ZoneName,
        ZSK#key_info.tag,
        ZSK#key_info.alg,
        ZSK#key_info.priv_key,
        Opts
    ),
    %% KSK signs only the DNSKEY RRs
    DnsKeyRRs = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    KskSigs = dnssec:sign_rr(
        DnsKeyRRs,
        ZoneName,
        KSK#key_info.tag,
        KSK#key_info.alg,
        KSK#key_info.priv_key,
        Opts
    ),
    KskSigs ++ ZskSigs ++ RRs.

compare_rr_sets(Generated, Expected) ->
    %% Normalise names (lower case, trailing dot, etc) for comparison
    NormFun = fun(#dns_rr{name = Name} = RR) ->
        RR#dns_rr{name = dns_domain:to_lower(Name)}
    end,
    GenSorted = lists:sort([NormFun(RR) || RR <- Generated]),
    ExpSorted = lists:sort([NormFun(RR) || RR <- Expected]),
    ?assertEqual(GenSorted, ExpSorted).

validate_zone_sample(_Config, Sample) ->
    #dnssec_test_sample{
        zonename = ZoneName,
        alg = Alg,
        inception = Inception,
        expiration = Expiration,
        nsec3 = NSEC3,
        zsk_pl = ZskProps,
        ksk_pl = KskProps,
        rr_clean = CleanRRs,
        rr_src = ExpectedRRs
    } = Sample,
    %% 1. Generate Key Structures from Property Lists
    KSK = generate_key_struct(KskProps, Alg, ZoneName),
    ZSK = generate_key_struct(ZskProps, Alg, ZoneName),
    %% 2. Combine Clean RRs with the new DNSKEYs
    BaseRRs = [ZSK#key_info.rr, KSK#key_info.rr | CleanRRs],
    %% 3. Apply Denial of Existence (NSEC/NSEC3)
    ZoneWithNSEC = apply_nsec_policies(BaseRRs, ZoneName, NSEC3),
    %% 4. Simulate Wire Encoding/Decoding (Normalization)
    NormalizedRRs = lists:map(fun cycle_encoding/1, ZoneWithNSEC),
    %% 5. Sign the Zone (ZSK signs all, KSK signs DNSKEYs)
    SignedZone = sign_zone_data(NormalizedRRs, ZoneName, ZSK, KSK, Inception, Expiration),
    %% 6. Final Comparison
    compare_rr_sets(SignedZone, ExpectedRRs).

pubkey_gen(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    [validate_pubkey_generation(Config, Sample) || Sample <- Samples].

validate_pubkey_generation(Config, Sample) ->
    #dnssec_test_sample{
        rr_src = SourceRRs,
        zsk_pl = ZskProps,
        ksk_pl = KskProps
    } = Sample,
    %% 1. Extract Expected DNSKEY Data from source RRs
    ExpectedData = [
        Data
     || #dns_rr{type = ?DNS_TYPE_DNSKEY, data = Data} <- SourceRRs
    ],
    %% 2. Generate DNSKEY Data from Property Lists
    GeneratedData = [
        props_to_dnskey_data(Config, Props)
     || Props <- [ZskProps, KskProps]
    ],
    %% 3. Compare Sorted Sets
    ?assertEqual(lists:sort(ExpectedData), lists:sort(GeneratedData)).

props_to_dnskey_data(_Config, Props) ->
    Key0 = #dns_rrdata_dnskey{
        flags = proplists:get_value(flags, Props),
        protocol = 3,
        alg = proplists:get_value(alg, Props),
        public_key = helper_samplekeypl_to_pubkey(Props)
    },
    helper_add_keytag_to_dnskey(Key0).

sample_keys(Config) ->
    Keys = lists:foldl(
        fun(#dnssec_test_sample{alg = Alg, zsk_pl = A, ksk_pl = B}, Acc) ->
            [{Alg, A}, {Alg, B} | Acc]
        end,
        [],
        proplists:get_value(dnssec_samples, Config)
    ),
    [?assert(test_sample_key(Alg, Proplist)) || {Alg, Proplist} <- Keys].

ed25519_basic_test(_Config) ->
    {Ed25519Pub, Ed25519Priv} = crypto:generate_key(eddsa, ed25519),
    Ed25519RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    Ed25519Sig = dnssec:sign_rrset(
        [Ed25519RR],
        ~"example",
        12345,
        ?DNS_ALG_ED25519,
        Ed25519Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    Ed25519DNSKey = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_ED25519,
            public_key = Ed25519Pub
        }
    },
    Ed25519DNSKeyWithTag = dnssec:add_keytag_to_dnskey(Ed25519DNSKey),
    ?assert(
        dnssec:verify_rrsig(
            Ed25519Sig,
            [Ed25519RR],
            [Ed25519DNSKeyWithTag],
            #{now => 1500000}
        )
    ).

ed448_basic_test(_Config) ->
    {Ed448Pub, Ed448Priv} = crypto:generate_key(eddsa, ed448),
    Ed448RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    Ed448Sig = dnssec:sign_rrset(
        [Ed448RR],
        ~"example",
        12346,
        ?DNS_ALG_ED448,
        Ed448Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    Ed448DNSKey = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_ED448,
            public_key = Ed448Pub
        }
    },
    Ed448DNSKeyWithTag = dnssec:add_keytag_to_dnskey(Ed448DNSKey),
    ?assert(
        dnssec:verify_rrsig(
            Ed448Sig,
            [Ed448RR],
            [Ed448DNSKeyWithTag],
            #{now => 1500000}
        )
    ).

test_sample_key(Alg, Proplist) ->
    PrivKey = helper_samplekeypl_to_privkey(Proplist),
    PubKey = helper_samplekeypl_to_pubkey(Proplist),
    test_sample_key(Alg, PrivKey, PubKey).

test_sample_key(dsa, PrivKey, PubKey) ->
    Sample = ~"1234",
    Sig = crypto:sign(dss, sha, Sample, PrivKey),
    crypto:verify(dss, sha, Sample, Sig, PubKey);
test_sample_key(rsa, PrivKey, PubKey) ->
    Sample = ~"1234",
    Cipher = crypto:sign(rsa, none, Sample, PrivKey, [{rsa_padding, rsa_pkcs1_padding}]),
    true =:= crypto:verify(rsa, none, Sample, Cipher, PubKey, [{rsa_padding, rsa_pkcs1_padding}]);
test_sample_key(ecdsap256, PrivKey, PubKey) ->
    Sample = crypto:hash(sha256, ~"1234"),
    Cipher = crypto:sign(ecdsa, sha256, Sample, [PrivKey, secp256r1]),
    true =:= crypto:verify(ecdsa, sha256, Sample, Cipher, [<<4, PubKey/binary>>, secp256r1]);
test_sample_key(ecdsap384, PrivKey, PubKey) ->
    Sample = crypto:hash(sha384, ~"1234"),
    Cipher = crypto:sign(ecdsa, sha384, Sample, [PrivKey, secp384r1]),
    true =:= crypto:verify(ecdsa, sha384, Sample, Cipher, [<<4, PubKey/binary>>, secp384r1]);
test_sample_key(ed25519, PrivKey, PubKey) ->
    Sample = ~"1234",
    Cipher = crypto:sign(eddsa, none, Sample, [PrivKey, ed25519]),
    true =:= crypto:verify(eddsa, none, Sample, Cipher, [PubKey, ed25519]);
test_sample_key(ed448, PrivKey, PubKey) ->
    Sample = ~"1234",
    Cipher = crypto:sign(eddsa, none, Sample, [PrivKey, ed448]),
    true =:= crypto:verify(eddsa, none, Sample, Cipher, [PubKey, ed448]).

helper_test_samples(Terms) ->
    lists:map(
        fun({ZoneName, KeysRaw, AxfrBin}) ->
            [ZSK, KSK] = lists:foldl(fun extract_zsk_and_ksk/2, [], KeysRaw),
            #dns_message{answers = RR} = dns:decode_message(AxfrBin),
            [{I, E} | _] = extract_rrsig_inception_expiration(RR),
            NSEC3 = extract_nsec3_param(RR),
            Alg = extract_alg_from_name(ZoneName),
            #dnssec_test_sample{
                zonename = iolist_to_binary(ZoneName),
                alg = Alg,
                inception = I,
                expiration = E,
                nsec3 = NSEC3,
                zsk_pl = ZSK,
                ksk_pl = KSK,
                rr_src = lists:usort(RR),
                rr_clean = lists:usort(exclude_rr_clean(RR))
            }
        end,
        Terms
    ).

extract_rrsig_inception_expiration(RR) ->
    lists:usort([
        {D#dns_rrdata_rrsig.inception, D#dns_rrdata_rrsig.expiration}
     || #dns_rr{type = ?DNS_TYPE_RRSIG, data = D} <- RR
    ]).

extract_nsec3_param(RR) ->
    case [P || #dns_rr{type = ?DNS_TYPE_NSEC3PARAM, data = P} <- RR] of
        [#dns_rrdata_nsec3param{} = Param] -> Param;
        [] -> undefined
    end.

extract_zsk_and_ksk(KeyPLRaw, Acc) ->
    KeyPL = [decode_key_proplist_tuple(Tuple) || {_, _} = Tuple <- KeyPLRaw],
    case proplists:get_value(flags, KeyPL) of
        257 -> Acc ++ [KeyPL];
        _ -> [KeyPL] ++ Acc
    end.

decode_key_proplist_tuple({alg, _} = Tuple) ->
    Tuple;
decode_key_proplist_tuple({flags, _} = Tuple) ->
    Tuple;
decode_key_proplist_tuple({name, _} = Tuple) ->
    Tuple;
decode_key_proplist_tuple({private_key, B64}) ->
    {private_key, base64:decode(B64)};
decode_key_proplist_tuple({public_key, B64}) ->
    {public_key, base64:decode(B64)};
decode_key_proplist_tuple({Key, B64}) ->
    Bin = base64:decode(B64),
    Size = byte_size(Bin),
    {Key, <<Size:32, Bin/binary>>}.

exclude_rr_clean(RRs) ->
    RRCleanExclude = [
        ?DNS_TYPE_NSEC,
        ?DNS_TYPE_NSEC3,
        ?DNS_TYPE_NSEC3PARAM,
        ?DNS_TYPE_RRSIG,
        ?DNS_TYPE_DNSKEY
    ],
    [R || #dns_rr{type = T} = R <- RRs, not lists:member(T, RRCleanExclude)].

extract_alg_from_name("ecdsap256-example") ->
    ecdsap256;
extract_alg_from_name("ecdsap384-example") ->
    ecdsap384;
extract_alg_from_name("ed25519-example") ->
    ed25519;
extract_alg_from_name("ed448-example") ->
    ed448;
extract_alg_from_name(ZoneName) ->
    case re:run(ZoneName, "dsa") of
        {match, _} -> dsa;
        nomatch -> rsa
    end.

helper_verify_rrset_test_cases(Config) ->
    lists:flatten(
        [
            begin
                Opts = #{now => Now},
                DNSKeys = [RR || #dns_rr{type = dnskey} = RR <- RRs],
                Map = lists:foldl(
                    fun
                        (
                            #dns_rr{
                                type = rrsig,
                                name = Name,
                                class = Class,
                                data = #dns_rrdata_rrsig{
                                    type_covered = Type
                                }
                            } = RR,
                            Acc
                        ) ->
                            Key = {dns_domain:to_lower(Name), Class, Type},
                            maps:update_with(Key, fun(L) -> L ++ [RR] end, [RR], Acc);
                        (
                            #dns_rr{
                                name = Name,
                                class = Class,
                                type = Type
                            } = RR,
                            Acc
                        ) ->
                            Key = {dns_domain:to_lower(Name), Class, Type},
                            maps:update_with(Key, fun(L) -> L ++ [RR] end, [RR], Acc)
                    end,
                    #{},
                    RRs
                ),
                RRSets = maps:values(Map),
                lists:map(
                    fun(TestRR) ->
                        {RRSigs, RRSet} = lists:partition(
                            fun(#dns_rr{type = Type}) ->
                                Type =:= rrsig
                            end,
                            TestRR
                        ),
                        [
                            {RRSig, RRSet, DNSKeys, Opts}
                         || RRSig <- RRSigs
                        ]
                    end,
                    RRSets
                )
            end
         || #dnssec_test_sample{inception = Now, rr_src = RRs} <-
                proplists:get_value(dnssec_samples, Config)
        ]
    ).

helper_samplekeypl_to_privkey(Proplist) ->
    Alg = proplists:get_value(alg, Proplist),
    helper_samplekeypl_to_privkey(Alg, Proplist).

helper_samplekeypl_to_privkey(DSA, Proplist) when
    DSA =:= ?DNS_ALG_DSA orelse DSA =:= ?DNS_ALG_NSEC3DSA
->
    P = proplists:get_value(p, Proplist),
    Q = proplists:get_value(q, Proplist),
    G = proplists:get_value(g, Proplist),
    X = proplists:get_value(x, Proplist),
    [I || <<L:32, I:L/unit:8>> <- [P, Q, G, X]];
helper_samplekeypl_to_privkey(?DNS_ALG_ECDSAP256SHA256, Proplist) ->
    proplists:get_value(private_key, Proplist);
helper_samplekeypl_to_privkey(?DNS_ALG_ECDSAP384SHA384, Proplist) ->
    proplists:get_value(private_key, Proplist);
helper_samplekeypl_to_privkey(?DNS_ALG_ED25519, Proplist) ->
    proplists:get_value(private_key, Proplist);
helper_samplekeypl_to_privkey(?DNS_ALG_ED448, Proplist) ->
    proplists:get_value(private_key, Proplist);
helper_samplekeypl_to_privkey(_RSA, Proplist) ->
    E = proplists:get_value(public_exp, Proplist),
    N = proplists:get_value(modulus, Proplist),
    D = proplists:get_value(private_exp, Proplist),
    [I || <<L:32, I:L/unit:8>> <- [E, N, D]].

helper_samplekeypl_to_pubkey(Proplist) ->
    Alg = proplists:get_value(alg, Proplist),
    helper_samplekeypl_to_pubkey(Alg, Proplist).

helper_samplekeypl_to_pubkey(DSA, Proplist) when
    DSA =:= ?DNS_ALG_DSA orelse DSA =:= ?DNS_ALG_NSEC3DSA
->
    %% [P, Q, G, Y] as integers for crypto and for DNSKEY (encode_dsa_key accepts integers).
    P = proplists:get_value(p, Proplist),
    Q = proplists:get_value(q, Proplist),
    G = proplists:get_value(g, Proplist),
    Y = proplists:get_value(y, Proplist),
    [I || <<L:32, I:L/unit:8>> <- [P, Q, G, Y]];
helper_samplekeypl_to_pubkey(?DNS_ALG_ECDSAP256SHA256, Proplist) ->
    proplists:get_value(public_key, Proplist);
helper_samplekeypl_to_pubkey(?DNS_ALG_ECDSAP384SHA384, Proplist) ->
    proplists:get_value(public_key, Proplist);
helper_samplekeypl_to_pubkey(?DNS_ALG_ED25519, Proplist) ->
    proplists:get_value(public_key, Proplist);
helper_samplekeypl_to_pubkey(?DNS_ALG_ED448, Proplist) ->
    proplists:get_value(public_key, Proplist);
helper_samplekeypl_to_pubkey(_RSA, Proplist) ->
    E = proplists:get_value(public_exp, Proplist),
    N = proplists:get_value(modulus, Proplist),
    [I || <<L:32, I:L/unit:8>> <- [E, N]].

helper_strip_leading_zeros(<<0, Rest/binary>>) ->
    helper_strip_leading_zeros(Rest);
helper_strip_leading_zeros(B) ->
    B.

helper_pubkey_to_dnskey_pubkey(rsa, [E, M]) ->
    MBin = helper_strip_leading_zeros(binary:encode_unsigned(M)),
    EBin = helper_strip_leading_zeros(binary:encode_unsigned(E)),
    ESize = byte_size(EBin),
    if
        ESize =< 16#FF ->
            <<ESize:8, EBin:ESize/binary, MBin/binary>>;
        ESize =< 16#FFFF ->
            <<0, ESize:16, EBin:ESize/binary, MBin/binary>>;
        true ->
            erlang:error(badarg)
    end;
%% DNSKEY public_key for DSA must be [P, Q, G, Y] for dns_encode:encode_dsa_key/1 (list, not wire binary).
helper_pubkey_to_dnskey_pubkey(dsa, [P, Q, G, Y]) ->
    [P, Q, G, Y];
helper_pubkey_to_dnskey_pubkey(nsec3dsa, [P, Q, G, Y]) ->
    [P, Q, G, Y];
helper_pubkey_to_dnskey_pubkey(ecdsap256, PubKey) when is_binary(PubKey) ->
    PubKey;
helper_pubkey_to_dnskey_pubkey(ecdsap384, PubKey) when is_binary(PubKey) ->
    PubKey;
helper_pubkey_to_dnskey_pubkey(ed25519, PubKey) when is_binary(PubKey) ->
    PubKey;
helper_pubkey_to_dnskey_pubkey(ed448, PubKey) when is_binary(PubKey) ->
    PubKey.

helper_add_keytag_to_dnskey(#dns_rrdata_dnskey{} = DNSKey) ->
    RR = #dns_rr{type = ?DNS_TYPE_DNSKEY, data = DNSKey},
    (dnssec:add_keytag_to_dnskey(RR))#dns_rr.data.

helper_fmt(Fmt, Args) ->
    iolist_to_binary(io_lib:format(Fmt, Args)).
