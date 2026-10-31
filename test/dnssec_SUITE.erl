-module(dnssec_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("public_key/include/public_key.hrl").

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
            gen_nsec_name_order_fqdn_and_relative,
            pubkey_gen,
            verify_rrset,
            verify_rrsig_expiry,
            sign_rr_and_rrset_5arg,
            add_keytag_to_cdnskey_test,
            keytag_known_answers,
            canonical_rrdata_form_test,
            canonical_form_matches_bind,
            rfc_known_answers,
            signatures_verify_independently,
            algorithms_checked_against_other_implementations,
            unsupported_algorithm,
            malformed_signature,
            malformed_input_does_not_verify,
            verify_needs_zone_key,
            verify_needs_rrsig_key_tag,
            verify_rejects_rrsig_not_fitting_rrset,
            verify_wildcard_expansion,
            verify_with_decremented_ttl,
            signers_name_in_canonical_form,
            ih_custom_hash_test,
            dsa_sign_verify_test,
            ecdsa_sign_verify_test,
            ecdsa_p256_wire_format_test,
            ecdsa_p384_wire_format_test,
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

%% One name spelled both as an FQDN and relatively is two distinct binaries that split to the same
%% labels, so it slips past name_order/2's equality clauses and into the label comparison.
gen_nsec_name_order_fqdn_and_relative(_Config) ->
    RRs = [
        #dns_rr{
            name = ~"a.example",
            type = ?DNS_TYPE_A,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {1, 1, 1, 1}}
        },
        #dns_rr{
            name = ~"a.example.",
            type = ?DNS_TYPE_TXT,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [~"v=1"]}
        }
    ],
    ?assertEqual(2, length(dnssec:gen_nsec(~"example", RRs, 3600))).

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

%% Every RRSIG in the AXFRs of the zones BIND signed in data_samples:dnssec/0
%% verifies. This test once matched the record types as atoms, found no
%% signatures and passed without verifying anything, while ECDSA and DSA
%% signatures did not verify at all, so every zone must yield signatures. Each
%% verifies with the DNSKEYs as the wire decoder gives them, RSA and DSA keys as
%% integers, and with their keys as RDATA bytes, as a zone file gives them.
verify_rrset(Config) ->
    PerZone = helper_verify_rrset_test_cases(Config),
    ?assertEqual(length(proplists:get_value(dnssec_samples, Config)), length(PerZone)),
    [?assertNotEqual([], Cases, Zone) || {Zone, Cases} <- PerZone],
    Failed = [
        {Zone, Form, length(Bad), length(Cases)}
     || {Zone, Cases} <- PerZone,
        {Form, KeyForm} <- [{decoded, fun(Keys) -> Keys end}, {bytes, fun dnskeys_as_bytes/1}],
        Bad <- [
            [
                RRSig
             || {RRSig, RRSet, DNSKeys, Opts} <- Cases,
                not dnssec:verify_rrsig(RRSig, RRSet, KeyForm(DNSKeys), Opts)
            ]
        ],
        Bad =/= []
    ],
    ?assertEqual([], Failed).

%% The DNSKEYs with their keys as the RDATA's bytes, as a zone file gives them
dnskeys_as_bytes(DNSKeys) ->
    [
        begin
            <<_:32, Key/binary>> = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
            RR#dns_rr{data = Data#dns_rrdata_dnskey{public_key = Key}}
        end
     || #dns_rr{data = Data} = RR <- DNSKeys
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

%% The other keytag tests only assert that *a* keytag was produced, so nothing
%% pinned the arithmetic. RFC4034 Appendix B computes it over the whole DNSKEY
%% RDATA as ac += (i & 1) ? key[i] : key[i] << 8, then ac += (ac >> 16) & 0xFFFF.
%% These expectations are computed by hand from that definition rather than from
%% the implementation, so they would catch a change to either the word summing or
%% the carry fold.
keytag_known_answers(_Config) ->
    Cases = [
        %% flags=256, protocol=3, alg=5, key = <<1,2>>
        %% 0x01<<8 + 0x00 + 0x03<<8 + 0x05 + 0x01<<8 + 0x02
        %%   = 256 + 0 + 768 + 5 + 256 + 2 = 1287, no carry
        {<<1, 0, 3, 5, 1, 2>>, 1287},
        %% Odd length: the final byte sits at an even index, so it is shifted.
        %% 65280 + 255 + 65280 + 255 + 65280 = 196350; 196350 >> 16 = 2;
        %%   196352 band 0xFFFF = 65280
        {<<255, 255, 255, 255, 255>>, 65280},
        %% Even length, exercises the carry fold:
        %% 3 * 0xFFFF = 196605; 196605 >> 16 = 2; 196607 band 0xFFFF = 65535
        {<<255, 255, 255, 255, 255, 255>>, 65535}
    ],
    [
        begin
            DNSKEY = dns_decode:decode_rrdata(<<>>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, Rdata),
            ?assertEqual(Expected, DNSKEY#dns_rrdata_dnskey.keytag, Rdata),
            %% CDNSKEY shares the computation
            CDNSKEY = dns_decode:decode_rrdata(<<>>, ?DNS_CLASS_IN, ?DNS_TYPE_CDNSKEY, Rdata),
            ?assertEqual(Expected, CDNSKEY#dns_rrdata_cdnskey.keytag, Rdata)
        end
     || {Rdata, Expected} <- Cases
    ],
    %% add_keytag_to_dnskey/1 must agree with decoding the same RDATA
    [
        begin
            <<Flags:16, Protocol:8, Alg:8, PublicKey/binary>> = Rdata,
            RR = #dns_rr{
                name = ~"example",
                type = ?DNS_TYPE_DNSKEY,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_dnskey{
                    flags = Flags, protocol = Protocol, alg = Alg, public_key = PublicKey
                }
            },
            #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} =
                dnssec:add_keytag_to_dnskey(RR),
            ?assertEqual(Expected, KeyTag, Rdata)
        end
     || {Rdata, Expected} <- Cases
    ].

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
    %% RFC3597§7, RFC4034§6.2: types defined after the list keep the case of their
    %% RDATA names in canonical form, and RFC6840§5.1 takes NSEC off the list
    [
        ?assertEqual(Data, dnssec:canonical_rrdata_form(Data))
     || Data <- [
            #dns_rrdata_dsync{rrtype = 1, scheme = 0, port = 443, target = ~"TARGET.EXAMPLE"},
            #dns_rrdata_ipseckey{
                precedence = 10, alg = 0, gateway = ~"GATEWAY.EXAMPLE", public_key = <<>>
            },
            #dns_rrdata_ipseckey{
                precedence = 10, alg = 1, gateway = {1, 2, 3, 4}, public_key = <<>>
            },
            #dns_rrdata_nsec{next_dname = ~"NEXT.EXAMPLE", types = []},
            #dns_rrdata_svcb{svc_priority = 1, target_name = ~"SVCB.EXAMPLE", svc_params = #{}},
            #dns_rrdata_https{svc_priority = 1, target_name = ~"HTTPS.EXAMPLE", svc_params = #{}},
            #dns_rrdata_lp{preference = 10, fqdn = ~"LP.EXAMPLE"},
            #dns_rrdata_amtrelay{
                precedence = 10,
                discovery_optional = false,
                relay_type = 3,
                relay = ~"Relay.EXAMPLE"
            },
            #dns_rrdata_hip{
                alg = 2, hit = <<1:128>>, public_key = <<1>>, rendezvous_servers = [~"RVS.Example"]
            }
        ]
    ],
    %% RFC4034§6.2: PX and SIG are on the list, so their names are lowercased
    ?assertEqual(
        #dns_rrdata_px{preference = 10, map822 = ~"net2.it", mapx400 = ~"prmd-net2.c-it"},
        dnssec:canonical_rrdata_form(
            #dns_rrdata_px{preference = 10, map822 = ~"NET2.it", mapx400 = ~"PRMD-net2.C-it"}
        )
    ),
    Sig = #dns_rrdata_sig{
        type_covered = ?DNS_TYPE_A,
        alg = ?DNS_ALG_RSASHA1,
        labels = 2,
        original_ttl = 3600,
        expiration = 1,
        inception = 1,
        keytag = 1,
        signers_name = ~"Example.COM",
        signature = <<1>>
    },
    ?assertEqual(
        Sig#dns_rrdata_sig{signers_name = ~"example.com"}, dnssec:canonical_rrdata_form(Sig)
    ),
    %% Passthrough for unknown type
    ?assertEqual(~"binary", dnssec:canonical_rrdata_form(~"binary")).

%% Signatures BIND 9.20's dnssec-signzone made with an Ed25519 key over records
%% whose RDATA names are mixed case. RFC3597§7 and RFC6840§5.1 keep that case in
%% canonical form for these types, so each signature verifies and, Ed25519 being
%% deterministic, signing the record again gives the same signature. Lowercasing
%% the names failed both ways: BIND's signatures did not verify here, and BIND's
%% dnssec-verify refused the signatures made here.
canonical_form_matches_bind(_Config) ->
    {PrivateKey, DNSKey} = bind_ed25519_key(),
    RR = fun(Name, Type, TTL, Data) ->
        #dns_rr{name = Name, type = Type, ttl = TTL, data = Data}
    end,
    Cases = [
        {
            RR(~"www.example.test", ?DNS_TYPE_HTTPS, 3600, #dns_rrdata_https{
                svc_priority = 1, target_name = ~"Svc.Example.Test", svc_params = #{}
            }),
            ~"RE6RL2LW1of41k02UJEzpaMgC0vYnsuH/BmTFWdRD2n3wDkqLzeR+YPSD7WZYATcM4jQqlQe2wvUVQAbbsxnBA=="
        },
        {
            RR(~"svc.example.test", ?DNS_TYPE_SVCB, 3600, #dns_rrdata_svcb{
                svc_priority = 1, target_name = ~"Pool.Example.Test", svc_params = #{}
            }),
            ~"2PnKixZDSwGYi8WXgBSE069yjdzio0WibFl5FFTd8rGfOusdLjbcwPf4EO7qF5sfuJmmxZ36Y379w0NjVSFgCQ=="
        },
        {
            RR(~"gw.example.test", ?DNS_TYPE_IPSECKEY, 3600, #dns_rrdata_ipseckey{
                precedence = 10,
                alg = 2,
                gateway = ~"Gateway.Example.Test",
                public_key = base64:decode(~"AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==")
            }),
            ~"q5q2f82buUGEIiK/ZgmLnPkRXbo69YnukAI/B3AN1DUTkRrHtjDLpDYz54Dh178pUOuC4WR4ydAsil865YuvCQ=="
        },
        {
            RR(~"_dsync.example.test", ?DNS_TYPE_DSYNC, 3600, #dns_rrdata_dsync{
                rrtype = ?DNS_TYPE_CDS, scheme = 1, port = 5359, target = ~"Notify.Example.Test"
            }),
            ~"dANBkdGSRCWilD5Hn99KsxoMIyAxBfOZb7Zb3sU8gl0aHfQvKTVWMZo8+W67y9VGoOZan5yeRTlo2VFzGPxZCQ=="
        },
        {
            RR(~"svc.example.test", ?DNS_TYPE_NSEC, 300, #dns_rrdata_nsec{
                next_dname = ~"Upper.example.test",
                types = [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_SVCB]
            }),
            ~"f8WrRhx2nabRer0MaMS0OmaQnqkyQMind0T0deG7Y7N3VuKEFkpdBUkV7Ep60fCA9TRTVEkuSkJj6wkqtQ57AA=="
        }
    ],
    %% 2026-10-01 to 2026-11-01
    {Inception, Expiration} = {1790812800, 1793491200},
    [
        begin
            Signature = base64:decode(Sig),
            [#dns_rr{data = #dns_rrdata_rrsig{signature = Signed}} = RRSig] = dnssec:sign_rr(
                [Data],
                ~"example.test",
                29059,
                ?DNS_ALG_ED25519,
                PrivateKey,
                #{inception => Inception, expiration => Expiration}
            ),
            ?assertEqual(Signature, Signed, Type),
            ?assert(
                dnssec:verify_rrsig(
                    RRSig#dns_rr{
                        data = (RRSig#dns_rr.data)#dns_rrdata_rrsig{signature = Signature}
                    },
                    [Data],
                    [DNSKey],
                    #{now => Inception + 1}
                ),
                Type
            )
        end
     || {#dns_rr{type = Type} = Data, Sig} <- Cases
    ].

%% The worked examples in the RFCs that define each algorithm: keys, signed data
%% and signatures that another implementation made. For each, the DNSKEY's key
%% tag and DS digest match, the RRSIG verifies and stops verifying when its
%% signature or the RRset changes, and the private key signs the RRset again.
%% RSA PKCS#1 v1.5, Ed25519 and Ed448 sign deterministically, so that gives the
%% RFC's RRSIG exactly. ECDSA does not, so signatures_verify_independently/1
%% checks the ECDSA signatures made here.
rfc_known_answers(_Config) ->
    [rfc_known_answer(Vector) || Vector <- rfc_vectors()].

rfc_known_answer(#{source := Source, alg := Alg, private_key := PrivateKey, zone := Zone} = Vector) ->
    {ok, RRs} = dns_zone:parse_string(Zone),
    [
        #dns_rr{name = Owner, data = #dns_rrdata_dnskey{alg = Alg, keytag = KeyTag} = KeyData} =
            DNSKey
    ] =
        [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [
        #dns_rr{
            data =
                #dns_rrdata_rrsig{
                    alg = Alg,
                    keytag = KeyTag,
                    signers_name = Signer,
                    inception = Inception,
                    expiration = Expiration,
                    signature = Signature
                } = SigData
        } = RRSig
    ] = [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    RRSet = [
        RR
     || #dns_rr{type = Type} = RR <- RRs,
        not lists:member(Type, [?DNS_TYPE_DNSKEY, ?DNS_TYPE_DS, ?DNS_TYPE_RRSIG])
    ],
    Opts = #{now => Inception},
    %% The zone parser and the wire decoder each compute the key tag
    #dns_rr{data = #dns_rrdata_dnskey{keytag = WireKeyTag}} =
        DecodedDNSKey = dnssec:add_keytag_to_dnskey(DNSKey),
    ?assertEqual(KeyTag, WireKeyTag, Source),
    case [Data || #dns_rr{type = ?DNS_TYPE_DS, data = Data} <- RRs] of
        [#dns_rrdata_ds{keytag = KeyTag, alg = Alg, digest_type = DigestType, digest = Digest}] ->
            ?assertEqual(Digest, ds_digest(DigestType, Owner, KeyData), Source);
        [] ->
            ok
    end,
    %% With the key as presentation format gives it and as the wire decoder does:
    %% for RSA one is the RFC3110 bytes, the other [E, M]
    ?assert(dnssec:verify_rrsig(RRSig, RRSet, [DNSKey], Opts), Source),
    ?assert(dnssec:verify_rrsig(RRSig, RRSet, [DecodedDNSKey], Opts), Source),
    <<Head:(byte_size(Signature) - 1)/binary, Last>> = Signature,
    Flipped = SigData#dns_rrdata_rrsig{signature = <<Head/binary, (Last bxor 1)>>},
    ?assertNot(dnssec:verify_rrsig(RRSig#dns_rr{data = Flipped}, RRSet, [DNSKey], Opts), Source),
    Moved = [RR#dns_rr{name = <<"moved.", Name/binary>>} || #dns_rr{name = Name} = RR <- RRSet],
    MovedRRSig = RRSig#dns_rr{name = <<"moved.", (RRSig#dns_rr.name)/binary>>},
    ?assertNot(dnssec:verify_rrsig(MovedRRSig, Moved, [DNSKey], Opts), Source),
    Signed = dnssec:sign_rrset(
        RRSet, Signer, KeyTag, Alg, PrivateKey, #{inception => Inception, expiration => Expiration}
    ),
    ?assert(dnssec:verify_rrsig(Signed, RRSet, [DNSKey], Opts), Source),
    case Vector of
        #{deterministic := true} -> ?assertEqual(RRSig, Signed, Source);
        #{deterministic := false} -> ok
    end.

%% RFC4034§5.1.4: the digest is over the owner name in canonical form and the
%% DNSKEY RDATA
ds_digest(DigestType, Owner, KeyData) ->
    Hash = maps:get(DigestType, #{2 => sha256, 4 => sha384}),
    RData = dns_encode:encode_rrdata(?DNS_CLASS_IN, KeyData),
    Wire = dns_domain:to_wire(dns_domain:to_lower(Owner)),
    crypto:hash(Hash, [Wire, RData]).

%% ECDSA and DSA hash the signed data themselves, once (RFC6605§4, RFC2536§3).
%% dnssec.erl once hashed it first as well, and so signed the hash of the hash:
%% its signatures verified with itself and with nothing else, since signing and
%% verifying shared the mistake. This builds the signed data by hand, from
%% RFC4034§3.1.8.1 and §6.2, and checks signatures with crypto alone, sharing no
%% code with dnssec.erl. It accepts the RFC6605 examples' own signatures, which
%% shows the check itself is right, and must accept the ones signed here.
signatures_verify_independently(Config) ->
    [
        begin
            {ok, RRs} = dns_zone:parse_string(Zone),
            [#dns_rrdata_dnskey{public_key = PublicKey}] =
                [D || #dns_rr{type = ?DNS_TYPE_DNSKEY, data = D} <- RRs],
            [
                #dns_rrdata_rrsig{
                    keytag = KeyTag,
                    inception = Inception,
                    expiration = Expiration,
                    signature = Theirs
                }
            ] = [D || #dns_rr{type = ?DNS_TYPE_RRSIG, data = D} <- RRs],
            Check = fun(Signature) ->
                SignedData = signed_data_by_hand(
                    Alg, KeyTag, ~"example.net", Inception, Expiration
                ),
                ecdsa_verify_by_hand(Alg, PublicKey, SignedData, Signature)
            end,
            ?assert(Check(Theirs), Source),
            Ours = sign_by_hand_rrset(
                Alg, KeyTag, ~"example.net", PrivateKey, Inception, Expiration
            ),
            ?assert(Check(Ours), Source)
        end
     || #{source := Source, alg := Alg, private_key := PrivateKey, zone := Zone} <- rfc_vectors(),
        Alg =:= ?DNS_ALG_ECDSAP256SHA256 orelse Alg =:= ?DNS_ALG_ECDSAP384SHA384
    ],
    %% No RFC has a DSA example, so the keys BIND signed the DSA sample zones with
    DSA = [
        begin
            #key_info{tag = KeyTag, alg = Alg} = generate_key_struct(ZSK, dsa, Zone),
            [P, Q, G, Y] = helper_samplekeypl_to_pubkey(ZSK),
            Ours = sign_by_hand_rrset(
                Alg, KeyTag, Zone, helper_samplekeypl_to_privkey(ZSK), 1000000, 2000000
            ),
            <<_T, R:20/unit:8, S:20/unit:8>> = Ours,
            Der = public_key:der_encode('Dss-Sig-Value', #'Dss-Sig-Value'{r = R, s = S}),
            SignedData = signed_data_by_hand(Alg, KeyTag, Zone, 1000000, 2000000),
            ?assert(crypto:verify(dss, sha, SignedData, Der, [P, Q, G, Y]), Zone)
        end
     || #dnssec_test_sample{alg = dsa, zonename = Zone, zsk_pl = ZSK} <-
            proplists:get_value(dnssec_samples, Config)
    ],
    ?assertEqual(2, length(DSA)).

%% www.Zone. 3600 IN A 192.0.2.1, signed by Zone
sign_by_hand_rrset(Alg, KeyTag, Zone, PrivateKey, Inception, Expiration) ->
    RR = #dns_rr{
        name = <<"www.", Zone/binary>>,
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    #dns_rr{data = #dns_rrdata_rrsig{signature = Signature}} = dnssec:sign_rrset(
        [RR], Zone, KeyTag, Alg, PrivateKey, #{inception => Inception, expiration => Expiration}
    ),
    Signature.

%% RFC4034§3.1.8.1: the RRSIG RDATA without its signature, then the RRset, here
%% www.Zone. 3600 IN A 192.0.2.1, in canonical form (RFC4034§6.2)
signed_data_by_hand(Alg, KeyTag, Zone, Inception, Expiration) ->
    Owner = <<"www.", Zone/binary>>,
    Labels = length(binary:split(Owner, ~".", [global, trim_all])),
    signed_data_by_hand(Alg, KeyTag, Zone, Owner, Inception, Expiration, ?DNS_TYPE_A, Labels).

%% The same, with the RRset's owner, and the RRSIG RDATA's type covered and
%% labels, as given
signed_data_by_hand(Alg, KeyTag, Signer, Owner, Inception, Expiration, TypeCovered, Labels) ->
    <<TypeCovered:16, Alg, Labels, 3600:32, Expiration:32, Inception:32, KeyTag:16,
        (wire_by_hand(Signer))/binary, (wire_by_hand(Owner))/binary, ?DNS_TYPE_A:16,
        ?DNS_CLASS_IN:16, 3600:32, 4:16, 192, 0, 2, 1>>.

wire_by_hand(Name) ->
    Labels = binary:split(string:lowercase(Name), ~".", [global, trim_all]),
    <<<<<<(byte_size(Label)), Label/binary>> || Label <- Labels>>/binary, 0>>.

%% RFC6605§4: the signature is r | s, the key x | y
ecdsa_verify_by_hand(?DNS_ALG_ECDSAP256SHA256, PublicKey, SignedData, Signature) ->
    ecdsa_verify_by_hand(sha256, secp256r1, 32, PublicKey, SignedData, Signature);
ecdsa_verify_by_hand(?DNS_ALG_ECDSAP384SHA384, PublicKey, SignedData, Signature) ->
    ecdsa_verify_by_hand(sha384, secp384r1, 48, PublicKey, SignedData, Signature).

ecdsa_verify_by_hand(Hash, Curve, Size, PublicKey, SignedData, Signature) ->
    <<R:Size/unit:8, S:Size/unit:8>> = Signature,
    Der = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}),
    crypto:verify(ecdsa, Hash, SignedData, Der, [<<4, PublicKey/binary>>, Curve]).

%% Every algorithm dnssec.erl signs with is checked against signatures another
%% implementation made, either an RFC example in rfc_known_answers/1 or a zone
%% BIND signed in verify_rrset/1. The algorithms are found by asking sign_rrset
%% for each number, so one added there without vectors here fails this test.
algorithms_checked_against_other_implementations(Config) ->
    Implemented = [Alg || Alg <- lists:seq(0, 255), implemented(Alg)],
    FromRFCs = [Alg || #{alg := Alg} <- rfc_vectors()],
    FromBIND = [
        Alg
     || #dnssec_test_sample{rr_src = RRs} <- proplists:get_value(dnssec_samples, Config),
        #dns_rr{type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{alg = Alg}} <- RRs
    ],
    ?assertNotEqual([], Implemented),
    ?assertEqual(Implemented, lists:usort(FromRFCs ++ FromBIND)).

implemented(Alg) ->
    RR = #dns_rr{name = ~"example", type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}},
    try dnssec:sign_rrset([RR], ~"example", 1, Alg, <<>>, #{}) of
        _ -> true
    catch
        error:{unsupported_algorithm, Alg} -> false;
        error:_ -> true
    end.

%% A signature in an algorithm dnssec.erl does not implement does not verify,
%% and signing in one fails saying so. Both used to fail with function_clause,
%% the first even with no key to try.
unsupported_algorithm(_Config) ->
    RR = #dns_rr{name = ~"example", type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}},
    RRSig = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_RRSIG,
        data = #dns_rrdata_rrsig{
            type_covered = ?DNS_TYPE_A,
            alg = 200,
            labels = 1,
            original_ttl = 3600,
            inception = 0,
            expiration = 2000000,
            keytag = 1,
            signers_name = ~"example",
            signature = <<1, 2, 3>>
        }
    },
    DNSKey = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = 200, public_key = <<1, 2, 3>>, keytag = 1
        }
    },
    ?assertNot(dnssec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1000000})),
    ?assertNot(dnssec:verify_rrsig(RRSig, [RR], [], #{now => 1000000})),
    ?assertError(
        {unsupported_algorithm, 200}, dnssec:sign_rrset([RR], ~"example", 1, 200, <<>>, #{})
    ).

%% RFC4035§5.3.2: a validator puts the RRset in the signed data with the
%% RRSIG's original TTL, and an RRset from a cache arrives with less. Any TTL
%% but the original crashed verify_rrsig/4 with function_clause.
verify_with_decremented_ttl(_Config) ->
    [#{zone := Zone} | _] = [V || #{alg := ?DNS_ALG_RSASHA256} = V <- rfc_vectors()],
    {ok, RRs} = dns_zone:parse_string(Zone),
    [DNSKey] = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [#dns_rr{data = #dns_rrdata_rrsig{inception = Now}} = RRSig] =
        [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    Cached = [RR#dns_rr{ttl = 1234} || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
    ?assert(dnssec:verify_rrsig(RRSig, Cached, [DNSKey], #{now => Now})).

%% Keys and signatures come off the wire: one too short for its algorithm does
%% not verify, rather than crashing
malformed_signature(_Config) ->
    [#{zone := Zone} | _] = [V || #{alg := ?DNS_ALG_RSASHA256} = V <- rfc_vectors()],
    {ok, RRs} = dns_zone:parse_string(Zone),
    [DNSKey] = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [#dns_rr{data = #dns_rrdata_rrsig{inception = Now} = Data} = RRSig] =
        [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    RRSet = [RR || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
    Short = RRSig#dns_rr{data = Data#dns_rrdata_rrsig{signature = <<1, 2, 3>>}},
    ?assertNot(dnssec:verify_rrsig(Short, RRSet, [DNSKey], #{now => Now})),
    #dns_rr{data = KeyData} = DNSKey,
    ShortKey = DNSKey#dns_rr{data = KeyData#dns_rrdata_dnskey{public_key = <<1, 2, 3>>}},
    ?assertNot(dnssec:verify_rrsig(RRSig, RRSet, [ShortKey], #{now => Now})).

%% Keys and signatures off the wire can be any bytes. For every algorithm
%% dnssec.erl implements, and one it does not, keys and signatures of every
%% length near the ones the algorithms use, the shapes of DSA's keys among
%% them, verify nothing, and raise nothing:
%% a validator must answer false, not crash. So does an empty RRset, or no key.
malformed_input_does_not_verify(_Config) ->
    %% 213 and 405 are T, Q, P, G and Y for T = 0 and T = 8, which take DSA's keys
    %% to crypto
    Lengths = [
        0, 1, 3, 20, 21, 31, 32, 33, 41, 56, 57, 63, 64, 65, 95, 96, 97, 114, 128, 213, 404, 405
    ],
    RR = #dns_rr{name = ~"example", type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}},
    Results = [
        {Alg, KeyLength, SigLength,
            dnssec:verify_rrsig(
                malformed_rrsig(Alg, pseudo_random_bytes(SigLength, 2)),
                [RR],
                [malformed_dnskey(Alg, Key)],
                #{now => 1000000}
            )}
     || Alg <- [Alg || Alg <- lists:seq(0, 255), implemented(Alg)] ++ [200],
        KeyLength <- Lengths,
        Key <- [malformed_key(KeyLength)],
        SigLength <- Lengths
    ],
    ?assertEqual([], [Result || {_, _, _, Verified} = Result <- Results, Verified =/= false]),
    RRSig = malformed_rrsig(?DNS_ALG_RSASHA256, <<1, 2, 3>>),
    DNSKey = malformed_dnskey(?DNS_ALG_RSASHA256, <<1, 2, 3>>),
    ?assertNot(dnssec:verify_rrsig(RRSig, [], [DNSKey], #{now => 1000000})),
    ?assertNot(dnssec:verify_rrsig(RRSig, [RR], [], #{now => 1000000})),
    ?assertNot(
        dnssec:verify_rrsig(RRSig, [RR], [malformed_dnskey(?DNS_ALG_RSASHA256, [1, 2, 3])], #{
            now => 1000000
        })
    ).

malformed_rrsig(Alg, Signature) ->
    #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_RRSIG,
        data = #dns_rrdata_rrsig{
            type_covered = ?DNS_TYPE_A,
            alg = Alg,
            labels = 1,
            original_ttl = 3600,
            inception = 0,
            expiration = 2000000,
            keytag = 1,
            signers_name = ~"example",
            signature = Signature
        }
    }.

malformed_dnskey(Alg, Key) ->
    #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        data = #dns_rrdata_dnskey{
            flags = 257, protocol = 3, alg = Alg, public_key = Key, keytag = 1
        }
    }.

%% Random bytes, but a DSA key's T where the length is that of one
malformed_key(Length) when Length =:= 213; Length =:= 405 ->
    <<((Length - 213) div 24), (pseudo_random_bytes(Length - 1, 1))/binary>>;
malformed_key(Length) ->
    pseudo_random_bytes(Length, 1).

%% The same bytes every run, so a failure here always reproduces
pseudo_random_bytes(Length, Seed) ->
    Blocks = [crypto:hash(sha512, <<Seed:32, I:32>>) || I <- lists:seq(0, Length div 64)],
    binary:part(iolist_to_binary(Blocks), 0, Length).

%% RFC4034§2.1.1: a DNSKEY without the Zone Key flag, bit 7, "MUST NOT be used
%% to verify RRSIGs". The SEP flag, bit 15, makes no difference. The DNSKEY's key
%% tag is left as the RRSIG names it, so only the flags differ.
verify_needs_zone_key(_Config) ->
    [#{zone := Zone} | _] = [V || #{alg := ?DNS_ALG_ECDSAP256SHA256} = V <- rfc_vectors()],
    {ok, RRs} = dns_zone:parse_string(Zone),
    [#dns_rr{data = #dns_rrdata_dnskey{flags = 257} = KeyData} = DNSKey] =
        [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [#dns_rr{data = #dns_rrdata_rrsig{inception = Now}} = RRSig] =
        [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    RRSet = [RR || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
    WithFlags = fun(Flags) -> DNSKey#dns_rr{data = KeyData#dns_rrdata_dnskey{flags = Flags}} end,
    ?assert(dnssec:verify_rrsig(RRSig, RRSet, [WithFlags(257)], #{now => Now})),
    ?assert(dnssec:verify_rrsig(RRSig, RRSet, [WithFlags(256)], #{now => Now})),
    ?assertNot(dnssec:verify_rrsig(RRSig, RRSet, [WithFlags(1)], #{now => Now})),
    ?assertNot(dnssec:verify_rrsig(RRSig, RRSet, [WithFlags(0)], #{now => Now})).

%% RFC4035§5.3.1: an RRSIG verifies only with the DNSKEY its signer's name,
%% algorithm and key tag name. The RFC6605§6.1 key, a KSK, published as a ZSK as
%% well has another key tag, and does not verify the KSK's RRSIG.
verify_needs_rrsig_key_tag(_Config) ->
    [#{zone := Zone} | _] = [V || #{alg := ?DNS_ALG_ECDSAP256SHA256} = V <- rfc_vectors()],
    {ok, RRs} = dns_zone:parse_string(Zone),
    [#dns_rr{data = #dns_rrdata_dnskey{flags = 257} = KeyData} = KSK] =
        [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [#dns_rr{data = #dns_rrdata_rrsig{inception = Now}} = RRSig] =
        [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    RRSet = [RR || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
    #dns_rr{data = #dns_rrdata_dnskey{keytag = ZSKTag}} =
        ZSK = dnssec:add_keytag_to_dnskey(KSK#dns_rr{data = KeyData#dns_rrdata_dnskey{flags = 256}}),
    ?assertNotEqual(55648, ZSKTag),
    ?assert(dnssec:verify_rrsig(RRSig, RRSet, [ZSK, KSK], #{now => Now})),
    ?assertNot(dnssec:verify_rrsig(RRSig, RRSet, [ZSK], #{now => Now})),
    %% The signer's name names the key whatever its case, and with or without the
    %% final dot a zone file gives the DNSKEY's owner
    #dns_rr{data = SigData} = RRSig,
    Spelled = RRSig#dns_rr{data = SigData#dns_rrdata_rrsig{signers_name = ~"Example.NET"}},
    ?assert(dnssec:verify_rrsig(Spelled, RRSet, [KSK], #{now => Now})).

%% RFC4035§5.3.1: an RRSIG whose owner or class is not the RRset's, whose type
%% covered is not the RRset's type, or whose labels field counts more labels
%% than the RRset's owner has, does not verify, even signed by the zone's own
%% key. Signed by hand with the RFC8080§6 Ed25519 key: the RRSIG with the right
%% fields verifies, the others do not.
verify_rejects_rrsig_not_fitting_rrset(_Config) ->
    [#{private_key := PrivateKey, zone := Zone} | _] =
        [V || #{alg := ?DNS_ALG_ED25519} = V <- rfc_vectors()],
    {ok, RRs} = dns_zone:parse_string(Zone),
    [#dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = DNSKey] =
        [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    RR = #dns_rr{
        name = ~"www.example.com",
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    %% RFC4035§5.3.2: an RRSIG whose labels field counts fewer labels than its
    %% owner has signs the wildcard it names
    SignedOwners = #{0 => ~"*", 1 => ~"*.com", 2 => ~"*.example.com"},
    RRSig = fun(Signer, TypeCovered, Labels) ->
        SignedData = signed_data_by_hand(
            ?DNS_ALG_ED25519,
            KeyTag,
            Signer,
            maps:get(Labels, SignedOwners, ~"www.example.com"),
            1000000,
            2000000,
            TypeCovered,
            Labels
        ),
        #dns_rr{
            name = ~"www.example.com",
            type = ?DNS_TYPE_RRSIG,
            ttl = 3600,
            data = #dns_rrdata_rrsig{
                type_covered = TypeCovered,
                alg = ?DNS_ALG_ED25519,
                labels = Labels,
                original_ttl = 3600,
                inception = 1000000,
                expiration = 2000000,
                keytag = KeyTag,
                signers_name = Signer,
                signature = crypto:sign(eddsa, none, SignedData, [PrivateKey, ed25519])
            }
        }
    end,
    Verify = fun(RRSIG) -> dnssec:verify_rrsig(RRSIG, [RR], [DNSKey], #{now => 1500000}) end,
    Fits = RRSig(~"example.com", ?DNS_TYPE_A, 3),
    ?assert(Verify(Fits)),
    ?assert(Verify(Fits#dns_rr{name = ~"WWW.Example.COM."})),
    ?assertNot(Verify(Fits#dns_rr{name = ~"other.example.com"})),
    ?assertNot(Verify(Fits#dns_rr{class = ?DNS_CLASS_CH})),
    ?assertNot(Verify(RRSig(~"example.com", ?DNS_TYPE_MX, 3))),
    ?assertNot(Verify(RRSig(~"example.com", ?DNS_TYPE_A, 4))),
    %% The same key published at another name: it verifies the RRsets at or
    %% under that name, whose zone it can be, and no others, nor the expansions
    %% of a wildcard above that name
    SignedBy = fun(Signer, Labels) ->
        Key = DNSKey#dns_rr{name = Signer},
        dnssec:verify_rrsig(RRSig(Signer, ?DNS_TYPE_A, Labels), [RR], [Key], #{now => 1500000})
    end,
    ?assert(SignedBy(~"com", 3)),
    ?assert(SignedBy(~"com", 1)),
    ?assert(SignedBy(~"example.com", 2)),
    ?assert(SignedBy(~"www.example.com", 3)),
    ?assertNot(SignedBy(~"example.com", 1)),
    ?assertNot(SignedBy(~"www.example.com", 2)),
    ?assertNot(SignedBy(~"example.net", 3)),
    ?assertNot(SignedBy(~"ample.com", 3)),
    ?assertNot(SignedBy(~"a.www.example.com", 3)).

%% RFC4035§5.3.2: an answer a wildcard was expanded into carries the wildcard's
%% RRSIG, whose labels field counts the wildcard's labels but not its "*", and is
%% verified as "*" and that many of the answer's last labels. The zones BIND
%% signed in data_samples:dnssec/0 hold wildcards: their RRSIGs verify for names
%% under them, and not for a name that is not.
verify_wildcard_expansion(Config) ->
    Wildcards = [
        Case
     || {_Zone, Cases} <- helper_verify_rrset_test_cases(Config),
        {_, [#dns_rr{name = <<"*.", _/binary>>} | _], _, _} = Case <- Cases
    ],
    ?assertNotEqual([], Wildcards),
    %% The answer, its RRSIG with it, at Name
    Verify = fun(RRSig, RRSet, Keys, Opts, Name) ->
        dnssec:verify_rrsig(
            RRSig#dns_rr{name = Name}, [RR#dns_rr{name = Name} || RR <- RRSet], Keys, Opts
        )
    end,
    [
        begin
            <<"*.", Parent/binary>> = Wildcard,
            ?assert(dnssec:verify_rrsig(RRSig, RRSet, Keys, Opts), Wildcard),
            ?assert(Verify(RRSig, RRSet, Keys, Opts, <<"a.", Parent/binary>>)),
            ?assert(Verify(RRSig, RRSet, Keys, Opts, <<"a.B.", Parent/binary>>)),
            %% Under another parent the wildcard's last labels do not match
            ?assertNot(Verify(RRSig, RRSet, Keys, Opts, <<"a.not", Parent/binary>>))
        end
     || {RRSig, [#dns_rr{name = Wildcard} | _] = RRSet, Keys, Opts} <- Wildcards
    ].

rsa_private_key(E, N, D) ->
    [binary:decode_unsigned(base64:decode(B)) || B <- [E, N, D]].

%% The examples of RFC5702§6, RFC6605§6 and RFC8080§6 as the RFCs print them,
%% but for RFC8080's RRSIGs, which are the ones its verified erratum 4935
%% corrects: the RFC's own have no algorithm and a label count that counts the
%% root. The erratum's open a second parenthesis they never close, left out here.
rfc_vectors() ->
    [
        #{
            source => ~"RFC5702§6.1",
            alg => ?DNS_ALG_RSASHA256,
            private_key => rsa_private_key(
                ~"AQAB",
                ~"wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==",
                ~"UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ=="
            ),
            deterministic => true,
            zone =>
                ~"""
            example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
                my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
                kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}
            www.example.net. 3600  IN  A  192.0.2.91
            www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
                20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
                l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
                cFYK/lPtPiVYP4bwg==);{id = 9033}
            """
        },
        #{
            source => ~"RFC5702§6.2",
            alg => ?DNS_ALG_RSASHA512,
            private_key => rsa_private_key(
                ~"AQAB",
                ~"0eg1M5b563zoq4k5ZEOnWmd2/BvpjzedJVdfIsDcMuuhE5SQ3pfQ7qmdaeMlC6Nf8DKGoUPGPXe06cP27/WRODtxXquSUytkO0kJDk8KX8PtA0+yBWwy7UnZDyCkynO00Uuk8HPVtZeMO1pHtlAGVnc8VjXZlNKdyit99waaE4s=",
                ~"rFS1IPbJllFFgFc33B5DDlC1egO8e81P4fFadODbp56V7sphKa6AZQCx8NYAew6VXFFPAKTw41QdHnK5kIYOwxvfFDjDcUGza88qbjyrDPSJenkeZbISMUSSqy7AMFzEolkk6WSn6k3thUVRgSlqDoOV3SEIAsrB043XzGrKIVE="
            ),
            deterministic => true,
            zone =>
                ~"""
            example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
                p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
                xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
                pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
                );{id = 3740 (zsk), size = 1024b}
            www.example.net. 3600  IN  A  192.0.2.91
            www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
                20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
                6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
                eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
                DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
                =);{id = 3740}
            """
        },
        #{
            source => ~"RFC6605§6.1",
            alg => ?DNS_ALG_ECDSAP256SHA256,
            private_key => base64:decode(~"GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ="),
            deterministic => false,
            zone =>
                ~"""
            example.net. 3600 IN DNSKEY 257 3 13 (
                GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
                krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
            example.net. 3600 IN DS 55648 13 2 (
                b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
                e2770ce6d6e37df61d17 )
            www.example.net. 3600 IN A 192.0.2.1
            www.example.net. 3600 IN RRSIG A 13 3 3600 (
                20100909100439 20100812100439 55648 example.net.
                qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
                yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )
            """
        },
        #{
            source => ~"RFC6605§6.2",
            alg => ?DNS_ALG_ECDSAP384SHA384,
            private_key => base64:decode(
                ~"WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR"
            ),
            deterministic => false,
            zone =>
                ~"""
            example.net. 3600 IN DNSKEY 257 3 14 (
                xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
                w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
                /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )
            example.net. 3600 IN DS 10771 14 4 (
                72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
                d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
                6df983d6 )
            www.example.net. 3600 IN A 192.0.2.1
            www.example.net. 3600 IN RRSIG A 14 3 3600 (
                20100909102025 20100812102025 10771 example.net.
                /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
                95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
                WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )
            """
        },
        #{
            source => ~"RFC8080§6, erratum 4935, example 1",
            alg => ?DNS_ALG_ED25519,
            private_key => base64:decode(~"ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI="),
            deterministic => true,
            zone =>
                ~"""
            example.com. 3600 IN DNSKEY 257 3 15 (
                l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
            example.com. 3600 IN DS 3613 15 2 (
                3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
                a304b )
            example.com. 3600 IN MX 10 mail.example.com.
            example.com. 3600 IN RRSIG MX 15 2 3600 (
                1440021600 1438207200 3613 example.com.
                oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f
                x8A4M3e23mRZ9VrbpMngwcrqNAg== )
            """
        },
        #{
            source => ~"RFC8080§6, erratum 4935, example 2",
            alg => ?DNS_ALG_ED25519,
            private_key => base64:decode(~"DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY="),
            deterministic => true,
            zone =>
                ~"""
            example.com. 3600 IN DNSKEY 257 3 15 (
                zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs= )
            example.com. 3600 IN DS 35217 15 2 (
                401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c
                6614c )
            example.com. 3600 IN MX 10 mail.example.com.
            example.com. 3600 IN RRSIG MX 15 2 3600 (
                1440021600 1438207200 35217 example.com.
                zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQ
                oSm5poJ7gD7AQR0O7KuI5k2pcBg== )
            """
        },
        #{
            source => ~"RFC8080§6, erratum 4935, example 3",
            alg => ?DNS_ALG_ED448,
            private_key => base64:decode(
                ~"xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA"
            ),
            deterministic => true,
            zone =>
                ~"""
            example.com. 3600 IN DNSKEY 257 3 16 (
                3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
                1FYYUcJKm1MDpJtIA )
            example.com. 3600 IN DS 9713 16 2 (
                6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2
                b19c7 )
            example.com. 3600 IN MX 10 mail.example.com.
            example.com. 3600 IN RRSIG MX 16 2 3600 (
                1440021600 1438207200 9713 example.com.
                3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0am
                xWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/
                JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA )
            """
        },
        #{
            source => ~"RFC8080§6, erratum 4935, example 4",
            alg => ?DNS_ALG_ED448,
            private_key => base64:decode(
                ~"WEykD3ht3MHkU8iH4uVOLz8JLwtRBSqiBoM6fF72+Mrp/u5gjxuB1DV6NnPO2BlZdz4hdSTkOdOA"
            ),
            deterministic => true,
            zone =>
                ~"""
            example.com. 3600 IN DNSKEY 257 3 16 (
                kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcN
                Lp5HlHAMy12VoISsA )
            example.com. 3600 IN DS 38353 16 2 (
                645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba
                28af4 )
            example.com. 3600 IN MX 10 mail.example.com.
            example.com. 3600 IN RRSIG MX 16 2 3600 (
                1440021600 1438207200 38353 example.com.
                E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57C
                SnZqjJP41O/9l4m0AsQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81
                Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA )
            """
        }
    ].

%% RFC4034§3.1.8.1, RFC6840§5.1: the signer's name goes into the signed data in
%% canonical form, lowercased. It went in as given, so signing with Example.Test
%% gave a signature BIND's for example.test did not match, and an RRSIG received
%% with Example.Test as its signer did not verify. The signature is BIND's, from
%% canonical_form_matches_bind/1.
signers_name_in_canonical_form(_Config) ->
    {PrivateKey, DNSKey} = bind_ed25519_key(),
    HTTPS = #dns_rr{
        name = ~"www.example.test",
        type = ?DNS_TYPE_HTTPS,
        ttl = 3600,
        data = #dns_rrdata_https{
            svc_priority = 1, target_name = ~"Svc.Example.Test", svc_params = #{}
        }
    },
    Signature = base64:decode(
        ~"RE6RL2LW1of41k02UJEzpaMgC0vYnsuH/BmTFWdRD2n3wDkqLzeR+YPSD7WZYATcM4jQqlQe2wvUVQAbbsxnBA=="
    ),
    {Inception, Expiration} = {1790812800, 1793491200},
    [#dns_rr{data = #dns_rrdata_rrsig{} = Data} = RRSig] = dnssec:sign_rr(
        [HTTPS],
        ~"Example.TEST",
        29059,
        ?DNS_ALG_ED25519,
        PrivateKey,
        #{inception => Inception, expiration => Expiration}
    ),
    ?assertMatch(#dns_rrdata_rrsig{signers_name = ~"example.test", signature = Signature}, Data),
    Received = RRSig#dns_rr{data = Data#dns_rrdata_rrsig{signers_name = ~"Example.TEST"}},
    ?assert(dnssec:verify_rrsig(Received, [HTTPS], [DNSKey], #{now => Inception + 1})).

%% The Ed25519 key, in the zone example.test, BIND signed the records with
bind_ed25519_key() ->
    PrivateKey = base64:decode(~"6OjVqw6yokJES96M8iQmufPniuPAUpSpAsfB2hQPSp0="),
    DNSKey = #dns_rr{
        name = ~"example.test",
        type = ?DNS_TYPE_DNSKEY,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_ED25519,
            public_key = base64:decode(~"VXEsoU69+/ogdTfuDFJteyXjQM3WniI/Jc11+fLq4Dg="),
            keytag = 29059
        }
    },
    {PrivateKey, DNSKey}.

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

%% RFC 6605 §4: ECDSA P-256 signatures must be exactly 64 bytes (r || s, 32+32).
%% Before the fix, crypto:sign returned DER which is variable-length (~70-72 bytes).
ecdsa_p256_wire_format_test(_Config) ->
    {Pub, Priv} = crypto:generate_key(ecdh, secp256r1),
    %% Strip the 0x04 uncompressed point prefix for DNSKEY public_key format
    <<4, PubRaw/binary>> = Pub,
    RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    RRSig = dnssec:sign_rrset(
        [RR],
        ~"example",
        zone_key_tag(?DNS_ALG_ECDSAP256SHA256, PubRaw),
        ?DNS_ALG_ECDSAP256SHA256,
        Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    #dns_rr{data = #dns_rrdata_rrsig{signature = Sig}} = RRSig,
    %% The signature MUST be exactly 64 bytes per RFC 6605
    ?assertEqual(64, byte_size(Sig)),
    %% Verify round-trip: the wire-format signature must verify correctly
    DNSKey = dnssec:add_keytag_to_dnskey(#dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP256SHA256,
            public_key = PubRaw
        }
    }),
    ?assert(dnssec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1500000})).

%% RFC 6605 §4: ECDSA P-384 signatures must be exactly 96 bytes (r || s, 48+48).
ecdsa_p384_wire_format_test(_Config) ->
    {Pub, Priv} = crypto:generate_key(ecdh, secp384r1),
    <<4, PubRaw/binary>> = Pub,
    RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    RRSig = dnssec:sign_rrset(
        [RR],
        ~"example",
        zone_key_tag(?DNS_ALG_ECDSAP384SHA384, PubRaw),
        ?DNS_ALG_ECDSAP384SHA384,
        Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    #dns_rr{data = #dns_rrdata_rrsig{signature = Sig}} = RRSig,
    %% The signature MUST be exactly 96 bytes per RFC 6605
    ?assertEqual(96, byte_size(Sig)),
    %% Verify round-trip
    DNSKey = dnssec:add_keytag_to_dnskey(#dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP384SHA384,
            public_key = PubRaw
        }
    }),
    ?assert(dnssec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1500000})).

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
        zone_key_tag(?DNS_ALG_ED25519, Ed25519Pub),
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
        zone_key_tag(?DNS_ALG_ED448, Ed448Pub),
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

%% The key tag of a zone key for example holding Key, which an RRSIG must carry
%% for the key to verify it (RFC4035§5.3.1)
zone_key_tag(Alg, Key) ->
    DNSKey = #dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        data = #dns_rrdata_dnskey{flags = 256, protocol = 3, alg = Alg, public_key = Key}
    },
    #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = dnssec:add_keytag_to_dnskey(DNSKey),
    KeyTag.

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
    [
        {Zone, helper_verify_rrset_test_cases(Now, RRs)}
     || #dnssec_test_sample{zonename = Zone, inception = Now, rr_src = RRs} <-
            proplists:get_value(dnssec_samples, Config)
    ].

helper_verify_rrset_test_cases(Now, RRs) ->
    Opts = #{now => Now},
    DNSKeys = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    %% Group each RRset with the RRSIGs covering it, by owner, class and type
    RRSets = lists:foldl(
        fun
            (
                #dns_rr{type = ?DNS_TYPE_RRSIG, data = #dns_rrdata_rrsig{type_covered = Type}} = RR,
                Acc
            ) ->
                add_to_rrset(RR, Type, Acc);
            (#dns_rr{type = Type} = RR, Acc) ->
                add_to_rrset(RR, Type, Acc)
        end,
        #{},
        RRs
    ),
    lists:flatmap(
        fun(RRSetAndSigs) ->
            {RRSigs, RRSet} = lists:partition(
                fun(#dns_rr{type = Type}) -> Type =:= ?DNS_TYPE_RRSIG end, RRSetAndSigs
            ),
            [{RRSig, RRSet, DNSKeys, Opts} || RRSig <- RRSigs]
        end,
        maps:values(RRSets)
    ).

add_to_rrset(#dns_rr{name = Name, class = Class} = RR, Type, Acc) ->
    Key = {dns_domain:to_lower(Name), Class, Type},
    maps:update_with(Key, fun(L) -> L ++ [RR] end, [RR], Acc).

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
