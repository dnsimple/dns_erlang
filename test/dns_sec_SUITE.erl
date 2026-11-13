-module(dns_sec_SUITE).
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
            gen_nsec_name_order_fqdn_and_relative,
            pubkey_gen,
            dnskey_public_key_layout,
            key_fields_read_back,
            rfc5702_known_answers,
            verify_rrset,
            verify_with_zone_text_dnskeys,
            rsa_key_rfc3110_rules_out_verifies_nothing,
            dsa_key_with_wide_t_verifies_nothing,
            verify_with_list_key_raises,
            sign_with_integer_key_raises,
            verify_rrsig_expiry,
            sign_rr_and_rrset_5arg,
            sign_leaves_rrsigs_unsigned,
            sign_rrset_rejects_records_of_other_rrsets,
            sign_rr_groups_owner_names_as_names,
            add_keytag_to_cdnskey_test,
            keytag_known_answers,
            keytag_rsamd5,
            canonical_rrdata_form_test,
            canonical_form_matches_bind,
            signers_name_in_canonical_form,
            duplicate_rrs_signed_once,
            verify_with_counted_down_ttl,
            verify_unimplemented_algorithm,
            ih_custom_hash_test,
            dsa_sign_verify_test,
            ecdsa_sign_verify_test,
            ecdsa_p256_wire_format_test,
            ecdsa_p384_wire_format_test,
            ecdsa_rfc6605_examples,
            sample_keys,
            ed25519_basic_test,
            ed448_basic_test,
            mldsa44_draft_example,
            mldsa44_expanded_key,
            mldsa44_malformed_does_not_verify
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
    GeneratedNSECs = dns_sec:gen_nsec(CleanRRs),
    %% 3. Normalize the generated records (Cycle encoding to match internal format)
    NormalizedNSECs = cycle_nsec_encoding(Config, GeneratedNSECs),
    %% 4. Compare
    ?assertEqual(lists:sort(ExpectedNSECs), lists:sort(NormalizedNSECs)).

gen_nsec_badarg(_Config) ->
    %% gen_nsec/1 requires a SOA in the list
    ?assertError(badarg, dns_sec:gen_nsec([])),
    ?assertError(
        badarg,
        dns_sec:gen_nsec([
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
    ?assertError(badarg, dns_sec:gen_nsec3([#dns_rr{type = ?DNS_TYPE_A}])),
    %% SOA but no NSEC3PARAM
    ?assertError(badarg, dns_sec:gen_nsec3([SOA])),
    %% Name not under zone -> name_mismatch
    ?assertError(
        name_mismatch,
        dns_sec:gen_nsec3([
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
    Generated = dns_sec:gen_nsec3(SourceRRs),
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
    Generated = dns_sec:gen_nsec(RRs),
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
    ?assertEqual(2, length(dns_sec:gen_nsec(~"example", RRs, 3600))).

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

%% Every RRSIG BIND made in the sample zones verifies. It checks there are RRSIGs
%% of every algorithm in the zones, as matching record types as atoms, which
%% records never carry, once left it none to verify.
verify_rrset(Config) ->
    Cases = helper_verify_rrset_test_cases(Config),
    Algs = [Alg || {#dns_rr{data = #dns_rrdata_rrsig{alg = Alg}}, _, _, _} <- Cases],
    ?assertEqual([3, 5, 6, 7, 8, 10, 13, 14], lists:usort(Algs)),
    [
        ?assert(dns_sec:verify_rrsig(RRSig, RRSet, DNSKeys, Opts))
     || {RRSig, RRSet, DNSKeys, Opts} <- Cases
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
    ?assertEqual(false, dns_sec:verify_rrsig(RRSigFuture, [RR], [DNSKey], #{now => Now})),
    ?assertEqual(false, dns_sec:verify_rrsig(RRSigExpired, [RR], [DNSKey], #{now => Now})).

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
    _ = dns_sec:sign_rr([RR], ~"example", 12345, ?DNS_ALG_ED25519, Ed25519Priv),
    _ = dns_sec:sign_rrset([RR], ~"example", 12345, ?DNS_ALG_ED25519, Ed25519Priv),
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
    Result = dns_sec:add_keytag_to_cdnskey(CDNSKEY),
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
        {<<255, 255, 255, 255, 255, 255>>, 65535},
        %% The example zone keys of RFC9563§6, SM2SM3, and RFC9558§2.2, ECC-GOST12, with the
        %% key tags those RFCs give
        {
            <<1, 0, 3, 17,
                (base64:decode(
                    ~"7EQ32PTAp+1ac6R9Ze2nfB8pPc2OJqkHSjugALr4SuD9awuQxhfw7wMpiXv7JK4/VwwTrCxJwu+qUuDsgoBK4w=="
                ))/binary>>,
            65042
        },
        {
            <<1, 0, 3, 23,
                (base64:decode(
                    ~"XGiiHlKUJd5fSeAK5O3L4tUNCPxs4pGqum6wKbqjdkquIQ8nOXrilXZ9HcY8b2AETkWrtWHfwvJD4twPPJFQSA=="
                ))/binary>>,
            47355
        }
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
                dns_sec:add_keytag_to_dnskey(RR),
            ?assertEqual(Expected, KeyTag, Rdata)
        end
     || {Rdata, Expected} <- Cases
    ].

%% RFC4034 Appendix B.1, as erratum 193 corrects it: algorithm 1, RSA/MD5, takes its key tag
%% from the third- and second-to-last octets of the modulus, which ends the RDATA. dnspython
%% 2.9.1's dns.dnssec.key_id gives these key tags for the same keys, where the Appendix B
%% checksum gives 63057, 50386 and 26146.
keytag_rsamd5(_Config) ->
    Modulus = fun(Size, K) ->
        <<First, Rest/binary>> = <<<<((I * K + 3) rem 256)>> || I <- lists:seq(1, Size)>>,
        <<(First bor 16#80), Rest/binary>>
    end,
    Cases = [
        {<<3, 1, 0, 1, (Modulus(64, 7))/binary>>, 46524},
        {<<3, 1, 0, 1, (Modulus(65, 11))/binary>>, 47299},
        %% RFC3110§2: the exponent's length in three octets
        {<<0, 0, 3, 1, 0, 1, (Modulus(128, 13))/binary>>, 26998}
    ],
    [
        begin
            Rdata = <<1, 0, 3, ?DNS_ALG_RSAMD5, PublicKey/binary>>,
            DNSKEY = dns_decode:decode_rrdata(<<>>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, Rdata),
            ?assertEqual(Expected, DNSKEY#dns_rrdata_dnskey.keytag, Expected),
            CDNSKEY = dns_decode:decode_rrdata(<<>>, ?DNS_CLASS_IN, ?DNS_TYPE_CDNSKEY, Rdata),
            ?assertEqual(Expected, CDNSKEY#dns_rrdata_cdnskey.keytag, Expected),
            RR = #dns_rr{
                name = ~"example",
                type = ?DNS_TYPE_DNSKEY,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_dnskey{
                    flags = 256, protocol = 3, alg = ?DNS_ALG_RSAMD5, public_key = PublicKey
                }
            },
            #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = dns_sec:add_keytag_to_dnskey(RR),
            ?assertEqual(Expected, KeyTag, Expected)
        end
     || {PublicKey, Expected} <- Cases
    ].

canonical_rrdata_form_test(_Config) ->
    %% Hit canonical_rrdata_form for record types that lower-case domain names
    ?assertMatch(
        #dns_rrdata_afsdb{hostname = ~"host.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_afsdb{subtype = 1, hostname = ~"HOST.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_cname{dname = ~"cname.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_cname{dname = ~"CNAME.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_dname{dname = ~"dname.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_dname{dname = ~"DNAME.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_kx{exchange = ~"kx.example", preference = 10},
        dns_sec:canonical_rrdata_form(#dns_rrdata_kx{preference = 10, exchange = ~"KX.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mb{madname = ~"mb.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_mb{madname = ~"MB.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mg{madname = ~"mg.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_mg{madname = ~"MG.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_minfo{rmailbx = ~"a.example", emailbx = ~"b.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_minfo{
            rmailbx = ~"A.EXAMPLE", emailbx = ~"B.EXAMPLE"
        })
    ),
    ?assertMatch(
        #dns_rrdata_mr{newname = ~"mr.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_mr{newname = ~"MR.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_mx{exchange = ~"mx.example", preference = 10},
        dns_sec:canonical_rrdata_form(#dns_rrdata_mx{preference = 10, exchange = ~"MX.EXAMPLE"})
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
        dns_sec:canonical_rrdata_form(#dns_rrdata_naptr{
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
        dns_sec:canonical_rrdata_form(#dns_rrdata_ns{dname = ~"NS.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_nxt{dname = ~"nxt.example", types = []},
        dns_sec:canonical_rrdata_form(#dns_rrdata_nxt{dname = ~"NXT.EXAMPLE", types = []})
    ),
    ?assertMatch(
        #dns_rrdata_ptr{dname = ~"ptr.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_ptr{dname = ~"PTR.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_rp{mbox = ~"m.example", txt = ~"t.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_rp{mbox = ~"M.EXAMPLE", txt = ~"T.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_rrsig{signers_name = ~"sig.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_rrsig{
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
        dns_sec:canonical_rrdata_form(#dns_rrdata_rt{preference = 10, host = ~"RT.EXAMPLE"})
    ),
    ?assertMatch(
        #dns_rrdata_soa{mname = ~"mname.example", rname = ~"rname.example"},
        dns_sec:canonical_rrdata_form(#dns_rrdata_soa{
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
        dns_sec:canonical_rrdata_form(#dns_rrdata_srv{
            priority = 0, weight = 0, port = 0, target = ~"SRV.EXAMPLE"
        })
    ),
    %% RFC3597§7, RFC4034§6.2: types defined after the list keep the case of their
    %% RDATA names in canonical form, and RFC6840§5.1 takes NSEC off the list
    [
        ?assertEqual(Data, dns_sec:canonical_rrdata_form(Data))
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
        dns_sec:canonical_rrdata_form(
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
        Sig#dns_rrdata_sig{signers_name = ~"example.com"}, dns_sec:canonical_rrdata_form(Sig)
    ),
    %% Passthrough for unknown type
    ?assertEqual(~"binary", dns_sec:canonical_rrdata_form(~"binary")).

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
            [#dns_rr{data = #dns_rrdata_rrsig{signature = Signed}} = RRSig] = dns_sec:sign_rr(
                [Data],
                ~"example.test",
                29059,
                ?DNS_ALG_ED25519,
                PrivateKey,
                #{inception => Inception, expiration => Expiration}
            ),
            ?assertEqual(Signature, Signed, Type),
            ?assert(
                dns_sec:verify_rrsig(
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
    [#dns_rr{data = #dns_rrdata_rrsig{} = Data} = RRSig] = dns_sec:sign_rr(
        [HTTPS],
        ~"Example.TEST",
        29059,
        ?DNS_ALG_ED25519,
        PrivateKey,
        #{inception => Inception, expiration => Expiration}
    ),
    ?assertMatch(#dns_rrdata_rrsig{signers_name = ~"example.test", signature = Signature}, Data),
    Received = RRSig#dns_rr{data = Data#dns_rrdata_rrsig{signers_name = ~"Example.TEST"}},
    ?assert(dns_sec:verify_rrsig(Received, [HTTPS], [DNSKey], #{now => Inception + 1})).

%% RFC4034§6.3: a duplicate record goes into the RRset's canonical form once, as
%% validators take it. It went in twice, so a signature made here did not verify
%% elsewhere, and one made elsewhere did not verify here. The signature is BIND's
%% over the record once, from canonical_form_matches_bind/1.
duplicate_rrs_signed_once(_Config) ->
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
    Sign = fun(RRs) ->
        dns_sec:sign_rr(
            RRs,
            ~"example.test",
            29059,
            ?DNS_ALG_ED25519,
            PrivateKey,
            #{inception => Inception, expiration => Expiration}
        )
    end,
    [#dns_rr{data = #dns_rrdata_rrsig{} = Data} = RRSig] = Sign([HTTPS, HTTPS]),
    ?assertEqual(Signature, Data#dns_rrdata_rrsig.signature),
    BIND = RRSig#dns_rr{data = Data#dns_rrdata_rrsig{signature = Signature}},
    ?assert(dns_sec:verify_rrsig(BIND, [HTTPS, HTTPS], [DNSKey], #{now => Inception + 1})),
    %% Duplicates in canonical form, which lowercases the names in MX RDATA
    MX = fun(Exchange) ->
        #dns_rr{
            name = ~"example.test",
            type = ?DNS_TYPE_MX,
            ttl = 3600,
            data = #dns_rrdata_mx{preference = 10, exchange = Exchange}
        }
    end,
    ?assertEqual(
        Sign([MX(~"mail.example.test")]),
        Sign([MX(~"Mail.Example.Test"), MX(~"mail.example.test")])
    ).

%% RFC4035§5.3.2: the signed data has the RRSIG's original TTL in every record,
%% whatever TTL the records arrived with, as from a cache they arrive counted down,
%% and the RRSIG with them. Unless the first record's TTL was the original TTL,
%% verifying raised function_clause. The RRSIG is BIND's, from
%% canonical_form_matches_bind/1.
verify_with_counted_down_ttl(_Config) ->
    {_PrivateKey, DNSKey} = bind_ed25519_key(),
    HTTPS = fun(TTL) ->
        #dns_rr{
            name = ~"www.example.test",
            type = ?DNS_TYPE_HTTPS,
            ttl = TTL,
            data = #dns_rrdata_https{
                svc_priority = 1, target_name = ~"Svc.Example.Test", svc_params = #{}
            }
        }
    end,
    RRSig = #dns_rr{
        name = ~"www.example.test",
        type = ?DNS_TYPE_RRSIG,
        ttl = 3600,
        data = #dns_rrdata_rrsig{
            type_covered = ?DNS_TYPE_HTTPS,
            alg = ?DNS_ALG_ED25519,
            labels = 3,
            original_ttl = 3600,
            inception = 1790812800,
            expiration = 1793491200,
            keytag = 29059,
            signers_name = ~"example.test",
            signature = base64:decode(
                ~"RE6RL2LW1of41k02UJEzpaMgC0vYnsuH/BmTFWdRD2n3wDkqLzeR+YPSD7WZYATcM4jQqlQe2wvUVQAbbsxnBA=="
            )
        }
    },
    [
        ?assert(
            dns_sec:verify_rrsig(RRSig#dns_rr{ttl = TTL}, [HTTPS(TTL)], [DNSKey], #{
                now => 1790812801
            }),
            TTL
        )
     || TTL <- [3600, 3599, 60, 0, 7200]
    ].

%% An RRSIG decoded off the wire can carry an algorithm this module does not
%% implement: RSAMD5, ECC-GOST, a private one. It verifies nothing, whether or not a
%% DNSKEY of its algorithm is there, where verifying raised function_clause even
%% with no DNSKEY to try. Signing in one raises without the key in the stack trace,
%% which a function_clause in sign/3 would carry.
verify_unimplemented_algorithm(_Config) ->
    A = #dns_rr{
        name = ~"a.example.test",
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    [
        begin
            RRSig = #dns_rr{
                name = ~"a.example.test",
                type = ?DNS_TYPE_RRSIG,
                ttl = 3600,
                data = #dns_rrdata_rrsig{
                    type_covered = ?DNS_TYPE_A,
                    alg = Alg,
                    labels = 3,
                    original_ttl = 3600,
                    inception = 1790812800,
                    expiration = 1793491200,
                    keytag = 1,
                    signers_name = ~"example.test",
                    signature = <<1, 2, 3>>
                }
            },
            DNSKey = #dns_rr{
                name = ~"example.test",
                type = ?DNS_TYPE_DNSKEY,
                ttl = 3600,
                data = #dns_rrdata_dnskey{
                    flags = 256, protocol = 3, alg = Alg, public_key = <<4, 5, 6>>, keytag = 1
                }
            },
            Opts = #{now => 1790812801},
            ?assertNot(dns_sec:verify_rrsig(RRSig, [A], [], Opts), Alg),
            ?assertNot(dns_sec:verify_rrsig(RRSig, [A], [DNSKey], Opts), Alg),
            Secret = ~"secret private key",
            try dns_sec:sign_rr([A], ~"example.test", 1, Alg, Secret, #{}) of
                Signed -> ct:fail({signed, Alg, Signed})
            catch
                error:Reason:Stack ->
                    ?assertEqual({unsupported_algorithm, Alg}, Reason),
                    ?assertEqual(nomatch, binary:match(term_to_binary(Stack), Secret), Alg)
            end
        end
     || Alg <- [1, 12, 253]
    ].

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
    Result = dns_sec:ih(CustomHash, Salt, NameWire, 2),
    ?assert(is_binary(Result)),
    ?assert(byte_size(Result) =:= 20).

dsa_sign_verify_test(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    DSASample = [S || #dnssec_test_sample{alg = dsa} = S <- Samples],
    [#dnssec_test_sample{zonename = ZoneName, zsk_pl = ZskProps} | _] = DSASample,
    PrivKey = helper_samplekeypl_to_privkey(ZskProps),
    PubKeyRR = generate_key_struct(ZskProps, ZoneName),
    DNSKeyWithTag = PubKeyRR#key_info.rr,
    RR = #dns_rr{
        name = <<"test.", ZoneName/binary>>,
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    #dns_rr{data = #dns_rrdata_rrsig{signature = Signature}} =
        RRSig = dns_sec:sign_rrset(
            [RR],
            ZoneName,
            PubKeyRR#key_info.tag,
            PubKeyRR#key_info.alg,
            PrivKey,
            #{inception => 1000000, expiration => 2000000}
        ),
    ?assert(
        dns_sec:verify_rrsig(RRSig, [RR], [DNSKeyWithTag], #{now => 1500000})
    ),
    %% RFC2536§3: the signature starts with the T of the key's DNSKEY
    #dns_rr{data = #dns_rrdata_dnskey{public_key = <<T, _/binary>>}} = DNSKeyWithTag,
    ?assertMatch(<<T, _:40/binary>>, Signature).

ecdsa_sign_verify_test(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    [#dnssec_test_sample{zonename = ZoneName, zsk_pl = ZskProps} | _] = [
        S
     || #dnssec_test_sample{alg = Alg} = S <- Samples,
        Alg =:= ecdsap256 orelse Alg =:= ecdsap384
    ],
    PrivKey = helper_samplekeypl_to_privkey(ZskProps),
    PubKeyRR = generate_key_struct(ZskProps, ZoneName),
    DNSKeyWithTag = PubKeyRR#key_info.rr,
    RR = #dns_rr{
        name = <<"test.", ZoneName/binary>>,
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    RRSig = dns_sec:sign_rrset(
        [RR],
        ZoneName,
        PubKeyRR#key_info.tag,
        PubKeyRR#key_info.alg,
        PrivKey,
        #{inception => 1000000, expiration => 2000000}
    ),
    ?assert(
        dns_sec:verify_rrsig(RRSig, [RR], [DNSKeyWithTag], #{now => 1500000})
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
    RRSig = dns_sec:sign_rrset(
        [RR],
        ~"example",
        12345,
        ?DNS_ALG_ECDSAP256SHA256,
        Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    #dns_rr{data = #dns_rrdata_rrsig{signature = Sig}} = RRSig,
    %% The signature MUST be exactly 64 bytes per RFC 6605
    ?assertEqual(64, byte_size(Sig)),
    %% Verify round-trip: the wire-format signature must verify correctly
    DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
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
    ?assert(dns_sec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1500000})).

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
    RRSig = dns_sec:sign_rrset(
        [RR],
        ~"example",
        12345,
        ?DNS_ALG_ECDSAP384SHA384,
        Priv,
        #{inception => 1000000, expiration => 2000000}
    ),
    #dns_rr{data = #dns_rrdata_rrsig{signature = Sig}} = RRSig,
    %% The signature MUST be exactly 96 bytes per RFC 6605
    ?assertEqual(96, byte_size(Sig)),
    %% Verify round-trip
    DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
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
    ?assert(dns_sec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1500000})).

%% RFC6605§6: the RFC's RRSIGs verify, and what its private keys sign verifies
%% with its DNSKEYs. Signing and verifying hashed the signed data twice, so they
%% agreed with each other and with no other implementation.
ecdsa_rfc6605_examples(_Config) ->
    Examples = [
        {?DNS_ALG_ECDSAP256SHA256, ~"GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=",
            ~"""
        example.net. 3600 IN DNSKEY 257 3 13 (
            GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
            krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
        www.example.net. 3600 IN A 192.0.2.1
        www.example.net. 3600 IN RRSIG A 13 3 3600 (
            20100909100439 20100812100439 55648 example.net.
            qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
            yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )
        """},
        {?DNS_ALG_ECDSAP384SHA384,
            ~"WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR",
            ~"""
        example.net. 3600 IN DNSKEY 257 3 14 (
            xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
            w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
            /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )
        www.example.net. 3600 IN A 192.0.2.1
        www.example.net. 3600 IN RRSIG A 14 3 3600 (
            20100909102025 20100812102025 10771 example.net.
            /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
            95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
            WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )
        """}
    ],
    [
        begin
            {ok, RRs} = dns_zone:parse_string(Zone),
            [DNSKey] = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
            [#dns_rr{data = SigData} = RRSig] = [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
            [#dns_rr{data = AData} = A] = [RR || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
            #dns_rrdata_rrsig{
                keytag = KeyTag,
                signers_name = Signer,
                inception = Inception,
                expiration = Expiration
            } = SigData,
            Opts = #{now => Inception},
            ?assert(dns_sec:verify_rrsig(RRSig, [A], [DNSKey], Opts)),
            Other = A#dns_rr{data = AData#dns_rrdata_a{ip = {192, 0, 2, 2}}},
            ?assertNot(dns_sec:verify_rrsig(RRSig, [Other], [DNSKey], Opts)),
            Signed = dns_sec:sign_rrset(
                [A],
                Signer,
                KeyTag,
                Alg,
                base64:decode(PrivateKey),
                #{inception => Inception, expiration => Expiration}
            ),
            ?assert(dns_sec:verify_rrsig(Signed, [A], [DNSKey], Opts))
        end
     || {Alg, PrivateKey, Zone} <- Examples
    ].

zone(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    %% Run the validation for every sample in the config
    [validate_zone_sample(Config, Sample) || #dnssec_test_sample{alg = rsa} = Sample <- Samples].

generate_key_struct(Props, ZoneName) ->
    AlgNo = proplists:get_value(alg, Props),
    Flags = proplists:get_value(flags, Props),
    Data0 = #dns_rrdata_dnskey{
        flags = Flags,
        protocol = 3,
        alg = AlgNo,
        public_key = sample_dnskey_public_key(Props)
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
    dns_sec:gen_nsec(RRs) ++ RRs;
apply_nsec_policies(RRs, ZoneName, #dns_rrdata_nsec3param{} = Param) ->
    %% NSEC3
    ParamRR = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_NSEC3PARAM,
        ttl = 0,
        data = Param
    },
    RRsWithParam = [ParamRR | RRs],
    dns_sec:gen_nsec3(RRsWithParam) ++ RRsWithParam.

%% Simulates encoding to binary and back to ensure data is canonical
cycle_encoding(#dns_rr{class = Class, type = Type, data = Data} = RR) ->
    Bin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
    NewData = dns_decode:decode_rrdata(Bin, Class, Type),
    RR#dns_rr{data = NewData}.

sign_zone_data(RRs, ZoneName, ZSK, KSK, Inception, Expiration) ->
    Opts = #{inception => Inception, expiration => Expiration},
    %% ZSK signs everything
    ZskSigs = dns_sec:sign_rr(
        RRs,
        ZoneName,
        ZSK#key_info.tag,
        ZSK#key_info.alg,
        ZSK#key_info.priv_key,
        Opts
    ),
    %% KSK signs only the DNSKEY RRs
    DnsKeyRRs = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    KskSigs = dns_sec:sign_rr(
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
        inception = Inception,
        expiration = Expiration,
        nsec3 = NSEC3,
        zsk_pl = ZskProps,
        ksk_pl = KskProps,
        rr_clean = CleanRRs,
        rr_src = ExpectedRRs
    } = Sample,
    %% 1. Generate Key Structures from Property Lists
    KSK = generate_key_struct(KskProps, ZoneName),
    ZSK = generate_key_struct(ZskProps, ZoneName),
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
        public_key = sample_dnskey_public_key(Props)
    },
    helper_add_keytag_to_dnskey(Key0).

%% dnskey_public_key/2 lays a key out as its DNSKEY carries it: an RSA key as
%% RFC3110§2 has it, with no leading zeros and the exponent's length in one
%% octet, or in three past 255 octets; a DSA key as RFC2536§2 has it, with the T
%% its P's size gives; an ECDSA point without the octet 4 that marks it
%% uncompressed (RFC6605§4); and an EdDSA key as it is (RFC8080§3). An RSA or DSA
%% key's numbers are their big-endian bytes, leading zeros allowed, and one given
%% as an integer raises {badarg, number_not_bytes}. A key the DNSKEY cannot carry
%% raises {badarg, Why}, Why naming the rule it breaks and the size in bits of the
%% number that breaks it: an empty RSA exponent, which would be written as the
%% zero octet that says a two-octet length follows, an RSA modulus out of range,
%% and a DSA key whose Q is not 160 bits long, whose P is not 512 + 64T bits long
%% for a T of 0 to 8, or whose G or Y is longer than P. An algorithm without a
%% key layout raises {unsupported_algorithm, Alg}
dnskey_public_key_layout(_Config) ->
    Rsa = fun(Key) -> dns_sec:dnskey_public_key(?DNS_ALG_RSASHA256, Key) end,
    {[E, N], _} = crypto:generate_key(rsa, {1024, 65537}),
    ?assertEqual(<<3, 1, 0, 1, N/binary>>, Rsa([E, N])),
    ?assertEqual(Rsa([E, N]), Rsa([<<0, E/binary>>, <<0, 0, N/binary>>])),
    Int = fun binary:decode_unsigned/1,
    ?assertError({badarg, number_not_bytes}, Rsa([Int(E), Int(N)])),
    ?assertError({badarg, number_not_bytes}, Rsa([E, Int(N)])),
    LongE = <<1, 0:(255 * 8)>>,
    ?assertEqual(<<0, 256:16, LongE/binary, N/binary>>, Rsa([LongE, N])),
    %% RFC3110§2: an exponent of 255 octets still takes one length octet
    E255 = <<1, 0:(254 * 8)>>,
    ?assertEqual(<<255, E255/binary, N/binary>>, Rsa([E255, N])),
    %% RFC3110§2, §3, RFC5702§2: an exponent of up to 4096 bits, and a modulus of
    %% 512 to 4096 bits, or 1024 to 4096 for RSA/SHA-512
    %% A number Size bits long, in whole octets
    Bits = fun(Size) -> <<0:((8 - Size rem 8) rem 8), 1:1, 0:(Size - 1)>> end,
    E4096 = Bits(4096),
    ?assertEqual(<<0, 512:16, E4096/binary, N/binary>>, Rsa([E4096, N])),
    ?assertEqual(<<3, 1, 0, 1, (Bits(512))/binary>>, Rsa([E, Bits(512)])),
    ?assertEqual(<<3, 1, 0, 1, (Bits(4096))/binary>>, Rsa([E, Bits(4096)])),
    ?assertEqual(
        <<3, 1, 0, 1, (Bits(1024))/binary>>,
        dns_sec:dnskey_public_key(?DNS_ALG_RSASHA512, [E, Bits(1024)])
    ),
    ?assertError(
        {badarg, {rsa_modulus_bits, 1023}},
        dns_sec:dnskey_public_key(?DNS_ALG_RSASHA512, [E, Bits(1023)])
    ),
    BadRsa = [
        {[<<>>, N], {rsa_exponent_bits, 0}},
        {[<<0>>, N], {rsa_exponent_bits, 0}},
        {[0, N], number_not_bytes},
        {[E, <<>>], {rsa_modulus_bits, 0}},
        {[E, <<0, 0>>], {rsa_modulus_bits, 0}},
        {[-1, N], number_not_bytes},
        {[E, N, N], key_shape},
        {[<<1, 0:(512 * 8)>>, N], {rsa_exponent_bits, 4097}},
        {[E, <<1, 0:(512 * 8)>>], {rsa_modulus_bits, 4097}},
        {[E, <<16#7F, 0:(63 * 8)>>], {rsa_modulus_bits, 511}}
    ],
    [?assertError({badarg, Why}, Rsa(Key), Key) || {Key, Why} <- BadRsa],
    Dsa = fun(Key) -> dns_sec:dnskey_public_key(?DNS_ALG_DSA, Key) end,
    Q = <<16#E2B4F7B1A4D6E39F7C5A0C0D7B4E3A9C1B2D3E4F:160>>,
    P = <<16#80, 0:(63 * 8)>>,
    ?assertEqual(
        <<0, Q/binary, P/binary, 0:(63 * 8), 2, 0:(63 * 8), 3>>, Dsa([P, Q, <<2>>, <<3>>])
    ),
    ?assertEqual(
        Dsa([P, Q, <<2>>, <<3>>]), Dsa([<<0, P/binary>>, <<0, Q/binary>>, <<0, 2>>, <<0, 3>>])
    ),
    ?assertError({badarg, number_not_bytes}, Dsa([Int(P), Int(Q), 2, 3])),
    ?assertError({badarg, number_not_bytes}, Dsa([P, Q, <<2>>, 3])),
    P1024 = <<16#80, 0:(127 * 8)>>,
    ?assertEqual(
        <<8, Q/binary, P1024/binary, 0:(127 * 8), 2, 0:(127 * 8), 3>>,
        Dsa([P1024, Q, <<2>>, <<3>>])
    ),
    %% P of 520 bits, which no T gives, of 1025 bits, past T = 8, and of 511 and
    %% 504 bits, short of T = 0; Q of 159 and 161 bits; G and Y longer than P
    BadDsa = [
        {[<<16#80, 0:(64 * 8)>>, Q, <<2>>, <<3>>], {dsa_p_bits, 520}},
        {[<<1, 0:(128 * 8)>>, Q, <<2>>, <<3>>], {dsa_p_bits, 1025}},
        {[<<16#7F, 0:(63 * 8)>>, Q, <<2>>, <<3>>], {dsa_p_bits, 511}},
        {[<<16#80, 0:(62 * 8)>>, Q, <<2>>, <<3>>], {dsa_p_bits, 504}},
        {[P, <<16#7F, 0:(19 * 8)>>, <<2>>, <<3>>], {dsa_q_bits, 159}},
        {[P, <<1, Q/binary>>, <<2>>, <<3>>], {dsa_q_bits, 161}},
        {[P, Q, <<1, 0:(64 * 8)>>, <<3>>], dsa_number_longer_than_p},
        {[P, Q, <<2>>, <<1, 0:(64 * 8)>>], dsa_number_longer_than_p},
        {[P, Q, <<2>>], key_shape}
    ],
    [?assertError({badarg, Why}, Dsa(Key), Key) || {Key, Why} <- BadDsa],
    {<<4, Point256:64/binary>> = Pub256, _} = crypto:generate_key(ecdh, secp256r1),
    ?assertEqual(Point256, dns_sec:dnskey_public_key(?DNS_ALG_ECDSAP256SHA256, Pub256)),
    {<<4, Point384:96/binary>> = Pub384, _} = crypto:generate_key(ecdh, secp384r1),
    ?assertEqual(Point384, dns_sec:dnskey_public_key(?DNS_ALG_ECDSAP384SHA384, Pub384)),
    {Ed25519, _} = crypto:generate_key(eddsa, ed25519),
    ?assertEqual(Ed25519, dns_sec:dnskey_public_key(?DNS_ALG_ED25519, Ed25519)),
    {Ed448, _} = crypto:generate_key(eddsa, ed448),
    ?assertEqual(Ed448, dns_sec:dnskey_public_key(?DNS_ALG_ED448, Ed448)),
    %% FIPS 204 §4: an ML-DSA-44 public key is 1312 octets
    MlDsa44 = binary:copy(<<16#5A>>, 1312),
    ?assertEqual(MlDsa44, dns_sec:dnskey_public_key(?DNS_ALG_MLDSA44, MlDsa44)),
    [
        ?assertError({badarg, key_shape}, dns_sec:dnskey_public_key(Alg, Key), Alg)
     || {Alg, Key} <- [
            {?DNS_ALG_ECDSAP256SHA256, Point256},
            {?DNS_ALG_ED25519, <<Ed25519/binary, 0>>},
            {?DNS_ALG_ED448, Ed25519},
            {?DNS_ALG_MLDSA44, <<MlDsa44/binary, 0>>},
            {?DNS_ALG_RSASHA256, <<3, 1, 0, 1, N/binary>>},
            {?DNS_ALG_DSA, [P, Q, <<2>>, <<3>>, <<4>>]}
        ]
    ],
    ?assertError({unsupported_algorithm, 200}, dns_sec:dnskey_public_key(200, Ed25519)),
    ?assertError(
        {unsupported_algorithm, ?DNS_ALG_ECCGOST},
        dns_sec:dnskey_public_key(?DNS_ALG_ECCGOST, Ed25519)
    ).

%% dns_dnskey:numbers/2, which verify_rrsig/4 splits RSA and DSA key fields with,
%% reads back the numbers of every field dnskey_public_key/2 lays out, the
%% three-octet exponent length and every T included, a DSA key's G and Y padded
%% to P's size as the field has them, and refuses a field it would not lay out
key_fields_read_back(_Config) ->
    {[E, N], _} = crypto:generate_key(rsa, {1024, 65537}),
    LongE = <<1, 0:(255 * 8)>>,
    Q = <<16#E2B4F7B1A4D6E39F7C5A0C0D7B4E3A9C1B2D3E4F:160>>,
    Dsa = fun(P) ->
        Size = byte_size(P),
        {[P, Q, <<2>>, <<3>>], [P, Q, <<2:(Size * 8)>>, <<3:(Size * 8)>>]}
    end,
    Keys =
        [
            {?DNS_ALG_RSASHA256, {[E, N], [E, N]}},
            {?DNS_ALG_RSASHA512, {[LongE, N], [LongE, N]}}
        ] ++
            [
                {Alg, Dsa(<<16#80, 0:((63 + 8 * T) * 8)>>)}
             || {Alg, T} <- [{?DNS_ALG_DSA, 0}, {?DNS_ALG_NSEC3DSA, 1}, {?DNS_ALG_DSA, 8}]
            ],
    [
        ?assertEqual(
            ReadBack, dns_dnskey:numbers(Alg, dns_sec:dnskey_public_key(Alg, Numbers)), Alg
        )
     || {Alg, {Numbers, ReadBack}} <- Keys
    ],
    {_, {DsaNumbers, _}} = lists:last(Keys),
    DsaField = dns_sec:dnskey_public_key(?DNS_ALG_DSA, DsaNumbers),
    [
        ?assertEqual(invalid, dns_dnskey:numbers(Alg, Field), Field)
     || {Alg, Field} <- [
            {?DNS_ALG_DSA, binary:part(DsaField, 0, byte_size(DsaField) - 1)},
            {?DNS_ALG_DSA, <<DsaField/binary, 0>>},
            {?DNS_ALG_RSASHA256, <<>>},
            {?DNS_ALG_RSASHA256, <<0, 3:16, 1, 0, 1, N/binary>>}
        ]
    ].

%% RFC5702§6's examples, read from their zone text. The DNSKEY's key field is what
%% dnskey_public_key/2 makes of the private key's numbers, the RFC's RRSIG
%% verifies with it and not with a bit of its signature flipped, and signing the
%% A record gives the RFC's signature, as RSA PKCS #1 v1.5 signatures are
%% deterministic. 5.2.0 and earlier raised verifying with an RSA DNSKEY read from
%% a zone file.
rfc5702_known_answers(_Config) ->
    [rfc5702_known_answer(Vector) || Vector <- rfc5702_vectors()].

rfc5702_known_answer(#{source := Source, alg := Alg, private_key := PrivateKey, zone := Zone}) ->
    {ok, RRs} = dns_zone:parse_string(Zone),
    [
        #dns_rr{data = #dns_rrdata_dnskey{alg = Alg, keytag = KeyTag, public_key = PublicKey}} =
            DNSKey
    ] = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
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
    RRSet = [RR || #dns_rr{type = ?DNS_TYPE_A} = RR <- RRs],
    [E, N, _D] = PrivateKey,
    ?assertEqual(PublicKey, dns_sec:dnskey_public_key(Alg, [E, N]), Source),
    Opts = #{now => Inception},
    ?assert(dns_sec:verify_rrsig(RRSig, RRSet, [DNSKey], Opts), Source),
    <<Head:(byte_size(Signature) - 1)/binary, Last>> = Signature,
    Flipped = SigData#dns_rrdata_rrsig{signature = <<Head/binary, (Last bxor 1)>>},
    ?assertNot(dns_sec:verify_rrsig(RRSig#dns_rr{data = Flipped}, RRSet, [DNSKey], Opts), Source),
    #dns_rr{data = #dns_rrdata_rrsig{signature = Signed}} = dns_sec:sign_rrset(
        RRSet, Signer, KeyTag, Alg, PrivateKey, #{inception => Inception, expiration => Expiration}
    ),
    ?assertEqual(Signature, Signed, Source).

%% The examples of RFC5702§6 as printed, with the private key's exponents and
%% modulus
rfc5702_vectors() ->
    [
        #{
            source => ~"RFC5702§6.1",
            alg => ?DNS_ALG_RSASHA256,
            private_key => rsa_private_key(
                ~"AQAB",
                ~"wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==",
                ~"UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ=="
            ),
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
        }
    ].

rsa_private_key(E, N, D) ->
    [base64:decode(B) || B <- [E, N, D]].

%% Every RRSIG BIND made in the sample zones verifies with its zone's DNSKEYs
%% written as zone text and read back, which give the same DNSKEYs as the wire:
%% RSA and DSA keys are their bytes from either. 5.2.0 and earlier decoded those
%% from the wire as numbers and kept them from zone text as bytes, and raised
%% verifying with the latter.
verify_with_zone_text_dnskeys(Config) ->
    Cases = helper_verify_rrset_test_cases(Config),
    Algs = [Alg || {#dns_rr{data = #dns_rrdata_rrsig{alg = Alg}}, _, _, _} <- Cases],
    ?assertEqual([3, 5, 6, 7, 8, 10, 13, 14], lists:usort(Algs)),
    [
        begin
            FromText = [zone_text_dnskey(DNSKey) || DNSKey <- DNSKeys],
            ?assertEqual(DNSKeys, FromText),
            ?assert(dns_sec:verify_rrsig(RRSig, RRSet, FromText, Opts))
        end
     || {RRSig, RRSet, DNSKeys, Opts} <- Cases
    ].

%% A DNSKEY with the RDATA its zone text reads back as. The owner stays as it
%% was, as zone text gives it a final dot.
zone_text_dnskey(DNSKey) ->
    Text = iolist_to_binary(dns_zone:encode_rr(DNSKey)),
    {ok, [#dns_rr{data = Data}]} = dns_zone:parse_string(<<Text/binary, "\n">>),
    DNSKey#dns_rr{data = Data}.

%% RFC3110§2: an exponent length of 1 to 255 takes one octet, and "leading zero
%% octets are prohibited in the exponent and modulus". A key that breaks either
%% rule holds the numbers of a key that verifies BIND's signatures, but
%% verify_rrsig/4 verifies nothing with it. Nor with a key shorter than its
%% algorithm allows: RFC5702§2 has RSA/SHA-512 keys of 1024 bits or more.
rsa_key_rfc3110_rules_out_verifies_nothing(Config) ->
    RsaAlgs = [
        ?DNS_ALG_RSASHA1, ?DNS_ALG_NSEC3RSASHA1, ?DNS_ALG_RSASHA256, ?DNS_ALG_RSASHA512
    ],
    Cases = signed_by_sample_key(Config, RsaAlgs, fun(_Key) -> true end),
    [
        begin
            #dns_rr{data = #dns_rrdata_dnskey{public_key = <<Len, E:Len/binary, N/binary>> = Key}} =
                DNSKey,
            ?assert(verify_with_key(Case, Key)),
            [
                ?assertNot(verify_with_key(Case, Bytes), Rule)
             || {Rule, Bytes} <- [
                    {zero_before_modulus, <<Len, E/binary, 0, N/binary>>},
                    {zero_before_exponent, <<(Len + 1), 0, E/binary, N/binary>>},
                    {long_exponent_length, <<0, Len:16, E/binary, N/binary>>}
                ]
            ]
        end
     || {_, _, DNSKey, _} = Case <- Cases
    ],
    {[<<1, 0, 1>> = E, N], [E, N, D | _]} = crypto:generate_key(rsa, {768, 65537}),
    RR = #dns_rr{
        name = ~"www.example",
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    SignAndVerify = fun(Alg) ->
        RRSig = dns_sec:sign_rrset(
            [RR], ~"example", 0, Alg, [E, N, D], #{inception => 1000000, expiration => 2000000}
        ),
        Data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = Alg, public_key = <<3, E/binary, N/binary>>
        },
        DNSKey = #dns_rr{name = ~"example", type = ?DNS_TYPE_DNSKEY, ttl = 3600, data = Data},
        dns_sec:verify_rrsig(RRSig, [RR], [DNSKey], #{now => 1500000})
    end,
    ?assert(SignAndVerify(?DNS_ALG_RSASHA256)),
    ?assertNot(SignAndVerify(?DNS_ALG_RSASHA512)).

%% RFC2536§2: P is "in the range 2**(511+64T) < P < 2**(512+64T) and so is
%% 64 + 8*T octets long", so a DSA DNSKEY whose T is wider than its P needs is no
%% RFC 2536 key. Written with the next T, eight more zero octets in front of each
%% of P, G and Y, a key that verifies BIND's signatures verifies nothing.
dsa_key_with_wide_t_verifies_nothing(Config) ->
    DsaAlgs = [?DNS_ALG_DSA, ?DNS_ALG_NSEC3DSA],
    Cases = signed_by_sample_key(Config, DsaAlgs, fun(<<T, _/binary>>) -> T < 8 end),
    [
        begin
            #dns_rr{data = #dns_rrdata_dnskey{public_key = <<T, Q:20/binary, PGY/binary>> = Key}} =
                DNSKey,
            S = 64 + 8 * T,
            <<P:S/binary, G:S/binary, Y:S/binary>> = PGY,
            Wide = <<(T + 1), Q/binary, 0:64, P/binary, 0:64, G/binary, 0:64, Y/binary>>,
            ?assert(verify_with_key(Case, Key)),
            ?assertNot(verify_with_key(Case, Wide))
        end
     || {_, _, DNSKey, _} = Case <- Cases
    ].

%% A DNSKEY whose key is not a binary, as an RSA key's [E, M] was before 6.0.0,
%% raises {badarg, public_key_not_binary}, where it would quietly verify nothing,
%% whether another DNSKEY verifies the RRSIG or not
verify_with_list_key_raises(Config) ->
    [{_, _, DNSKey, _} = Case] =
        signed_by_sample_key(Config, [?DNS_ALG_RSASHA256], fun(_) -> true end),
    #dns_rr{data = #dns_rrdata_dnskey{public_key = <<Len, E:Len/binary, N/binary>>}} = DNSKey,
    ?assertError({badarg, public_key_not_binary}, verify_with_key(Case, [E, N])),
    Int = fun binary:decode_unsigned/1,
    ?assertError({badarg, public_key_not_binary}, verify_with_key(Case, [Int(E), Int(N)])),
    %% The DNSKEY that verifies is tried first, as its key tag is the RRSIG's
    {RRSig, RRSet, #dns_rr{data = Data}, Opts} = Case,
    ListKey = DNSKey#dns_rr{data = Data#dns_rrdata_dnskey{public_key = [E, N]}},
    ?assert(dns_sec:verify_rrsig(RRSig, RRSet, [DNSKey], Opts)),
    ?assertError(
        {badarg, public_key_not_binary},
        dns_sec:verify_rrsig(RRSig, RRSet, [DNSKey, ListKey], Opts)
    ).

%% A private key's numbers are their big-endian bytes. Given as integers, which
%% crypto would take, converting them on every signature, an RSA or DSA key
%% raises {badarg, number_not_bytes}
sign_with_integer_key_raises(Config) ->
    RR = #dns_rr{
        name = ~"www.example",
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Sign = fun(Alg, Key) ->
        dns_sec:sign_rrset(
            [RR], ~"example", 0, Alg, Key, #{inception => 1000000, expiration => 2000000}
        )
    end,
    Int = fun binary:decode_unsigned/1,
    {_, [E, N, D | _] = Rsa} = crypto:generate_key(rsa, {1024, 65537}),
    ?assertMatch(#dns_rr{}, Sign(?DNS_ALG_RSASHA256, Rsa)),
    ?assertMatch(#dns_rr{}, Sign(?DNS_ALG_RSASHA256, [E, N, D])),
    ?assertError({badarg, number_not_bytes}, Sign(?DNS_ALG_RSASHA256, [Int(E), Int(N), Int(D)])),
    ?assertError({badarg, number_not_bytes}, Sign(?DNS_ALG_RSASHA256, [E, N, Int(D)])),
    ?assertError(
        {badarg, number_not_bytes},
        dns_sec:sign_rr([RR], ~"example", 0, ?DNS_ALG_RSASHA256, [Int(E), Int(N), Int(D)], #{})
    ),
    Samples = proplists:get_value(dnssec_samples, Config),
    [#dnssec_test_sample{zsk_pl = DsaProps} | _] = [
        S
     || #dnssec_test_sample{alg = dsa} = S <- Samples
    ],
    Dsa = helper_samplekeypl_to_privkey(DsaProps),
    ?assertMatch(#dns_rr{}, Sign(?DNS_ALG_DSA, Dsa)),
    ?assertError({badarg, number_not_bytes}, Sign(?DNS_ALG_DSA, [Int(Number) || Number <- Dsa])).

%% For each of the algorithms, in order, the first RRSIG BIND made in the sample
%% zones with it by a DNSKEY whose key passes Filter, the RRset it covers, that
%% DNSKEY, and the time to verify at. Raises if an algorithm has none
signed_by_sample_key(Config, Algs, Filter) ->
    Cases = helper_verify_rrset_test_cases(Config),
    [
        hd([
            {RRSig, RRSet, DNSKey, Opts}
         || {
                #dns_rr{data = #dns_rrdata_rrsig{alg = SigAlg, keytag = KeyTag}} = RRSig,
                RRSet,
                DNSKeys,
                Opts
            } <- Cases,
            SigAlg =:= Alg,
            #dns_rr{
                data = #dns_rrdata_dnskey{alg = KeyAlg, keytag = KeyKeyTag, public_key = Key}
            } = DNSKey <- DNSKeys,
            KeyAlg =:= Alg,
            KeyKeyTag =:= KeyTag,
            Filter(Key)
        ])
     || Alg <- Algs
    ].

%% Whether a case of signed_by_sample_key/3 verifies with Key as its DNSKEY's key
verify_with_key({RRSig, RRSet, #dns_rr{data = Data} = DNSKey, Opts}, Key) ->
    WithKey = DNSKey#dns_rr{data = Data#dns_rrdata_dnskey{public_key = Key}},
    dns_sec:verify_rrsig(RRSig, RRSet, [WithKey], Opts).

sample_keys(Config) ->
    Keys = lists:foldl(
        fun(#dnssec_test_sample{alg = Alg, zsk_pl = A, ksk_pl = B}, Acc) ->
            [{Alg, A}, {Alg, B} | Acc]
        end,
        [],
        proplists:get_value(dnssec_samples, Config)
    ),
    [?assert(test_sample_key(Alg, Proplist)) || {Alg, Proplist} <- Keys].

%% RFC4035§2.2: an RRSIG RRset is never signed. sign_rr/6 leaves RRSIG records out of what it
%% signs, and sign_rrset/6 refuses an RRSIG RRset, where both signed it.
sign_leaves_rrsigs_unsigned(_Config) ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = ?DNS_ALG_ED25519, public_key = Pub
        }
    }),
    #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = DNSKey,
    A = #dns_rr{
        name = ~"www.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Opts = #{inception => 1000000, expiration => 2000000},
    Sign = fun(RRs) -> dns_sec:sign_rr(RRs, ~"example", KeyTag, ?DNS_ALG_ED25519, Priv, Opts) end,
    [RRSig] = Sign([A]),
    %% Given the RRSIG with the record it covers, only the A RRset is signed
    [#dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_A}} = Again] = Sign([A, RRSig]),
    ?assert(dns_sec:verify_rrsig(Again, [A], [DNSKey], #{now => 1500000})),
    ?assertEqual([], Sign([RRSig])),
    ?assertError(
        {badarg, rrsig_rrset},
        dns_sec:sign_rrset([RRSig], ~"example", KeyTag, ?DNS_ALG_ED25519, Priv, Opts)
    ).

%% RFC4034§3.1.8.1: sign_rrset/6 signs its records as one RRset, under the first record's owner,
%% class and type. A record of another RRset made an RRSIG that never verifies, so it now raises
%% instead. Owners that are one name, in another case or with a final dot, are one RRset.
sign_rrset_rejects_records_of_other_rrsets(_Config) ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = ?DNS_ALG_ED25519, public_key = Pub
        }
    }),
    #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = DNSKey,
    A = fun(Name, Last) ->
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_A,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 0, 2, Last}}
        }
    end,
    Opts = #{inception => 1000000, expiration => 2000000},
    Sign = fun(RRs) ->
        dns_sec:sign_rrset(RRs, ~"example", KeyTag, ?DNS_ALG_ED25519, Priv, Opts)
    end,
    RRSet = [A(~"www.example", 1), A(~"www.example", 2)],
    RRSig = Sign(RRSet),
    ?assert(dns_sec:verify_rrsig(RRSig, RRSet, [DNSKey], #{now => 1500000})),
    %% Ed25519 signs deterministically, so the same RRset written otherwise gets the same RRSIG
    [
        ?assertEqual(RRSig, Sign([A(~"www.example", 1), A(Name, 2)]), Name)
     || Name <- [~"WWW.Example", ~"www.example."]
    ],
    %% An owner whose first label holds a dot, written as \\. in it
    ?assertEqual(
        Sign([A(~"a\\.b.example", 1), A(~"a\\.b.example", 2)]),
        Sign([A(~"a\\.b.example", 1), A(~"A\\.B.Example.", 2)])
    ),
    ?assertError(
        {badarg, mixed_rrset}, Sign([A(~"a\\.b.example", 1), A(~"a.b.example", 2)])
    ),
    Mixed = {badarg, mixed_rrset},
    ?assertError(Mixed, Sign([A(~"www.example", 1), A(~"ftp.example", 2)])),
    AAAA = #dns_rr{
        name = ~"www.example",
        type = ?DNS_TYPE_AAAA,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_aaaa{ip = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}}
    },
    ?assertError(Mixed, Sign([A(~"www.example", 1), AAAA])),
    Chaos = (A(~"www.example", 2))#dns_rr{class = ?DNS_CLASS_CH},
    ?assertError(Mixed, Sign([A(~"www.example", 1), Chaos])).

%% sign_rr/6 groups records into RRsets by owner name as sign_rrset/6 compares them. Owners written
%% with and without a final dot made two RRSIGs, each covering part of the RRset, that never
%% verified; they now make one.
sign_rr_groups_owner_names_as_names(_Config) ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
        name = ~"example",
        type = ?DNS_TYPE_DNSKEY,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256, protocol = 3, alg = ?DNS_ALG_ED25519, public_key = Pub
        }
    }),
    #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = DNSKey,
    A = fun(Name, Last) ->
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_A,
            class = ?DNS_CLASS_IN,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 0, 2, Last}}
        }
    end,
    Opts = #{inception => 1000000, expiration => 2000000},
    Sign = fun(RRs) -> dns_sec:sign_rr(RRs, ~"example", KeyTag, ?DNS_ALG_ED25519, Priv, Opts) end,
    RRSet = [A(~"www.example", 1), A(~"www.example", 2)],
    [RRSig] = Sign(RRSet),
    ?assert(dns_sec:verify_rrsig(RRSig, RRSet, [DNSKey], #{now => 1500000})),
    %% Ed25519 signs deterministically, so the same RRset written otherwise gets the same RRSIG
    [
        ?assertEqual([RRSig], Sign([A(~"www.example", 1), A(Name, 2)]), Name)
     || Name <- [~"www.example.", ~"WWW.Example."]
    ],
    %% Other owners are other RRsets
    ?assertMatch([_, _], Sign([A(~"www.example", 1), A(~"ftp.example.", 2)])).

ed25519_basic_test(_Config) ->
    {Ed25519Pub, Ed25519Priv} = crypto:generate_key(eddsa, ed25519),
    Ed25519RR = #dns_rr{
        name = ~"test.example",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    Ed25519Sig = dns_sec:sign_rrset(
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
    Ed25519DNSKeyWithTag = dns_sec:add_keytag_to_dnskey(Ed25519DNSKey),
    ?assert(
        dns_sec:verify_rrsig(
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
    Ed448Sig = dns_sec:sign_rrset(
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
    Ed448DNSKeyWithTag = dns_sec:add_keytag_to_dnskey(Ed448DNSKey),
    ?assert(
        dns_sec:verify_rrsig(
            Ed448Sig,
            [Ed448RR],
            [Ed448DNSKeyWithTag],
            #{now => 1500000}
        )
    ).

%% draft-westerbaan-dnssec-mldsa-04§6: the draft's RRSIG verifies, and so does one signed
%% here with its seed. Without ML-DSA, verifying gives false and signing raises.
mldsa44_draft_example(_Config) ->
    {DNSKey, RRSig, MX} = mldsa44_draft_records(),
    #dns_rr{data = SigData} = RRSig,
    #dns_rr{data = MXData} = MX,
    #dns_rrdata_rrsig{
        keytag = KeyTag,
        signers_name = Signer,
        inception = Inception,
        expiration = Expiration,
        signature = Signature
    } = SigData,
    Opts = #{now => Inception},
    Sign = fun() ->
        dns_sec:sign_rrset(
            [MX],
            Signer,
            KeyTag,
            ?DNS_ALG_MLDSA44,
            list_to_binary(lists:seq(0, 31)),
            #{inception => Inception, expiration => Expiration}
        )
    end,
    case has_mldsa44() of
        true ->
            ?assert(dns_sec:verify_rrsig(RRSig, [MX], [DNSKey], Opts)),
            Other = MX#dns_rr{data = MXData#dns_rrdata_mx{preference = 20}},
            ?assertNot(dns_sec:verify_rrsig(RRSig, [Other], [DNSKey], Opts)),
            <<First, Rest/binary>> = Signature,
            Flipped = SigData#dns_rrdata_rrsig{signature = <<(First bxor 1), Rest/binary>>},
            ?assertNot(dns_sec:verify_rrsig(RRSig#dns_rr{data = Flipped}, [MX], [DNSKey], Opts)),
            #dns_rr{data = SignedData} = Signed = Sign(),
            ?assertEqual(
                SigData#dns_rrdata_rrsig{signature = <<>>},
                SignedData#dns_rrdata_rrsig{signature = <<>>}
            ),
            ?assert(dns_sec:verify_rrsig(Signed, [MX], [DNSKey], Opts));
        false ->
            ?assertNot(dns_sec:verify_rrsig(RRSig, [MX], [DNSKey], Opts)),
            ?assertError({unsupported_algorithm, ?DNS_ALG_MLDSA44}, Sign()),
            no_mldsa44()
    end.

%% The 2560-byte expanded key from crypto:generate_key/2 signs too
mldsa44_expanded_key(_Config) ->
    case has_mldsa44() of
        true ->
            {PublicKey, PrivateKey} = crypto:generate_key(mldsa44, []),
            ?assertEqual(2560, byte_size(PrivateKey)),
            A = #dns_rr{
                name = ~"a.example.test",
                type = ?DNS_TYPE_A,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
            },
            DNSKey = dns_sec:add_keytag_to_dnskey(#dns_rr{
                name = ~"example.test",
                type = ?DNS_TYPE_DNSKEY,
                ttl = 3600,
                data = #dns_rrdata_dnskey{
                    flags = 256,
                    protocol = 3,
                    alg = ?DNS_ALG_MLDSA44,
                    public_key = PublicKey,
                    keytag = 0
                }
            }),
            #dns_rr{data = #dns_rrdata_dnskey{keytag = KeyTag}} = DNSKey,
            Signed = dns_sec:sign_rrset(
                [A],
                ~"example.test",
                KeyTag,
                ?DNS_ALG_MLDSA44,
                PrivateKey,
                #{inception => 1790812800, expiration => 1793491200}
            ),
            ?assert(dns_sec:verify_rrsig(Signed, [A], [DNSKey], #{now => 1790812801}));
        false ->
            no_mldsa44()
    end.

%% Wrong-size or random keys and signatures never verify
mldsa44_malformed_does_not_verify(_Config) ->
    {#dns_rr{data = KeyData} = DNSKey, #dns_rr{data = SigData} = RRSig, MX} =
        mldsa44_draft_records(),
    #dns_rrdata_dnskey{public_key = Key} = KeyData,
    #dns_rrdata_rrsig{inception = Inception, signature = Signature} = SigData,
    Resize = fun
        (Bin, Size) when Size =< byte_size(Bin) -> binary:part(Bin, 0, Size);
        (Bin, Size) -> <<Bin/binary, 0:((Size - byte_size(Bin)) * 8)>>
    end,
    Keys = [Resize(Key, Size) || Size <- [0, 32, 1311, 1313, 2560]],
    Signatures = [Resize(Signature, Size) || Size <- [0, 2419, 2421]],
    Opts = #{now => Inception},
    [
        ?assertNot(
            dns_sec:verify_rrsig(
                RRSig,
                [MX],
                [DNSKey#dns_rr{data = KeyData#dns_rrdata_dnskey{public_key = K}}],
                Opts
            ),
            byte_size(K)
        )
     || K <- [crypto:strong_rand_bytes(1312) | Keys]
    ],
    [
        ?assertNot(
            dns_sec:verify_rrsig(
                RRSig#dns_rr{data = SigData#dns_rrdata_rrsig{signature = S}},
                [MX],
                [DNSKey],
                Opts
            ),
            byte_size(S)
        )
     || S <- [crypto:strong_rand_bytes(2420) | Signatures]
    ].

%% The DNSKEY, RRSIG and MX of draft-westerbaan-dnssec-mldsa-04§6
mldsa44_draft_records() ->
    {ok, RRs} = dns_zone:parse_string(data_samples:mldsa44_example()),
    [DNSKey] = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
    [RRSig] = [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- RRs],
    [MX] = [RR || #dns_rr{type = ?DNS_TYPE_MX} = RR <- RRs],
    {DNSKey, RRSig, MX}.

has_mldsa44() ->
    lists:member(mldsa44, crypto:supports(public_keys)).

%% CI sets DNS_ERLANG_REQUIRE_PQC where crypto should have ML-DSA
no_mldsa44() ->
    case os:getenv("DNS_ERLANG_REQUIRE_PQC") of
        "true" -> ct:fail("crypto has no mldsa44, and DNS_ERLANG_REQUIRE_PQC is true");
        _ -> {comment, "crypto has no mldsa44"}
    end.

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
                DNSKeys = [RR || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs],
                Map = lists:foldl(
                    fun
                        (
                            #dns_rr{
                                type = ?DNS_TYPE_RRSIG,
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
                                Type =:= ?DNS_TYPE_RRSIG
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
    [I || <<L:32, I:L/binary>> <- [P, Q, G, X]];
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
    [I || <<L:32, I:L/binary>> <- [E, N, D]].

helper_samplekeypl_to_pubkey(Proplist) ->
    Alg = proplists:get_value(alg, Proplist),
    helper_samplekeypl_to_pubkey(Alg, Proplist).

helper_samplekeypl_to_pubkey(DSA, Proplist) when
    DSA =:= ?DNS_ALG_DSA orelse DSA =:= ?DNS_ALG_NSEC3DSA
->
    %% [P, Q, G, Y] as their big-endian bytes, as crypto takes them
    P = proplists:get_value(p, Proplist),
    Q = proplists:get_value(q, Proplist),
    G = proplists:get_value(g, Proplist),
    Y = proplists:get_value(y, Proplist),
    [I || <<L:32, I:L/binary>> <- [P, Q, G, Y]];
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
    [I || <<L:32, I:L/binary>> <- [E, N]].

%% A sample key's DNSKEY public key field, made by dnskey_public_key/2 from the
%% key as crypto gives it: an RSA or DSA key's numbers, an ECDSA point with the
%% octet 4 in front that marks it uncompressed, an EdDSA key as it is
sample_dnskey_public_key(Props) ->
    Alg = proplists:get_value(alg, Props),
    Key =
        case helper_samplekeypl_to_pubkey(Props) of
            Point when Alg =:= ?DNS_ALG_ECDSAP256SHA256; Alg =:= ?DNS_ALG_ECDSAP384SHA384 ->
                <<4, Point/binary>>;
            Other ->
                Other
        end,
    dns_sec:dnskey_public_key(Alg, Key).

helper_add_keytag_to_dnskey(#dns_rrdata_dnskey{} = DNSKey) ->
    RR = #dns_rr{type = ?DNS_TYPE_DNSKEY, data = DNSKey},
    (dns_sec:add_keytag_to_dnskey(RR))#dns_rr.data.

helper_fmt(Fmt, Args) ->
    iolist_to_binary(io_lib:format(Fmt, Args)).
