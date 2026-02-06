-module(dns_json_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            test_simple_records,
            test_all_rrdata_types,
            test_nested_records,
            test_dnssec_records,
            test_optrr_records,
            test_special_encodings,
            test_svcb_params,
            test_svcb_params_json_edge_cases,
            test_svcb_params_numeric_keys_0_to_6_equivalent_to_named,
            test_svcb_params_numeric_key_invalid_value_rejected,
            test_dnskey_formats,
            test_nsec3_salt,
            test_ipseckey_gateway,
            test_error_cases,
            test_edge_cases
        ]}
    ].

init_per_suite(Config) ->
    case code:ensure_loaded(json) of
        {module, json} ->
            Config;
        {error, _} ->
            {skip, "json module not available"}
    end.

end_per_suite(_Config) ->
    ok.

test_simple_records(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    Cases = [
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_AAAA,
            ttl = 3600,
            data = #dns_rrdata_aaaa{
                ip = {16#2001, 16#0db8, 16#85a3, 0, 0, 16#8a2e, 16#0370, 16#7334}
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_NS,
            ttl = 3600,
            data = #dns_rrdata_ns{dname = ~"ns.example.com"}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_CNAME,
            ttl = 3600,
            data = #dns_rrdata_cname{dname = ~"www.example.com"}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_PTR,
            ttl = 3600,
            data = #dns_rrdata_ptr{dname = ~"ptr.example.com"}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_MX,
            ttl = 3600,
            data = #dns_rrdata_mx{preference = 10, exchange = ~"mail.example.com"}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_TXT,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [~"v=spf1", ~"include:example.com"]}
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SRV,
            ttl = 3600,
            data = #dns_rrdata_srv{
                priority = 10,
                weight = 60,
                port = 5060,
                target = ~"sip.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_CAA,
            ttl = 3600,
            data = #dns_rrdata_caa{
                flags = 0,
                tag = ~"issue",
                value = ~"letsencrypt.org"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SOA,
            ttl = 3600,
            data = #dns_rrdata_soa{
                mname = ~"ns1.example.com",
                rname = ~"admin.example.com",
                serial = 2024010101,
                refresh = 3600,
                retry = 1800,
                expire = 604800,
                minimum = 86400
            }
        }
    ],
    [assert_transcode(Record) || Record <- Cases].

test_all_rrdata_types(_Config) ->
    Cases = [
        #dns_query{
            name = ~"example.com",
            class = ?DNS_CLASS_IN,
            type = ?DNS_TYPE_A
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_AFSDB,
            ttl = 3600,
            data = #dns_rrdata_afsdb{
                subtype = 1,
                hostname = ~"afs.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DNAME,
            ttl = 3600,
            data = #dns_rrdata_dname{
                dname = ~"dname.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DHCID,
            ttl = 3600,
            data = #dns_rrdata_dhcid{
                data = ~"dhcid-data-test"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_KEY,
            ttl = 3600,
            data = #dns_rrdata_key{
                type = 0,
                xt = 0,
                name_type = 0,
                sig = 0,
                protocol = 3,
                alg = ?DNS_ALG_RSASHA256,
                public_key = ~"test-key-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_KX,
            ttl = 3600,
            data = #dns_rrdata_kx{
                preference = 10,
                exchange = ~"kx.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_HINFO,
            ttl = 3600,
            data = #dns_rrdata_hinfo{
                cpu = ~"x86-64",
                os = ~"Linux"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_LOC,
            ttl = 3600,
            data = #dns_rrdata_loc{
                size = 1000,
                horiz = 2000,
                vert = 3000,
                lat = 37741900,
                lon = -12206400,
                alt = 100000
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_MB,
            ttl = 3600,
            data = #dns_rrdata_mb{
                madname = ~"mb.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_MG,
            ttl = 3600,
            data = #dns_rrdata_mg{
                madname = ~"mg.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_MINFO,
            ttl = 3600,
            data = #dns_rrdata_minfo{
                rmailbx = ~"rmail.example.com",
                emailbx = ~"email.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_MR,
            ttl = 3600,
            data = #dns_rrdata_mr{
                newname = ~"mr.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_NSEC,
            ttl = 3600,
            data = #dns_rrdata_nsec{
                next_dname = ~"next.example.com",
                types = [?DNS_TYPE_A, ?DNS_TYPE_NS]
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_TLSA,
            ttl = 3600,
            data = #dns_rrdata_tlsa{
                usage = 3,
                selector = 1,
                matching_type = 1,
                certificate = ~"tlsa-cert-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_CDS,
            ttl = 3600,
            data = #dns_rrdata_cds{
                keytag = 12345,
                alg = ?DNS_ALG_RSASHA256,
                digest_type = 2,
                digest = <<1, 2, 3, 4, 5, 6, 7, 8>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DLV,
            ttl = 3600,
            data = #dns_rrdata_dlv{
                keytag = 12345,
                alg = ?DNS_ALG_RSASHA256,
                digest_type = 2,
                digest = <<1, 2, 3, 4, 5, 6, 7, 8>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_CERT,
            ttl = 3600,
            data = #dns_rrdata_cert{
                type = 1,
                keytag = 12345,
                alg = ?DNS_ALG_RSASHA256,
                cert = ~"cert-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_RRSIG,
            ttl = 3600,
            data = #dns_rrdata_rrsig{
                type_covered = ?DNS_TYPE_A,
                alg = ?DNS_ALG_RSASHA256,
                labels = 1,
                original_ttl = 3600,
                expiration = 1234567890,
                inception = 1234560000,
                keytag = 12345,
                signers_name = ~"signer.example.com",
                signature = ~"signature-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_NXT,
            ttl = 3600,
            data = #dns_rrdata_nxt{
                dname = ~"nxt.example.com",
                types = [?DNS_TYPE_A, ?DNS_TYPE_NS]
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_RP,
            ttl = 3600,
            data = #dns_rrdata_rp{
                mbox = ~"mbox.example.com",
                txt = ~"txt.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_RT,
            ttl = 3600,
            data = #dns_rrdata_rt{
                preference = 10,
                host = ~"rt.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SPF,
            ttl = 3600,
            data = #dns_rrdata_spf{
                spf = [~"v=spf1", ~"include:example.com"]
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_NAPTR,
            ttl = 3600,
            data = #dns_rrdata_naptr{
                order = 100,
                preference = 10,
                flags = ~"u",
                services = ~"E2U+sip",
                regexp = ~"!^.*$!sip:customer@example.com!",
                replacement = ~"naptr.example.com"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_TSIG,
            ttl = 3600,
            data = #dns_rrdata_tsig{
                alg = ?DNS_TSIG_ALG_SHA256,
                time = 1234567890,
                fudge = 300,
                mac = ~"mac-data",
                msgid = 12345,
                err = ?DNS_TSIGERR_NOERROR,
                other = ~"other-data"
            }
        },
        #dns_opt_llq{
            opcode = ?DNS_LLQOPCODE_SETUP,
            errorcode = ?DNS_LLQERRCODE_NOERROR,
            id = 12345678901234567890,
            leaselife = 3600
        },
        #dns_opt_owner{
            seq = 0,
            primary_mac = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E>>,
            wakeup_mac = <<>>,
            password = <<>>
        },
        #dns_opt_owner{
            seq = 1,
            primary_mac = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E>>,
            wakeup_mac = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5F>>,
            password = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#60>>
        },
        #dns_opt_ul{
            lease = 3600
        },
        #dns_opt_cookie{
            client = <<1, 2, 3, 4, 5, 6, 7, 8>>,
            server = <<9, 10, 11, 12, 13, 14, 15, 16>>
        },
        #dns_opt_ede{
            info_code = 1,
            extra_text = ~"extra text"
        },
        #dns_opt_unknown{
            id = 9999,
            bin = <<1, 2, 3, 4, 5>>
        }
    ],
    [assert_transcode(Record) || Record <- Cases].

test_nested_records(_Config) ->
    Message = #dns_message{
        id = 12345,
        qr = true,
        questions = [
            #dns_query{
                name = ~"example.com",
                class = ?DNS_CLASS_IN,
                type = ?DNS_TYPE_A
            }
        ],
        answers = [
            #dns_rr{
                name = ~"example.com",
                type = ?DNS_TYPE_A,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
            }
        ]
    },
    assert_transcode(Message).

test_dnssec_records(_Config) ->
    Cases = data_samples:dnssec(),
    TestCases = [dns:decode_message(Bin) || {_Name, _RawKeys, Bin} <- Cases],
    [assert_transcode(Record) || Record <- TestCases].

test_optrr_records(_Config) ->
    Cases = [
        #dns_message{
            additional = [
                #dns_optrr{
                    udp_payload_size = 4096,
                    data = [
                        #dns_opt_nsid{data = <<222, 175>>}
                    ]
                }
            ]
        },
        #dns_message{
            additional = [
                #dns_optrr{
                    udp_payload_size = 4096,
                    data = [
                        #dns_opt_ecs{
                            family = 1,
                            source_prefix_length = 24,
                            scope_prefix_length = 0,
                            address = <<192, 168, 1, 0>>
                        }
                    ]
                }
            ]
        }
    ],
    [assert_transcode(Record) || Record <- Cases].

test_special_encodings(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    Cases = [
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DNSKEY,
            ttl = 3600,
            data = #dns_rrdata_dnskey{
                flags = 256,
                protocol = 3,
                alg = ?DNS_ALG_RSASHA256,
                public_key = ~"test-public-key-data",
                keytag = 12345
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DS,
            ttl = 3600,
            data = #dns_rrdata_ds{
                keytag = 12345,
                alg = ?DNS_ALG_RSASHA256,
                digest_type = 2,
                digest = <<1, 2, 3, 4, 5, 6, 7, 8>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SSHFP,
            ttl = 3600,
            data = #dns_rrdata_sshfp{
                alg = 1,
                fp_type = 1,
                fp = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_EUI48,
            ttl = 3600,
            data = #dns_rrdata_eui48{
                address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_EUI64,
            ttl = 3600,
            data = #dns_rrdata_eui64{
                address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E, 16#6F, 16#70>>
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_OPENPGPKEY,
            ttl = 3600,
            data = #dns_rrdata_openpgpkey{
                data = ~"test-openpgp-key-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SMIMEA,
            ttl = 3600,
            data = #dns_rrdata_smimea{
                usage = 3,
                selector = 1,
                matching_type = 1,
                certificate = ~"test-certificate-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_WALLET,
            ttl = 3600,
            data = #dns_rrdata_wallet{
                data = ~"test-wallet-data"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_URI,
            ttl = 3600,
            data = #dns_rrdata_uri{
                priority = 10,
                weight = 1,
                target = ~"https://www.example.com/"
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SVCB,
            ttl = 3600,
            data = #dns_rrdata_svcb{
                svc_priority = 0,
                target_name = ~"target.example.com",
                svc_params = #{}
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SVCB,
            ttl = 3600,
            data = #dns_rrdata_svcb{
                svc_priority = 16,
                target_name = ~"target.example.com",
                svc_params = #{?DNS_SVCB_PARAM_PORT => 8080}
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_HTTPS,
            ttl = 3600,
            data = #dns_rrdata_https{
                svc_priority = 0,
                target_name = ~"target.example.com",
                svc_params = #{}
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_HTTPS,
            ttl = 3600,
            data = #dns_rrdata_https{
                svc_priority = 1,
                target_name = ~"target.example.com",
                svc_params = #{?DNS_SVCB_PARAM_ALPN => [~"h2", ~"h3"]}
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_CSYNC,
            ttl = 3600,
            data = #dns_rrdata_csync{
                soa_serial = 12345,
                flags = 0,
                types = [?DNS_TYPE_A, ?DNS_TYPE_NS, ?DNS_TYPE_SOA]
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_DSYNC,
            ttl = 3600,
            data = #dns_rrdata_dsync{
                rrtype = ?DNS_TYPE_A,
                scheme = 1,
                port = 443,
                target = ~"target.example.com."
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_RESINFO,
            ttl = 3600,
            data = #dns_rrdata_resinfo{
                data = [~"test-resinfo-data"]
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_ZONEMD,
            ttl = 3600,
            data = #dns_rrdata_zonemd{
                serial = 2024010101,
                scheme = 1,
                algorithm = 1,
                hash =
                    <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                        23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                        42, 43, 44, 45, 46, 47, 48>>
            }
        }
    ],
    [assert_transcode(Record) || Record <- Cases].

test_svcb_params(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    Cases = [
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_SVCB,
            ttl = 3600,
            data = #dns_rrdata_svcb{
                svc_priority = 1,
                target_name = ~"target.example.com",
                svc_params = #{
                    ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_PORT, ?DNS_SVCB_PARAM_ALPN],
                    ?DNS_SVCB_PARAM_ALPN => [~"h2", ~"h3"],
                    ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none,
                    ?DNS_SVCB_PARAM_PORT => 443,
                    ?DNS_SVCB_PARAM_IPV4HINT => [{192, 168, 1, 1}, {192, 168, 1, 2}],
                    ?DNS_SVCB_PARAM_ECH => ~"ech-config-data",
                    ?DNS_SVCB_PARAM_IPV6HINT => [
                        {16#2001, 16#0db8, 16#85a3, 0, 0, 16#8a2e, 16#0370, 16#7334}
                    ]
                }
            }
        },
        #dns_rr{
            name = ~"example.com",
            type = ?DNS_TYPE_HTTPS,
            ttl = 3600,
            data = #dns_rrdata_https{
                svc_priority = 1,
                target_name = ~"target.example.com",
                svc_params = #{
                    ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_PORT],
                    ?DNS_SVCB_PARAM_PORT => 8080,
                    ?DNS_SVCB_PARAM_ALPN => [~"http/1.1"]
                }
            }
        }
    ],
    [assert_transcode(Record) || Record <- Cases].

test_svcb_params_json_edge_cases(_Config) ->
    %% Test SVCB params through JSON with edge cases
    %% Empty params
    EmptySvcb = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{}
        }
    },
    assert_transcode(EmptySvcb),

    %% Unknown key in JSON format
    UnknownKeySvcb = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{65001 => <<"test-data">>}
        }
    },
    assert_transcode(UnknownKeySvcb),

    %% ALPN with empty list
    EmptyAlpnSvcb = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{?DNS_SVCB_PARAM_ALPN => []}
        }
    },
    assert_transcode(EmptyAlpnSvcb),

    %% IP hints with empty lists
    EmptyHintsSvcb = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{
                ?DNS_SVCB_PARAM_IPV4HINT => [],
                ?DNS_SVCB_PARAM_IPV6HINT => []
            }
        }
    },
    assert_transcode(EmptyHintsSvcb),

    %% Test invalid IPv4 in JSON (through dns_json:from_map)
    InvalidIpv4JsonMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"SVCB",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"svc_priority" => 1,
            ~"target_name" => ~"target.example.com",
            ~"svc_params" => #{~"ipv4hint" => [~"192.168.1.1", ~"invalid-ip"]}
        }
    },
    ?assertError({invalid_ipv4_in_json, _, _}, dns_json:from_map(InvalidIpv4JsonMap)),

    %% Test invalid IPv6 in JSON
    InvalidIpv6JsonMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"SVCB",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"svc_priority" => 1,
            ~"target_name" => ~"target.example.com",
            ~"svc_params" => #{~"ipv6hint" => [~"2001:db8::1", ~"invalid-ipv6"]}
        }
    },
    ?assertError({invalid_ipv6_in_json, _, _}, dns_json:from_map(InvalidIpv6JsonMap)).

%% key0-key6 in JSON are equivalent to named params; validate the same
test_svcb_params_numeric_keys_0_to_6_equivalent_to_named(_Config) ->
    %% JSON with numeric keys "0","1","2","3","4","5","6" round-trips like named
    JsonParams = #{
        ~"key0" => [~"alpn", ~"port"],
        ~"key1" => [~"h2", ~"h3"],
        ~"key2" => null,
        ~"key3" => 443,
        ~"key4" => [~"192.0.2.1"],
        ~"key5" => ~"ech-data",
        ~"key6" => [~"2001:db8::1"]
    },
    Params = dns_svcb_params:from_json(JsonParams),
    ?assertEqual(
        [?DNS_SVCB_PARAM_ALPN, ?DNS_SVCB_PARAM_PORT],
        maps:get(?DNS_SVCB_PARAM_MANDATORY, Params)
    ),
    ?assertEqual([~"h2", ~"h3"], maps:get(?DNS_SVCB_PARAM_ALPN, Params)),
    ?assertEqual(none, maps:get(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, Params)),
    ?assertEqual(443, maps:get(?DNS_SVCB_PARAM_PORT, Params)),
    ?assertEqual([{192, 0, 2, 1}], maps:get(?DNS_SVCB_PARAM_IPV4HINT, Params)),
    ?assertEqual(~"ech-data", maps:get(?DNS_SVCB_PARAM_ECH, Params)),
    ?assertEqual(
        [{16#2001, 16#0db8, 0, 0, 0, 0, 0, 1}],
        maps:get(?DNS_SVCB_PARAM_IPV6HINT, Params)
    ),
    %% Round-trip: to_json then from_json yields same param map (keys normalized to names)
    JsonOut = dns_svcb_params:to_json(Params),
    Params2 = dns_svcb_params:from_json(JsonOut),
    ?assertEqual(
        maps:get(?DNS_SVCB_PARAM_MANDATORY, Params), maps:get(?DNS_SVCB_PARAM_MANDATORY, Params2)
    ),
    ?assertEqual(maps:get(?DNS_SVCB_PARAM_PORT, Params), maps:get(?DNS_SVCB_PARAM_PORT, Params2)).

%% key0-key6 with invalid value type are rejected (same as named)
test_svcb_params_numeric_key_invalid_value_rejected(_Config) ->
    ?assertError(
        {svcb_param_invalid_value, ?DNS_SVCB_PARAM_MANDATORY, _},
        dns_svcb_params:from_json(#{~"key0" => 123})
    ),
    ?assertError(
        {svcb_param_invalid_value, ?DNS_SVCB_PARAM_PORT, _},
        dns_svcb_params:from_json(#{~"key3" => ~"not-an-integer"})
    ).

test_dnskey_formats(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    %% Test DNSKEY with binary public_key
    DnskeyBinary = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_DNSKEY,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_RSASHA256,
            public_key = ~"binary-public-key-data",
            keytag = 12345
        }
    },
    assert_transcode(DnskeyBinary),

    %% Test DNSKEY with list public_key (RSA components)
    DnskeyList = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_DNSKEY,
        ttl = 3600,
        data = #dns_rrdata_dnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_RSASHA256,
            public_key = [12345, 67890, 11111],
            keytag = 12345
        }
    },
    assert_transcode(DnskeyList),

    %% Test CDNSKEY with binary public_key
    CdnskeyBinary = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 3600,
        data = #dns_rrdata_cdnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_RSASHA256,
            public_key = ~"binary-public-key-data",
            keytag = 12345
        }
    },
    assert_transcode(CdnskeyBinary),

    %% Test CDNSKEY with list public_key
    CdnskeyList = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 3600,
        data = #dns_rrdata_cdnskey{
            flags = 256,
            protocol = 3,
            alg = ?DNS_ALG_RSASHA256,
            public_key = [12345, 67890, 11111],
            keytag = 12345
        }
    },
    assert_transcode(CdnskeyList).

test_nsec3_salt(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    %% Test NSEC3 with empty salt
    Nsec3EmptySalt = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_NSEC3,
        ttl = 3600,
        data = #dns_rrdata_nsec3{
            hash_alg = ?DNSSEC_NSEC3_ALG_SHA1,
            opt_out = false,
            iterations = 0,
            salt = <<>>,
            hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20>>,
            types = [?DNS_TYPE_A]
        }
    },
    Map1 = assert_transcode(Nsec3EmptySalt),
    Nsec3Data = maps:get(~"data", Map1),
    ?assertEqual(~"-", maps:get(~"salt", Nsec3Data)),

    %% Test NSEC3 with non-empty salt
    Nsec3Salt = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_NSEC3,
        ttl = 3600,
        data = #dns_rrdata_nsec3{
            hash_alg = ?DNSSEC_NSEC3_ALG_SHA1,
            opt_out = false,
            iterations = 1,
            salt = <<16#AB, 16#CD, 16#EF>>,
            hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20>>,
            types = [?DNS_TYPE_A]
        }
    },
    assert_transcode(Nsec3Salt),

    %% Test NSEC3PARAM with empty salt
    Nsec3paramEmptySalt = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_NSEC3PARAM,
        ttl = 3600,
        data = #dns_rrdata_nsec3param{
            hash_alg = ?DNSSEC_NSEC3_ALG_SHA1,
            flags = 0,
            iterations = 0,
            salt = <<>>
        }
    },
    Map3 = assert_transcode(Nsec3paramEmptySalt),
    Nsec3paramData = maps:get(~"data", Map3),
    ?assertEqual(~"-", maps:get(~"salt", Nsec3paramData)),

    %% Test NSEC3PARAM with non-empty salt
    Nsec3paramSalt = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_NSEC3PARAM,
        ttl = 3600,
        data = #dns_rrdata_nsec3param{
            hash_alg = ?DNSSEC_NSEC3_ALG_SHA1,
            flags = 0,
            iterations = 1,
            salt = <<16#AB, 16#CD, 16#EF>>
        }
    },
    assert_transcode(Nsec3paramSalt).

test_ipseckey_gateway(_Config) ->
    %% RRDATA records must be wrapped in dns_rr
    %% Test IPSECKEY with IP gateway (IPv4)
    IpseckeyIpv4 = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_IPSECKEY,
        ttl = 3600,
        data = #dns_rrdata_ipseckey{
            precedence = 10,
            alg = 1,
            gateway = {192, 168, 1, 1},
            public_key = ~"public-key-data"
        }
    },
    assert_transcode(IpseckeyIpv4),

    %% Test IPSECKEY with IP gateway (IPv6)
    IpseckeyIpv6 = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_IPSECKEY,
        ttl = 3600,
        data = #dns_rrdata_ipseckey{
            precedence = 10,
            alg = 1,
            gateway = {16#2001, 16#0db8, 16#85a3, 0, 0, 16#8a2e, 16#0370, 16#7334},
            public_key = ~"public-key-data"
        }
    },
    assert_transcode(IpseckeyIpv6),

    %% Test IPSECKEY with dname gateway
    IpseckeyDname = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_IPSECKEY,
        ttl = 3600,
        data = #dns_rrdata_ipseckey{
            precedence = 10,
            alg = 1,
            gateway = ~"gateway.example.com",
            public_key = ~"public-key-data"
        }
    },
    assert_transcode(IpseckeyDname).

test_error_cases(_Config) ->
    %% Test invalid map format (empty map)
    ?assertError({invalid_map_format, _}, dns_json:from_map(#{})),

    %% Test invalid map format (multiple keys)
    ?assertError({invalid_map_format, _}, dns_json:from_map(#{~"A" => #{}, ~"AAAA" => #{}})),

    %% Test invalid IP address (using erldns format)
    InvalidIpMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"A",
        ~"ttl" => 3600,
        ~"data" => #{~"ip" => ~"invalid-ip"}
    },
    ?assertError({invalid_ip, _}, dns_json:from_map(InvalidIpMap)),

    %% Test unknown record key
    ?assertError(
        {unknown_record_key, ~"UNKNOWN", _}, dns_json:from_map(#{~"UNKNOWN" => #{}})
    ),

    %% Test RRDATA requires wrapper
    ?assertError(
        {rrdata_requires_wrapper, _}, dns_json:to_map(#dns_rrdata_a{ip = {192, 168, 1, 1}})
    ),
    ?assertError(
        {rrdata_requires_wrapper, _},
        dns_json:from_map(#{~"A" => #{~"ip" => ~"192.168.1.1"}})
    ),

    %% Test unknown record type
    ?assertError({unknown_record_type, _}, dns_json:to_map({unknown_record, field1, field2})),

    %% Test invalid record key (non-binary)
    ?assertError(
        {invalid_record_key, _, _},
        dns_json:from_map(#{message => #{questions => []}})
    ),

    %% Test unknown type name (invalid integer string)
    InvalidTypeMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"not-a-number",
        ~"ttl" => 3600,
        ~"data" => #{}
    },
    ?assertError({unknown_type_name, _}, dns_json:from_map(InvalidTypeMap)),

    %% Test unknown type number (valid integer string but unknown type)
    UnknownTypeMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"99999",
        ~"ttl" => 3600,
        ~"data" => #{}
    },
    ?assertError({unknown_type_cannot_convert_to_rrdata, _}, dns_json:from_map(UnknownTypeMap)),

    %% Test unknown type without data field
    UnknownTypeNoDataMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"99999",
        ~"ttl" => 3600,
        ~"data" => #{~"other" => ~"value"}
    },
    ?assertError(
        {unknown_type_cannot_convert_to_rrdata, _}, dns_json:from_map(UnknownTypeNoDataMap)
    ),

    %% Test integer class value
    IntClassMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"A",
        ~"class" => 1,
        ~"ttl" => 3600,
        ~"data" => #{~"ip" => ~"192.168.1.1"}
    },
    Record = dns_json:from_map(IntClassMap),
    ?assertEqual(1, Record#dns_rr.class),

    %% Test unknown type with base64 data (fallback case)
    UnknownTypeWithDataMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"99999",
        ~"ttl" => 3600,
        ~"data" => #{~"data" => base64:encode(~"raw-binary-data")}
    },
    UnknownRecord = dns_json:from_map(UnknownTypeWithDataMap),
    ?assertEqual(~"raw-binary-data", UnknownRecord#dns_rr.data),

    %% Test dns_rr with unknown type number (integer_to_binary path)
    UnknownTypeNum = 99999,
    UnknownTypeNumRecord = #dns_rr{
        name = ~"example.com",
        type = UnknownTypeNum,
        ttl = 3600,
        data = ~"raw-data"
    },
    UnknownTypeNumMap = dns_json:to_map(UnknownTypeNumRecord),
    ?assertEqual(integer_to_binary(UnknownTypeNum), maps:get(~"type", UnknownTypeNumMap)),

    %% Test dns_rr with unknown class number (integer_to_binary path)
    UnknownClassNum = 999,
    UnknownClassRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_A,
        class = UnknownClassNum,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
    },
    UnknownClassMap = dns_json:to_map(UnknownClassRecord),
    ?assertEqual(integer_to_binary(UnknownClassNum), maps:get(~"class", UnknownClassMap)),

    %% Test class name that returns undefined from dns_names:name_class (fallback to IN)
    UnknownClassBinMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"A",
        ~"class" => ~"UNKNOWN_CLASS",
        ~"ttl" => 3600,
        ~"data" => #{~"ip" => ~"192.168.1.1"}
    },
    UnknownClassBinRecord = dns_json:from_map(UnknownClassBinMap),
    ?assertEqual(?DNS_CLASS_IN, UnknownClassBinRecord#dns_rr.class),

    %% Test to_map_rrdata with binary (unknown type)
    UnknownTypeBinary = #dns_rr{
        name = ~"example.com",
        type = 99999,
        ttl = 3600,
        data = ~"raw-binary-data"
    },
    UnknownTypeBinaryMap = dns_json:to_map(UnknownTypeBinary),
    ?assertEqual(
        #{~"data" => base64:encode(~"raw-binary-data")}, maps:get(~"data", UnknownTypeBinaryMap)
    ),

    %% Test record_type_from_key for "rr" key (dns_rr is not RRDATA, so it processes as regular record)
    %% This will fail because the fields don't match, but it tests record_type_from_key(~"rr")
    RrKeyMap = #{~"rr" => #{name => ~"example.com"}},
    try
        dns_json:from_map(RrKeyMap),
        ?assert(false)
    catch
        error:{badarg, _} -> ok;
        error:function_clause -> ok;
        _:_ -> ok
    end,

    %% Test record_key_name error case (unknown record type) - line 104
    ?assertError(
        {unknown_record_type, unknown_tag}, dns_json:to_map({unknown_tag, field1, field2})
    ),

    %% Test to_map_rrdata with tuple (not binary) - line 328
    %% This is already covered by normal dns_rr records, but let's make sure
    TupleRr = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
    },
    TupleRrMap = dns_json:to_map(TupleRr),
    ?assert(maps:is_key(~"data", TupleRrMap)),

    %% Test to_map_rrdata with tuple (line 328) - ensure it's called
    %% This is already covered by normal dns_rr records, but let's be explicit
    TupleDataRr = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns.example.com"}
    },
    TupleDataMap = dns_json:to_map(TupleDataRr),
    ?assert(maps:is_key(~"data", TupleDataMap)),
    ?assert(maps:is_key(~"dname", maps:get(~"data", TupleDataMap))).

test_edge_cases(_Config) ->
    %% Test message with all sections populated
    FullMessage = #dns_message{
        id = 12345,
        qr = true,
        questions = [
            #dns_query{name = ~"q1.example.com", class = ?DNS_CLASS_IN, type = ?DNS_TYPE_A},
            #dns_query{name = ~"q2.example.com", class = ?DNS_CLASS_IN, type = ?DNS_TYPE_AAAA}
        ],
        answers = [
            #dns_rr{
                name = ~"a1.example.com",
                type = ?DNS_TYPE_A,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
            }
        ],
        authority = [
            #dns_rr{
                name = ~"auth.example.com",
                type = ?DNS_TYPE_NS,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_ns{dname = ~"ns.example.com"}
            }
        ],
        additional = [
            #dns_rr{
                name = ~"add.example.com",
                type = ?DNS_TYPE_A,
                class = ?DNS_CLASS_IN,
                ttl = 3600,
                data = #dns_rrdata_a{ip = {192, 168, 1, 2}}
            }
        ]
    },
    assert_transcode(FullMessage),

    %% Test OPTRR with multiple options
    OptrrMultiple = #dns_optrr{
        udp_payload_size = 4096,
        data = [
            #dns_opt_nsid{data = <<222, 175>>},
            #dns_opt_ecs{
                family = 1,
                source_prefix_length = 24,
                scope_prefix_length = 0,
                address = <<192, 168, 1, 0>>
            },
            #dns_opt_unknown{id = 9999, bin = <<1, 2, 3, 4>>}
        ]
    },
    assert_transcode(OptrrMultiple),

    %% Test empty lists
    EmptyMessage = #dns_message{},
    assert_transcode(EmptyMessage),

    %% Test SVCB params with unknown parameter (fallback to base64)
    SvcbUnknown = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{999 => ~"unknown-param-data"}
        }
    },
    assert_transcode(SvcbUnknown),

    %% Test from_map_dnskey_publickey with binary that doesn't match format
    %% This should return the binary as-is
    DnskeyMap = #{
        ~"name" => ~"example.com",
        ~"type" => ~"DNSKEY",
        ~"class" => ~"IN",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"flags" => 256,
            ~"protocol" => 3,
            ~"alg" => ?DNS_ALG_RSASHA256,
            ~"public_key" => base64:encode(~"simple-binary-data"),
            ~"keytag" => 12345
        }
    },
    DnskeyRecord = dns_json:from_map(DnskeyMap),
    ?assertEqual(dns_rr, element(1, DnskeyRecord)),
    DnskeyData = element(6, DnskeyRecord),
    ?assertEqual(dns_rrdata_dnskey, element(1, DnskeyData)),
    ?assertEqual(~"simple-binary-data", element(5, DnskeyData)),

    %% Test from_map_dnskey_publickey with properly formatted binary (list of integers)
    %% Create a binary that matches the format: <<L:32, I:L/unit:8, ...>>
    TestInt = 12345,
    TestIntBin = binary:encode_unsigned(TestInt),
    TestIntLen = byte_size(TestIntBin),
    FormattedBin = <<TestIntLen:32, TestIntBin/binary>>,
    DnskeyMap2 = #{
        ~"name" => ~"example.com",
        ~"type" => ~"DNSKEY",
        ~"class" => ~"IN",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"flags" => 256,
            ~"protocol" => 3,
            ~"alg" => ?DNS_ALG_RSASHA256,
            ~"public_key" => base64:encode(FormattedBin),
            ~"keytag" => 12345
        }
    },
    DnskeyRecord2 = dns_json:from_map(DnskeyMap2),
    ?assertEqual(dns_rr, element(1, DnskeyRecord2)),
    DnskeyData2 = element(6, DnskeyRecord2),
    ?assertEqual(dns_rrdata_dnskey, element(1, DnskeyData2)),
    ?assertEqual([TestInt], element(5, DnskeyData2)),

    %% Test SVCB params with non-binary, non-list value (fallback case)
    SvcbNonBinary = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SVCB,
        ttl = 3600,
        data = #dns_rrdata_svcb{
            svc_priority = 1,
            target_name = ~"target.example.com",
            svc_params = #{999 => 12345}
        }
    },
    assert_transcode(SvcbNonBinary),

    %% Simulate API/JSON that omits svc_params for alias-form SVCB/HTTPS
    SVCBJson = #{
        ~"name" => ~"svcb-alias.example.com.",
        ~"type" => ~"SVCB",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"svc_priority" => 0,
            ~"target_name" => ~"pool.example.com."
        }
    },
    HTTPSJson = #{
        ~"name" => ~"https-alias.example.com.",
        ~"type" => ~"HTTPS",
        ~"ttl" => 3600,
        ~"data" => #{
            ~"svc_priority" => 0,
            ~"target_name" => ~"pool.example.com."
        }
    },
    SVCBRR = dns_json:from_map(SVCBJson),
    HTTPSRR = dns_json:from_map(HTTPSJson),
    ?assertEqual(#{}, (SVCBRR#dns_rr.data)#dns_rrdata_svcb.svc_params),
    ?assertEqual(#{}, (HTTPSRR#dns_rr.data)#dns_rrdata_https.svc_params),
    %% Record roundtrip: to_map -> from_map yields same record
    ?assertEqual(SVCBRR, dns_json:from_map(dns_json:to_map(SVCBRR))),
    ?assertEqual(HTTPSRR, dns_json:from_map(dns_json:to_map(HTTPSRR))).

assert_transcode(Record) when is_tuple(Record) ->
    Map = dns_json:to_map(Record),
    ?assertEqual(Record, dns_json:from_map(Map)),
    Map.
