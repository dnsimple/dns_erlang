-module(dns_check_SUITE).
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
            rrdata_integers_must_fit,
            rrdata_addresses_must_fit,
            rrdata_loc_coordinates_must_fit,
            rrdata_lengths_must_fit,
            rrdata_type_numbers_must_fit,
            rrdata_names_must_fit,
            ilnp_64_bit_values_must_be_8_bytes,
            amtrelay_relay_must_match_its_type,
            drip_data_must_not_be_empty,
            hip_hit_and_key_must_fit,
            svcb_params_must_fit,
            rr_header_must_fit,
            rr_class_must_suit_rrdata,
            header_must_fit,
            query_must_fit,
            optrr_must_fit,
            opts_must_fit
        ]}
    ].

%% Bit syntax keeps only the low bits of an integer too wide for its segment, so
%% the encoder writes 70000 as preference 4464 and -1 as 65535. Every fixed-width
%% RDATA field must take its largest value and refuse one past it.
rrdata_integers_must_fit(_) ->
    N = <<"example.com">>,
    P256 = <<0:512>>,
    Dnskey = #dns_rrdata_dnskey{flags = 257, protocol = 3, alg = 13, public_key = P256},
    RsaDnskey = Dnskey#dns_rrdata_dnskey{alg = ?DNS_ALG_RSASHA256, public_key = [65537, 12345]},
    Cdnskey = #dns_rrdata_cdnskey{flags = 257, protocol = 3, alg = 13, public_key = P256},
    RsaCdnskey = Cdnskey#dns_rrdata_cdnskey{alg = ?DNS_ALG_RSASHA256, public_key = [65537, 12345]},
    Ds = #dns_rrdata_ds{keytag = 1, alg = 1, digest_type = 1, digest = <<1>>},
    Cds = #dns_rrdata_cds{keytag = 1, alg = 1, digest_type = 1, digest = <<1>>},
    Dlv = #dns_rrdata_dlv{keytag = 1, alg = 1, digest_type = 1, digest = <<1>>},
    Key = #dns_rrdata_key{
        type = 0, xt = 0, name_type = 0, sig = 0, protocol = 3, alg = 1, public_key = <<1>>
    },
    Nsec3 = #dns_rrdata_nsec3{
        hash_alg = 1, opt_out = false, iterations = 1, salt = <<>>, hash = <<1>>, types = []
    },
    Nsec3Param = #dns_rrdata_nsec3param{hash_alg = 1, flags = 0, iterations = 1, salt = <<>>},
    Tlsa = #dns_rrdata_tlsa{usage = 1, selector = 1, matching_type = 1, certificate = <<1>>},
    Smimea = #dns_rrdata_smimea{usage = 1, selector = 1, matching_type = 1, certificate = <<1>>},
    Rrsig = #dns_rrdata_rrsig{
        type_covered = 1,
        alg = 13,
        labels = 1,
        original_ttl = 1,
        expiration = 1,
        inception = 1,
        keytag = 1,
        signers_name = N,
        signature = <<1>>
    },
    Sig = #dns_rrdata_sig{
        type_covered = 0,
        alg = 15,
        labels = 0,
        original_ttl = 0,
        expiration = 1,
        inception = 1,
        keytag = 1,
        signers_name = N,
        signature = <<1>>
    },
    Soa = #dns_rrdata_soa{
        mname = N, rname = N, serial = 1, refresh = 1, retry = 1, expire = 1, minimum = 1
    },
    Srv = #dns_rrdata_srv{priority = 1, weight = 1, port = 1, target = N},
    Tsig = #dns_rrdata_tsig{
        alg = N, time = 1, fudge = 1, mac = <<1>>, msgid = 1, err = 0, other = <<>>
    },
    Cases = [
        {#dns_rrdata_afsdb{subtype = 1, hostname = N}, #dns_rrdata_afsdb.subtype, 16},
        {#dns_rrdata_caa{flags = 0, tag = <<"issue">>, value = <<>>}, #dns_rrdata_caa.flags, 8},
        {#dns_rrdata_cert{type = 1, keytag = 1, alg = 1, cert = <<1>>}, #dns_rrdata_cert.type, 16},
        {
            #dns_rrdata_cert{type = 1, keytag = 1, alg = 1, cert = <<1>>},
            #dns_rrdata_cert.keytag,
            16
        },
        {#dns_rrdata_cert{type = 1, keytag = 1, alg = 1, cert = <<1>>}, #dns_rrdata_cert.alg, 8},
        {#dns_rrdata_uri{priority = 1, weight = 1, target = <<"x">>}, #dns_rrdata_uri.priority, 16},
        {#dns_rrdata_uri{priority = 1, weight = 1, target = <<"x">>}, #dns_rrdata_uri.weight, 16},
        {Ds, #dns_rrdata_ds.keytag, 16},
        {Ds, #dns_rrdata_ds.alg, 8},
        {Ds, #dns_rrdata_ds.digest_type, 8},
        {Cds, #dns_rrdata_cds.keytag, 16},
        {Cds, #dns_rrdata_cds.alg, 8},
        {Cds, #dns_rrdata_cds.digest_type, 8},
        {Dlv, #dns_rrdata_dlv.keytag, 16},
        {Dlv, #dns_rrdata_dlv.alg, 8},
        {Dlv, #dns_rrdata_dlv.digest_type, 8},
        {Dnskey, #dns_rrdata_dnskey.flags, 16},
        {Dnskey, #dns_rrdata_dnskey.protocol, 8},
        {Dnskey, #dns_rrdata_dnskey.alg, 8},
        {RsaDnskey, #dns_rrdata_dnskey.flags, 16},
        {RsaDnskey, #dns_rrdata_dnskey.protocol, 8},
        {Cdnskey, #dns_rrdata_cdnskey.flags, 16},
        {Cdnskey, #dns_rrdata_cdnskey.protocol, 8},
        {Cdnskey, #dns_rrdata_cdnskey.alg, 8},
        {RsaCdnskey, #dns_rrdata_cdnskey.flags, 16},
        {RsaCdnskey, #dns_rrdata_cdnskey.protocol, 8},
        {
            #dns_rrdata_zonemd{serial = 1, scheme = 1, algorithm = 1, hash = <<1>>},
            #dns_rrdata_zonemd.serial,
            32
        },
        {
            #dns_rrdata_zonemd{serial = 1, scheme = 1, algorithm = 1, hash = <<1>>},
            #dns_rrdata_zonemd.scheme,
            8
        },
        {
            #dns_rrdata_zonemd{serial = 1, scheme = 1, algorithm = 1, hash = <<1>>},
            #dns_rrdata_zonemd.algorithm,
            8
        },
        {
            #dns_rrdata_ipseckey{precedence = 1, alg = 1, gateway = <<>>, public_key = <<1>>},
            #dns_rrdata_ipseckey.precedence,
            8
        },
        {
            #dns_rrdata_ipseckey{precedence = 1, alg = 1, gateway = N, public_key = <<1>>},
            #dns_rrdata_ipseckey.alg,
            8
        },
        {Key, #dns_rrdata_key.type, 2},
        {Key, #dns_rrdata_key.xt, 1},
        {Key, #dns_rrdata_key.name_type, 2},
        {Key, #dns_rrdata_key.sig, 4},
        {Key, #dns_rrdata_key.protocol, 8},
        {Key, #dns_rrdata_key.alg, 8},
        {#dns_rrdata_kx{preference = 1, exchange = N}, #dns_rrdata_kx.preference, 16},
        {#dns_rrdata_mx{preference = 1, exchange = N}, #dns_rrdata_mx.preference, 16},
        {#dns_rrdata_rt{preference = 1, host = N}, #dns_rrdata_rt.preference, 16},
        {
            #dns_rrdata_naptr{
                order = 1,
                preference = 1,
                flags = <<>>,
                services = <<>>,
                regexp = <<>>,
                replacement = N
            },
            #dns_rrdata_naptr.order,
            16
        },
        {
            #dns_rrdata_naptr{
                order = 1,
                preference = 1,
                flags = <<>>,
                services = <<>>,
                regexp = <<>>,
                replacement = N
            },
            #dns_rrdata_naptr.preference,
            16
        },
        {
            #dns_rrdata_csync{soa_serial = 1, flags = 0, types = [1]},
            #dns_rrdata_csync.soa_serial,
            32
        },
        {#dns_rrdata_csync{soa_serial = 1, flags = 0, types = [1]}, #dns_rrdata_csync.flags, 16},
        {
            #dns_rrdata_dsync{rrtype = 1, scheme = 1, port = 1, target = N},
            #dns_rrdata_dsync.rrtype,
            16
        },
        {
            #dns_rrdata_dsync{rrtype = 1, scheme = 1, port = 1, target = N},
            #dns_rrdata_dsync.scheme,
            8
        },
        {
            #dns_rrdata_dsync{rrtype = 1, scheme = 1, port = 1, target = N},
            #dns_rrdata_dsync.port,
            16
        },
        {Nsec3, #dns_rrdata_nsec3.hash_alg, 8},
        {Nsec3, #dns_rrdata_nsec3.iterations, 16},
        {Nsec3Param, #dns_rrdata_nsec3param.hash_alg, 8},
        {Nsec3Param, #dns_rrdata_nsec3param.flags, 8},
        {Nsec3Param, #dns_rrdata_nsec3param.iterations, 16},
        {Tlsa, #dns_rrdata_tlsa.usage, 8},
        {Tlsa, #dns_rrdata_tlsa.selector, 8},
        {Tlsa, #dns_rrdata_tlsa.matching_type, 8},
        {Smimea, #dns_rrdata_smimea.usage, 8},
        {Smimea, #dns_rrdata_smimea.selector, 8},
        {Smimea, #dns_rrdata_smimea.matching_type, 8},
        {Rrsig, #dns_rrdata_rrsig.type_covered, 16},
        {Rrsig, #dns_rrdata_rrsig.alg, 8},
        {Rrsig, #dns_rrdata_rrsig.labels, 8},
        {Rrsig, #dns_rrdata_rrsig.original_ttl, 32},
        {Rrsig, #dns_rrdata_rrsig.expiration, 32},
        {Rrsig, #dns_rrdata_rrsig.inception, 32},
        {Rrsig, #dns_rrdata_rrsig.keytag, 16},
        {Soa, #dns_rrdata_soa.serial, 32},
        {Soa, #dns_rrdata_soa.refresh, 32},
        {Soa, #dns_rrdata_soa.retry, 32},
        {Soa, #dns_rrdata_soa.expire, 32},
        {Soa, #dns_rrdata_soa.minimum, 32},
        {Srv, #dns_rrdata_srv.priority, 16},
        {Srv, #dns_rrdata_srv.weight, 16},
        {Srv, #dns_rrdata_srv.port, 16},
        {#dns_rrdata_sshfp{alg = 1, fp_type = 1, fp = <<1>>}, #dns_rrdata_sshfp.alg, 8},
        {#dns_rrdata_sshfp{alg = 1, fp_type = 1, fp = <<1>>}, #dns_rrdata_sshfp.fp_type, 8},
        {
            #dns_rrdata_svcb{svc_priority = 1, target_name = N, svc_params = #{}},
            #dns_rrdata_svcb.svc_priority,
            16
        },
        {
            #dns_rrdata_https{svc_priority = 1, target_name = N, svc_params = #{}},
            #dns_rrdata_https.svc_priority,
            16
        },
        {Tsig, #dns_rrdata_tsig.time, 48},
        {Tsig, #dns_rrdata_tsig.fudge, 16},
        {Tsig, #dns_rrdata_tsig.msgid, 16},
        {Tsig, #dns_rrdata_tsig.err, 16},
        {#dns_rrdata_nid{preference = 1, node_id = <<1:64>>}, #dns_rrdata_nid.preference, 16},
        {#dns_rrdata_l32{preference = 1, locator32 = {1, 2, 3, 4}}, #dns_rrdata_l32.preference, 16},
        {#dns_rrdata_l64{preference = 1, locator64 = <<1:64>>}, #dns_rrdata_l64.preference, 16},
        {#dns_rrdata_lp{preference = 1, fqdn = N}, #dns_rrdata_lp.preference, 16},
        {
            #dns_rrdata_amtrelay{
                precedence = 1, discovery_optional = false, relay_type = 3, relay = N
            },
            #dns_rrdata_amtrelay.precedence,
            8
        },
        {
            #dns_rrdata_hip{alg = 1, hit = <<1>>, public_key = <<1>>, rendezvous_servers = []},
            #dns_rrdata_hip.alg,
            8
        },
        {Sig, #dns_rrdata_sig.type_covered, 16},
        {Sig, #dns_rrdata_sig.alg, 8},
        {Sig, #dns_rrdata_sig.labels, 8},
        {Sig, #dns_rrdata_sig.original_ttl, 32},
        {Sig, #dns_rrdata_sig.expiration, 32},
        {Sig, #dns_rrdata_sig.inception, 32},
        {Sig, #dns_rrdata_sig.keytag, 16},
        {#dns_rrdata_px{preference = 1, map822 = N, mapx400 = N}, #dns_rrdata_px.preference, 16}
    ],
    [
        begin
            Max = (1 bsl Bits) - 1,
            Label = {element(1, Base), Idx},
            ?assert(dns_check:rrdata(setelement(Idx, Base, Max)), Label),
            [?assertNot(dns_check:rrdata(setelement(Idx, Base, V)), Label) || V <- [Max + 1, -1]]
        end
     || {Base, Idx, Bits} <- Cases
    ].

%% An address is written octet by octet (A, IPSECKEY) or in 16-bit groups (AAAA),
%% and is truncated the same way: {300, 1, 2, 3} goes out as 44.1.2.3
rrdata_addresses_must_fit(_) ->
    Ipseckey = fun(Gateway) ->
        #dns_rrdata_ipseckey{precedence = 1, alg = 1, gateway = Gateway, public_key = <<1>>}
    end,
    Amtrelay = fun(RelayType, Relay) ->
        #dns_rrdata_amtrelay{
            precedence = 1, discovery_optional = false, relay_type = RelayType, relay = Relay
        }
    end,
    Fits = [
        #dns_rrdata_a{ip = {255, 255, 255, 255}},
        #dns_rrdata_aaaa{ip = {65535, 0, 0, 0, 0, 0, 0, 65535}},
        Ipseckey({255, 0, 0, 255}),
        Ipseckey({65535, 0, 0, 0, 0, 0, 0, 65535}),
        #dns_rrdata_l32{preference = 1, locator32 = {255, 255, 255, 255}},
        Amtrelay(1, {255, 255, 255, 255}),
        Amtrelay(2, {65535, 0, 0, 0, 0, 0, 0, 65535})
    ],
    DoNotFit = [
        #dns_rrdata_a{ip = {256, 0, 0, 0}},
        #dns_rrdata_a{ip = {0, 0, 0, -1}},
        #dns_rrdata_aaaa{ip = {65536, 0, 0, 0, 0, 0, 0, 1}},
        #dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, -1}},
        Ipseckey({256, 0, 0, 1}),
        Ipseckey({0, 0, 0, 0, 0, 0, 0, 65536}),
        #dns_rrdata_l32{preference = 1, locator32 = {256, 0, 0, 0}},
        Amtrelay(1, {256, 0, 0, 0}),
        Amtrelay(2, {0, 0, 0, 0, 0, 0, 0, 65536})
    ],
    [?assert(dns_check:rrdata(D), D) || D <- Fits],
    [?assertNot(dns_check:rrdata(D), D) || D <- DoNotFit].

%% RFC1876§2: latitude and longitude are offsets from 2^31 and altitude from
%% -100000.00 m, each written in 32 bits
rrdata_loc_coordinates_must_fit(_) ->
    Loc = fun(Lat, Lon, Alt) ->
        #dns_rrdata_loc{size = 1, horiz = 1, vert = 1, lat = Lat, lon = Lon, alt = Alt}
    end,
    Edge = 1 bsl 31,
    AltMax = (1 bsl 32) - 1 - 10000000,
    Fits = [Loc(Edge - 1, -Edge, -10000000), Loc(-Edge, Edge - 1, AltMax)],
    DoNotFit = [
        Loc(Edge, 0, 0),
        Loc(-Edge - 1, 0, 0),
        Loc(0, Edge, 0),
        Loc(0, 0, -10000001),
        Loc(0, 0, AltMax + 1)
    ],
    [?assert(dns_check:rrdata(D), D) || D <- Fits],
    [?assertNot(dns_check:rrdata(D), D) || D <- DoNotFit].

%% A length written ahead of its field wraps like any other integer: a 256-byte
%% CAA tag or NSEC3 salt is announced as 0 bytes, and RDATA over 65535 bytes gets
%% an RDLENGTH that wraps (RFC1035§3.2.1). HINFO's CPU and OS are one
%% <character-string> each, which the encoder would split into several.
rrdata_lengths_must_fit(_) ->
    Bytes = fun(Size) -> binary:copy(<<"a">>, Size) end,
    Caa = fun(Tag) -> #dns_rrdata_caa{flags = 0, tag = Tag, value = <<>>} end,
    Nsec3 = fun(Salt, Hash) ->
        #dns_rrdata_nsec3{
            hash_alg = 1, opt_out = false, iterations = 1, salt = Salt, hash = Hash, types = []
        }
    end,
    Nsec3Param = fun(Salt) ->
        #dns_rrdata_nsec3param{hash_alg = 1, flags = 0, iterations = 1, salt = Salt}
    end,
    Tsig = fun(MAC, Other) ->
        #dns_rrdata_tsig{
            alg = <<"hmac-sha256">>,
            time = 1,
            fudge = 1,
            mac = MAC,
            msgid = 1,
            err = 0,
            other = Other
        }
    end,
    %% 255 strings of 255 bytes and one of 254, each after its length byte
    TxtOf = fun(Last) ->
        #dns_rrdata_txt{txt = lists:duplicate(255, Bytes(255)) ++ [Bytes(Last)]}
    end,
    Hinfo = fun(CPU, OS) -> #dns_rrdata_hinfo{cpu = CPU, os = OS} end,
    Naptr = fun(Regexp) ->
        #dns_rrdata_naptr{
            order = 1,
            preference = 1,
            flags = <<>>,
            services = <<>>,
            regexp = Regexp,
            replacement = <<"example.com">>
        }
    end,
    Fits = [
        Hinfo(Bytes(255), Bytes(255)),
        Naptr(Bytes(255)),
        Caa(Bytes(255)),
        Nsec3(Bytes(255), Bytes(255)),
        Nsec3Param(Bytes(255)),
        Tsig(Bytes(1000), Bytes(1000)),
        TxtOf(254),
        Bytes(65535)
    ],
    DoNotFit = [
        Hinfo(Bytes(256), <<>>),
        Hinfo(<<>>, Bytes(256)),
        Naptr(Bytes(256)),
        Caa(Bytes(256)),
        Nsec3(Bytes(256), <<1>>),
        Nsec3(<<>>, Bytes(256)),
        Nsec3Param(Bytes(256)),
        Tsig(Bytes(65536), <<>>),
        Tsig(<<>>, Bytes(65536)),
        TxtOf(255),
        Bytes(65536)
    ],
    [?assert(dns_check:rrdata(D), D) || D <- Fits],
    [?assertNot(dns_check:rrdata(D), D) || D <- DoNotFit],
    %% And as part of a whole record
    ?assertNot(
        dns_check:rr(#dns_rr{
            name = <<"example.com">>, type = ?DNS_TYPE_TXT, ttl = 1, data = TxtOf(255)
        })
    ).

%% RFC4034§4.1.2: a type bitmap window number is 8 bits, so type 65536 would land
%% in window 0 as type 0
rrdata_type_numbers_must_fit(_) ->
    Records = fun(Types) ->
        [
            #dns_rrdata_nsec{next_dname = <<"example.com">>, types = Types},
            #dns_rrdata_nsec3{
                hash_alg = 1,
                opt_out = false,
                iterations = 1,
                salt = <<>>,
                hash = <<1>>,
                types = Types
            },
            #dns_rrdata_csync{soa_serial = 1, flags = 0, types = Types}
        ]
    end,
    [?assert(dns_check:rrdata(D), D) || D <- Records([0, 65535])],
    [
        ?assertNot(dns_check:rrdata(D), D)
     || Types <- [[1, 65536], [-1, 1]], D <- Records(Types)
    ].

%% RFC9460§2.2: keys, ports and mandatory keys are 16 bits and hints are
%% addresses. Ports and keys would wrap, and the encoder skips a hint that is
%% not an address tuple, leaving the record shorter than it was written.
svcb_params_must_fit(_) ->
    Svcb = fun(Params) ->
        #dns_rrdata_svcb{svc_priority = 1, target_name = <<"svc.example.com">>, svc_params = Params}
    end,
    Fits = [
        #{?DNS_SVCB_PARAM_PORT => 65535},
        #{?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_PORT], ?DNS_SVCB_PARAM_PORT => 1},
        #{?DNS_SVCB_PARAM_IPV4HINT => [{255, 255, 255, 255}]},
        #{?DNS_SVCB_PARAM_IPV6HINT => [{65535, 0, 0, 0, 0, 0, 0, 65535}]},
        #{65535 => <<"x">>}
    ],
    DoNotFit = [
        #{?DNS_SVCB_PARAM_PORT => 65536},
        #{?DNS_SVCB_PARAM_PORT => -1},
        #{?DNS_SVCB_PARAM_MANDATORY => [65536]},
        #{?DNS_SVCB_PARAM_IPV4HINT => [{256, 0, 0, 0}]},
        #{?DNS_SVCB_PARAM_IPV4HINT => [{1, 2, 3, 4}, {1, 2, 3}]},
        #{?DNS_SVCB_PARAM_IPV6HINT => [{65536, 0, 0, 0, 0, 0, 0, 1}]},
        #{?DNS_SVCB_PARAM_IPV6HINT => [{1, 2, 3, 4}]},
        #{65536 => <<"x">>},
        #{?DNS_SVCB_PARAM_ECH => binary:copy(<<0>>, 65536)}
    ],
    [?assert(dns_check:rrdata(Svcb(P)), P) || P <- Fits],
    [?assertNot(dns_check:rrdata(Svcb(P)), P) || P <- DoNotFit].

%% RFC1035§2.3.4: a label is 63 octets or less and a name 255 or less on the wire.
%% A longer last label used to slip through, as dns_domain:to_wire/1 checks only
%% the labels before it, and was written with a length byte the wire reads as the
%% reserved extended label type.
rrdata_names_must_fit(_) ->
    Label = fun(Size) -> binary:copy(<<"a">>, Size) end,
    Ok = <<"example.", (Label(63))/binary>>,
    Names = [
        <<"example.", (Label(64))/binary>>,
        <<(Label(64))/binary, ".example">>,
        Label(64),
        iolist_to_binary(lists:join(".", [Label(63), Label(63), Label(63), Label(63)]))
    ],
    Records = fun(N) ->
        [
            #dns_rrdata_afsdb{subtype = 1, hostname = N},
            #dns_rrdata_amtrelay{
                precedence = 1, discovery_optional = false, relay_type = 3, relay = N
            },
            #dns_rrdata_cname{dname = N},
            #dns_rrdata_dname{dname = N},
            #dns_rrdata_hip{alg = 1, hit = <<1>>, public_key = <<1>>, rendezvous_servers = [N]},
            #dns_rrdata_hip{
                alg = 1, hit = <<1>>, public_key = <<1>>, rendezvous_servers = [<<"example">>, N]
            },
            #dns_rrdata_dsync{rrtype = 1, scheme = 1, port = 1, target = N},
            #dns_rrdata_ipseckey{precedence = 1, alg = 1, gateway = N, public_key = <<1>>},
            #dns_rrdata_kx{preference = 1, exchange = N},
            #dns_rrdata_lp{preference = 1, fqdn = N},
            #dns_rrdata_mb{madname = N},
            #dns_rrdata_mg{madname = N},
            #dns_rrdata_minfo{rmailbx = N, emailbx = <<"example">>},
            #dns_rrdata_minfo{rmailbx = <<"example">>, emailbx = N},
            #dns_rrdata_mr{newname = N},
            #dns_rrdata_mx{preference = 1, exchange = N},
            #dns_rrdata_naptr{
                order = 1,
                preference = 1,
                flags = <<>>,
                services = <<>>,
                regexp = <<>>,
                replacement = N
            },
            #dns_rrdata_ns{dname = N},
            #dns_rrdata_nsec{next_dname = N, types = []},
            #dns_rrdata_nxt{dname = N, types = []},
            #dns_rrdata_ptr{dname = N},
            #dns_rrdata_px{preference = 1, map822 = N, mapx400 = <<"example">>},
            #dns_rrdata_px{preference = 1, map822 = <<"example">>, mapx400 = N},
            #dns_rrdata_rp{mbox = N, txt = <<"example">>},
            #dns_rrdata_rp{mbox = <<"example">>, txt = N},
            #dns_rrdata_rrsig{
                type_covered = 1,
                alg = 13,
                labels = 1,
                original_ttl = 1,
                expiration = 1,
                inception = 1,
                keytag = 1,
                signers_name = N,
                signature = <<1>>
            },
            #dns_rrdata_rt{preference = 1, host = N},
            #dns_rrdata_sig{
                type_covered = 0,
                alg = 15,
                labels = 0,
                original_ttl = 0,
                expiration = 1,
                inception = 1,
                keytag = 1,
                signers_name = N,
                signature = <<1>>
            },
            #dns_rrdata_soa{
                mname = N,
                rname = <<"example">>,
                serial = 1,
                refresh = 1,
                retry = 1,
                expire = 1,
                minimum = 1
            },
            #dns_rrdata_soa{
                mname = <<"example">>,
                rname = N,
                serial = 1,
                refresh = 1,
                retry = 1,
                expire = 1,
                minimum = 1
            },
            #dns_rrdata_srv{priority = 1, weight = 1, port = 1, target = N},
            #dns_rrdata_svcb{svc_priority = 1, target_name = N, svc_params = #{}},
            #dns_rrdata_https{svc_priority = 1, target_name = N, svc_params = #{}},
            #dns_rrdata_tsig{
                alg = N, time = 1, fudge = 1, mac = <<1>>, msgid = 1, err = 0, other = <<>>
            }
        ]
    end,
    [?assert(dns_check:rrdata(D), D) || D <- Records(Ok)],
    [?assertNot(dns_check:rrdata(D), D) || N <- Names, D <- Records(N)].

%% RFC6742§2.1, §2.3: the NodeID and the Locator64 are 64 bits, no more, no less.
%% The encoder writes the binary as it is under an RDLENGTH of 10, so a value of
%% another size would leave the record's length wrong.
ilnp_64_bit_values_must_be_8_bytes(_) ->
    Records = fun(Value) ->
        [
            #dns_rrdata_nid{preference = 1, node_id = Value},
            #dns_rrdata_l64{preference = 1, locator64 = Value}
        ]
    end,
    [?assert(dns_check:rrdata(D), D) || D <- Records(<<1:64>>)],
    [?assertNot(dns_check:rrdata(D), D) || V <- [<<1:56>>, <<1:72>>, <<>>], D <- Records(V)].

%% RFC8777§4.2.3, §4.2.4: the relay type says what the relay holds, and the encoder
%% writes the relay by its type: a type 0 record carries no relay at all, so one
%% that holds a name would lose it, and only types 0 to 3 are defined.
amtrelay_relay_must_match_its_type(_) ->
    Amtrelay = fun(RelayType, Relay) ->
        #dns_rrdata_amtrelay{
            precedence = 1, discovery_optional = true, relay_type = RelayType, relay = Relay
        }
    end,
    V4 = {192, 0, 2, 1},
    V6 = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    Name = <<"relay.example">>,
    Fits = [Amtrelay(0, <<>>), Amtrelay(1, V4), Amtrelay(2, V6), Amtrelay(3, Name)],
    DoNotFit = [
        Amtrelay(0, Name),
        Amtrelay(0, V4),
        Amtrelay(1, V6),
        Amtrelay(1, Name),
        Amtrelay(2, V4),
        Amtrelay(2, Name),
        Amtrelay(3, V4),
        Amtrelay(3, V6),
        Amtrelay(4, <<>>),
        Amtrelay(-1, <<>>),
        (Amtrelay(0, <<>>))#dns_rrdata_amtrelay{discovery_optional = 1}
    ],
    [?assert(dns_check:rrdata(D), D) || D <- Fits],
    [?assertNot(dns_check:rrdata(D), D) || D <- DoNotFit].

%% RFC9886§5.1, §5.2: HHIT and BRID hold CBOR with mandatory fields, and the
%% decoder refuses RDATA of zero length for every type it knows, so an empty one
%% would go out and not come back.
drip_data_must_not_be_empty(_) ->
    [
        ?assert(dns_check:rrdata(D), D)
     || D <- [#dns_rrdata_hhit{data = <<0>>}, #dns_rrdata_brid{data = <<0>>}]
    ],
    [
        ?assertNot(dns_check:rrdata(D), D)
     || D <- [
            #dns_rrdata_hhit{data = <<>>},
            #dns_rrdata_brid{data = <<>>},
            #dns_rrdata_hhit{data = [<<0>>]},
            #dns_rrdata_brid{data = undefined}
        ]
    ].

%% RFC8005§5: the HIT and the public key are REQUIRED, and the HIT's length is
%% one octet, so a HIT of 256 bytes would go out with a length of 0
hip_hit_and_key_must_fit(_) ->
    Hip = fun(HIT, PublicKey, Servers) ->
        #dns_rrdata_hip{alg = 2, hit = HIT, public_key = PublicKey, rendezvous_servers = Servers}
    end,
    Fits = [
        Hip(<<1>>, <<1>>, []),
        Hip(binary:copy(<<1>>, 255), <<1>>, [<<"rvs.example">>]),
        Hip(<<1:128>>, binary:copy(<<1>>, 1000), [<<"rvs1.example">>, <<"rvs2.example">>])
    ],
    DoNotFit = [
        Hip(<<>>, <<1>>, []),
        Hip(binary:copy(<<1>>, 256), <<1>>, []),
        Hip(<<1>>, <<>>, []),
        Hip(<<1>>, <<1>>, <<"rvs.example">>),
        Hip(<<1>>, <<1>>, undefined),
        Hip(undefined, <<1>>, []),
        Hip(<<1>>, binary:copy(<<1>>, 65532), [])
    ],
    [?assert(dns_check:rrdata(D), D) || D <- Fits],
    [?assertNot(dns_check:rrdata(D), D) || D <- DoNotFit].

%% RFC2181§8: a TTL is 31 bits, since one with the top bit set is read as zero.
%% Type and class are 16 bits, and the owner name has to be one the wire can hold.
rr_header_must_fit(_) ->
    RR = #dns_rr{
        name = <<"example.com">>,
        type = ?DNS_TYPE_A,
        ttl = 1,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    Fits = [
        RR,
        RR#dns_rr{ttl = 16#7FFFFFFF},
        RR#dns_rr{ttl = 0},
        RR#dns_rr{type = 65535, data = <<1>>},
        RR#dns_rr{type = ?DNS_TYPE_TXT, class = 65535, data = #dns_rrdata_txt{txt = [<<"a">>]}}
    ],
    DoNotFit = [
        RR#dns_rr{ttl = 16#80000000},
        RR#dns_rr{ttl = -1},
        RR#dns_rr{ttl = undefined},
        RR#dns_rr{type = 65536, data = <<1>>},
        RR#dns_rr{class = 65536},
        RR#dns_rr{name = <<(binary:copy(<<"a">>, 64))/binary, ".example.com">>},
        RR#dns_rr{name = <<"example.", (binary:copy(<<"a">>, 64))/binary>>},
        RR#dns_rr{data = #dns_rrdata_a{ip = {256, 0, 0, 0}}}
    ],
    [?assert(dns_check:rr(R), R) || R <- Fits],
    [?assertNot(dns_check:rr(R), R) || R <- DoNotFit].

%% The encoder writes A, AAAA, EUI48 and EUI64 RDATA in class IN or NONE only, and
%% DHCID, OPENPGPKEY and WALLET in IN only, and fails any message carrying one in
%% another class. The RDATA is checked in the record's own class, so such a record
%% is refused when it is loaded.
rr_class_must_suit_rrdata(_) ->
    InOnly = [
        #dns_rrdata_a{ip = {192, 0, 2, 1}},
        #dns_rrdata_aaaa{ip = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}},
        #dns_rrdata_eui48{address = <<1:48>>},
        #dns_rrdata_eui64{address = <<1:64>>},
        #dns_rrdata_dhcid{data = <<1>>},
        #dns_rrdata_openpgpkey{data = <<1>>},
        #dns_rrdata_wallet{data = [<<"a">>]}
    ],
    RR = fun(Class, Data) ->
        #dns_rr{name = <<"example.com">>, type = 1, class = Class, ttl = 1, data = Data}
    end,
    [?assert(dns_check:rr(RR(?DNS_CLASS_IN, D)), D) || D <- InOnly],
    [
        ?assertNot(dns_check:rr(RR(Class, D)), {Class, D})
     || Class <- [?DNS_CLASS_CH, ?DNS_CLASS_HS], D <- InOnly
    ],
    %% Types the encoder writes in any class
    [
        ?assert(dns_check:rr(RR(Class, D)), {Class, D})
     || Class <- [?DNS_CLASS_CH, ?DNS_CLASS_HS],
        D <- [#dns_rrdata_txt{txt = [<<"a">>]}, #dns_rrdata_ns{dname = <<"ns.example.com">>}]
    ].

%% RFC1035§4.1.1: the ID and the four counts are 16 bits, and OPCODE and RCODE 4
header_must_fit(_) ->
    Msg = #dns_message{},
    Fits = [
        Msg,
        Msg#dns_message{id = 65535, oc = 15, rc = 15},
        Msg#dns_message{qc = 65535, anc = 65535, auc = 65535, adc = 65535},
        Msg#dns_message{qr = true, aa = true, tc = true, rd = true, ra = true, ad = true, cd = true}
    ],
    DoNotFit = [
        Msg#dns_message{id = 65536},
        Msg#dns_message{id = -1},
        Msg#dns_message{oc = 16},
        Msg#dns_message{rc = 16},
        Msg#dns_message{qc = 65536},
        Msg#dns_message{anc = 65536},
        Msg#dns_message{auc = -1},
        Msg#dns_message{adc = undefined},
        Msg#dns_message{qr = 1},
        Msg#dns_message{cd = undefined}
    ],
    [?assert(dns_check:header(M), M) || M <- Fits],
    [?assertNot(dns_check:header(M), M) || M <- DoNotFit].

query_must_fit(_) ->
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    ?assert(dns_check:query(Q#dns_query{type = 65535, class = 65535})),
    [
        ?assertNot(dns_check:query(Bad), Bad)
     || Bad <- [
            Q#dns_query{type = 65536},
            Q#dns_query{class = -1},
            Q#dns_query{name = binary:copy(<<"a">>, 64)}
        ]
    ].

%% RFC6891§6.1.2: the OPT pseudo-RR carries the UDP payload size in its CLASS
%% field and the extended RCODE and version in its TTL field
optrr_must_fit(_) ->
    OptRR = #dns_optrr{},
    Fits = [
        OptRR,
        OptRR#dns_optrr{udp_payload_size = 65535, ext_rcode = 255, version = 255},
        OptRR#dns_optrr{data = [#dns_opt_nsid{data = binary:copy(<<0>>, 65531)}]}
    ],
    DoNotFit = [
        OptRR#dns_optrr{udp_payload_size = 65536},
        OptRR#dns_optrr{ext_rcode = 256},
        OptRR#dns_optrr{version = -1},
        OptRR#dns_optrr{dnssec = 1},
        OptRR#dns_optrr{data = [#dns_opt_ul{lease = 1 bsl 32}]},
        %% Each option is 4 bytes of code and length before its data, and together
        %% they are the RDATA, which RDLENGTH limits to 65535 bytes
        OptRR#dns_optrr{data = [#dns_opt_nsid{data = binary:copy(<<0>>, 65532)}]},
        OptRR#dns_optrr{data = [#dns_opt_nsid{data = binary:copy(<<0>>, 40000)} || _ <- [1, 2]]}
    ],
    [?assert(dns_check:optrr(O), O) || O <- Fits],
    [?assertNot(dns_check:optrr(O), O) || O <- DoNotFit].

opts_must_fit(_) ->
    Mac = <<1, 2, 3, 4, 5, 6>>,
    Fits = [
        #dns_opt_llq{opcode = 65535, errorcode = 65535, id = (1 bsl 64) - 1, leaselife = 1 bsl 31},
        #dns_opt_ul{lease = (1 bsl 32) - 1},
        #dns_opt_nsid{data = <<"ns1">>},
        #dns_opt_owner{seq = 255, primary_mac = Mac, wakeup_mac = <<>>, password = <<>>},
        #dns_opt_owner{seq = 0, primary_mac = Mac, wakeup_mac = Mac, password = <<>>},
        #dns_opt_owner{seq = 0, primary_mac = Mac, wakeup_mac = Mac, password = <<1, 2, 3, 4>>},
        #dns_opt_owner{seq = 0, primary_mac = Mac, wakeup_mac = Mac, password = Mac},
        #dns_opt_ecs{
            family = 1, source_prefix_length = 255, scope_prefix_length = 255, address = <<1, 2, 3>>
        },
        #dns_opt_cookie{client = <<1:64>>},
        #dns_opt_cookie{client = <<1:64>>, server = <<1:256>>},
        #dns_opt_ede{info_code = 65535, extra_text = <<"text">>},
        #dns_opt_unknown{id = 65535, bin = <<1>>}
    ],
    DoNotFit = [
        #dns_opt_llq{opcode = 65536, errorcode = 0, id = 0, leaselife = 0},
        #dns_opt_llq{opcode = 0, errorcode = 0, id = 1 bsl 64, leaselife = 0},
        #dns_opt_ul{lease = -1},
        #dns_opt_owner{seq = 256, primary_mac = Mac, wakeup_mac = <<>>, password = <<>>},
        #dns_opt_owner{seq = 0, primary_mac = <<1>>, wakeup_mac = <<>>, password = <<>>},
        #dns_opt_owner{seq = 0, primary_mac = Mac, wakeup_mac = <<>>, password = Mac},
        #dns_opt_owner{seq = 0, primary_mac = Mac, wakeup_mac = Mac, password = <<1>>},
        #dns_opt_ecs{
            family = 65536, source_prefix_length = 0, scope_prefix_length = 0, address = <<>>
        },
        #dns_opt_ecs{
            family = 1, source_prefix_length = 256, scope_prefix_length = 0, address = <<>>
        },
        #dns_opt_cookie{client = <<1:56>>},
        #dns_opt_cookie{client = <<1:64>>, server = <<1:56>>},
        #dns_opt_cookie{client = <<1:64>>, server = <<1:264>>},
        #dns_opt_ede{info_code = 65536, extra_text = <<>>},
        #dns_opt_unknown{id = 65536, bin = <<>>},
        #dns_opt_nsid{data = binary:copy(<<0>>, 65536)}
    ],
    [?assert(dns_check:opt(O), O) || O <- Fits],
    [?assertNot(dns_check:opt(O), O) || O <- DoNotFit].
