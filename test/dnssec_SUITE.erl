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

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            zone,
            gen_nsec,
            pubkey_gen,
            verify_rrset,
            sample_keys
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
    [
        begin
            RRClean = [RR || #dns_rr{type = Type} = RR <- RRSrc, Type =/= ?DNS_TYPE_NSEC],
            NSEC = lists:sort(
                lists:foldr(
                    fun(#dns_rr{data = Data} = RR, Acc) ->
                        Bin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
                        NewData = dns_decode:decode_rrdata(
                            Bin,
                            ?DNS_CLASS_IN,
                            ?DNS_TYPE_NSEC
                        ),
                        [RR#dns_rr{data = NewData} | Acc]
                    end,
                    [],
                    dnssec:gen_nsec(RRClean)
                )
            ),
            SrcNSEC = lists:sort(
                [RR || #dns_rr{type = ?DNS_TYPE_NSEC} = RR <- RRSrc]
            ),
            ?assertEqual(SrcNSEC, NSEC)
        end
     || #dnssec_test_sample{
            nsec3 = undefined,
            rr_src = RRSrc
        } <- proplists:get_value(dnssec_samples, Config)
    ].

verify_rrset(Config) ->
    [
        ?assert(dnssec:verify_rrsig(RRSig, RRSet, DNSKeys, Opts))
     || {_Name, RRSig, RRSet, DNSKeys, Opts} <- helper_verify_rrset_test_cases(Config)
    ].

zone(Config) ->
    [
        begin
            ZoneNameB = iolist_to_binary(ZoneName),
            %% Add DNS keys
            ZSKAlg = proplists:get_value(alg, ZSKPL),
            ZSKPrivKey = helper_samplekeypl_to_privkey(ZSKPL),
            ZSKPubKey = helper_samplekeypl_to_pubkey(ZSKPL),
            ZSKPubKeyBin = helper_pubkey_to_dnskey_pubkey(Alg, ZSKPubKey),
            ZSKAlgNo = proplists:get_value(alg, ZSKPL),
            ZSKFlags = proplists:get_value(flags, ZSKPL),
            ZSKKey0 = #dns_rrdata_dnskey{
                flags = ZSKFlags,
                protocol = 3,
                alg = ZSKAlgNo,
                public_key = ZSKPubKeyBin
            },
            ZSKKey = helper_add_keytag_to_dnskey(ZSKKey0),
            KSKAlg = proplists:get_value(alg, KSKPL),
            KSKPrivKey = helper_samplekeypl_to_privkey(KSKPL),
            KSKPubKey = helper_samplekeypl_to_pubkey(KSKPL),
            KSKPubKeyBin = helper_pubkey_to_dnskey_pubkey(Alg, KSKPubKey),
            KSKAlgNo = proplists:get_value(alg, KSKPL),
            KSKFlags = proplists:get_value(flags, KSKPL),
            KSKKey0 = #dns_rrdata_dnskey{
                flags = KSKFlags,
                protocol = 3,
                alg = KSKAlgNo,
                public_key = KSKPubKeyBin
            },
            KSKKey = helper_add_keytag_to_dnskey(KSKKey0),
            DNSKeyTmpl = #dns_rr{
                name = iolist_to_binary(ZoneName),
                type = ?DNS_TYPE_DNSKEY,
                class = ?DNS_CLASS_IN,
                ttl = 3600
            },
            RRDNSKey = [
                DNSKeyTmpl#dns_rr{data = KSKKey},
                DNSKeyTmpl#dns_rr{data = ZSKKey}
                | RRClean
            ],
            %% Add NSEC / NSEC3
            RRNSEC =
                case NSEC3 of
                    undefined ->
                        dnssec:gen_nsec(RRDNSKey) ++ RRDNSKey;
                    #dns_rrdata_nsec3param{} = Param ->
                        RRNSEC3 = [
                            #dns_rr{
                                name = ZoneNameB,
                                type = ?DNS_TYPE_NSEC3PARAM,
                                ttl = 0,
                                data = Param
                            }
                            | RRDNSKey
                        ],
                        dnssec:gen_nsec3(RRNSEC3) ++ RRNSEC3
                end,
            RRDECENC = lists:map(
                fun(
                    #dns_rr{
                        class = Class,
                        type = Type,
                        data = Data
                    } = RR
                ) ->
                    Bin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
                    NewData = dns_decode:decode_rrdata(Bin, Class, Type),
                    RR#dns_rr{data = NewData}
                end,
                RRNSEC
            ),
            %% Add RRSIG
            Opts = #{inception => I, expiration => E},
            RRSigsZSK = dnssec:sign_rr(
                RRDECENC,
                ZoneNameB,
                ZSKKey#dns_rrdata_dnskey.keytag,
                ZSKAlg,
                ZSKPrivKey,
                Opts
            ),
            RRDNSKeys = [
                RR
             || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRDECENC
            ],
            RRSigsKSK = dnssec:sign_rr(
                RRDNSKeys,
                ZoneNameB,
                KSKKey#dns_rrdata_dnskey.keytag,
                KSKAlg,
                KSKPrivKey,
                Opts
            ),
            RRFinal = RRSigsKSK ++ RRSigsZSK ++ RRDECENC,
            GeneratedRR = lists:sort(
                [
                    RR#dns_rr{name = dnssec:normalise_dname(Name)}
                 || #dns_rr{name = Name} = RR <- RRFinal
                ]
            ),
            SampleRR = lists:sort(
                [
                    RR#dns_rr{name = dnssec:normalise_dname(Name)}
                 || #dns_rr{name = Name} = RR <- RRSrc
                ]
            ),
            ?assertEqual(GeneratedRR, SampleRR)
        end
     || #dnssec_test_sample{
            zonename = ZoneName,
            alg = rsa = Alg,
            inception = I,
            expiration = E,
            nsec3 = NSEC3,
            zsk_pl = ZSKPL,
            ksk_pl = KSKPL,
            rr_clean = RRClean,
            rr_src = RRSrc
        } <- proplists:get_value(dnssec_samples, Config)
    ].

pubkey_gen(Config) ->
    [
        begin
            DnsKeyRR = lists:sort(
                [
                    RR
                 || #dns_rr{type = ?DNS_TYPE_DNSKEY} = RR <- RRs
                ]
            ),
            Generated = lists:sort(
                lists:map(
                    fun(PL) ->
                        PubKey = helper_samplekeypl_to_pubkey(PL),
                        AlgNo = proplists:get_value(alg, PL),
                        Flags = proplists:get_value(flags, PL),
                        Key = #dns_rrdata_dnskey{
                            flags = Flags,
                            protocol = 3,
                            alg = AlgNo,
                            public_key = PubKey
                        },
                        helper_add_keytag_to_dnskey(Key)
                    end,
                    [ZSK_PL, KSK_PL]
                )
            ),
            Expect = lists:sort([
                (RR#dns_rr.data)#dns_rrdata_dnskey{}
             || RR <- DnsKeyRR
            ]),
            ?assertEqual(Expect, Generated)
        end
     || #dnssec_test_sample{
            rr_src = RRs,
            ksk_pl = KSK_PL,
            zsk_pl = ZSK_PL
        } <- proplists:get_value(dnssec_samples, Config)
    ].

sample_keys(Config) ->
    Keys = lists:foldl(
        fun(
            #dnssec_test_sample{
                alg = Alg,
                zsk_pl = A,
                ksk_pl = B
            },
            Acc
        ) ->
            [{Alg, A}, {Alg, B} | Acc]
        end,
        [],
        proplists:get_value(dnssec_samples, Config)
    ),
    [?assert(test_sample_key(Alg, Proplist)) || {Alg, Proplist} <- Keys].

test_sample_key(Alg, Proplist) ->
    PrivKey = helper_samplekeypl_to_privkey(Proplist),
    PubKey = helper_samplekeypl_to_pubkey(Proplist),
    test_sample_key(Alg, PrivKey, PubKey).

test_sample_key(dsa, PrivKey, PubKey) ->
    Sample = <<"1234">>,
    Sig = crypto:sign(dss, sha, Sample, PrivKey),
    crypto:verify(dss, sha, Sample, Sig, PubKey);
test_sample_key(rsa, PrivKey, PubKey) ->
    Sample = <<"1234">>,
    Cipher = crypto:sign(rsa, none, Sample, PrivKey, [{rsa_padding, rsa_pkcs1_padding}]),
    true =:= crypto:verify(rsa, none, Sample, Cipher, PubKey, [{rsa_padding, rsa_pkcs1_padding}]);
test_sample_key(ecdsap256, PrivKey, PubKey) ->
    Sample = crypto:hash(sha256, <<"1234">>),
    Cipher = crypto:sign(ecdsa, sha256, Sample, [PrivKey, secp256r1]),
    true =:= crypto:verify(ecdsa, sha256, Sample, Cipher, [<<4, PubKey/binary>>, secp256r1]);
test_sample_key(ecdsap384, PrivKey, PubKey) ->
    Sample = crypto:hash(sha384, <<"1234">>),
    Cipher = crypto:sign(ecdsa, sha384, Sample, [PrivKey, secp384r1]),
    true =:= crypto:verify(ecdsa, sha384, Sample, Cipher, [<<4, PubKey/binary>>, secp384r1]).

helper_test_samples(Terms) ->
    lists:map(
        fun({ZoneName, KeysRaw, AxfrBin}) ->
            [ZSK, KSK] = lists:foldl(fun extract_zsk_and_ksk/2, [], KeysRaw),
            #dns_message{answers = RR} = dns:decode_message(AxfrBin),
            [{I, E} | _] = extract_rrsig_inception_expiration(RR),
            NSEC3 = extract_nsec3_param(RR),
            Alg = extract_alg_from_name(ZoneName),
            #dnssec_test_sample{
                zonename = ZoneName,
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
                Dict = lists:foldl(
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
                            Dict
                        ) ->
                            Key = {dns:dname_to_lower(Name), Class, Type},
                            dict:append(Key, RR, Dict);
                        (
                            #dns_rr{
                                name = Name,
                                class = Class,
                                type = Type
                            } = RR,
                            Dict
                        ) ->
                            Key = {dns:dname_to_lower(Name), Class, Type},
                            dict:append(Key, RR, Dict)
                    end,
                    dict:new(),
                    RRs
                ),
                RRSets = [RRSet || {_, RRSet} <- dict:to_list(Dict)],
                lists:map(
                    fun([#dns_rr{name = Name} | _] = TestRR) ->
                        {RRSigs, RRSet} = lists:partition(
                            fun(#dns_rr{type = Type}) ->
                                Type =:= rrsig
                            end,
                            TestRR
                        ),
                        [#dns_rr{type = Type} | _] = RRSet,
                        TestName = helper_fmt("~s/~p", [Name, Type]),
                        [
                            {TestName, RRSig, RRSet, DNSKeys, Opts}
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
    P = proplists:get_value(p, Proplist),
    Q = proplists:get_value(q, Proplist),
    G = proplists:get_value(g, Proplist),
    Y = proplists:get_value(y, Proplist),
    [I || <<L:32, I:L/unit:8>> <- [P, Q, G, Y]];
helper_samplekeypl_to_pubkey(?DNS_ALG_ECDSAP256SHA256, Proplist) ->
    proplists:get_value(public_key, Proplist);
helper_samplekeypl_to_pubkey(?DNS_ALG_ECDSAP384SHA384, Proplist) ->
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
helper_pubkey_to_dnskey_pubkey(dsa, Key) ->
    {M, [P, Q, G, Y]} = lists:foldr(
        fun(<<L:32, I:L/unit:8>>, {MaxL, Ints}) ->
            NewMaxL =
                case L > MaxL of
                    true -> L;
                    false -> MaxL
                end,
            {NewMaxL, [I | Ints]}
        end,
        {0, []},
        Key
    ),
    T = (M - 64) div 8,
    M = 64 + T * 8,
    <<T, Q:20/unit:8, P:M/unit:8, G:M/unit:8, Y:M/unit:8>>.

helper_add_keytag_to_dnskey(#dns_rrdata_dnskey{} = DNSKey) ->
    RR = #dns_rr{type = ?DNS_TYPE_DNSKEY, data = DNSKey},
    (dnssec:add_keytag_to_dnskey(RR))#dns_rr.data.

helper_fmt(Fmt, Args) ->
    iolist_to_binary(io_lib:format(Fmt, Args)).
