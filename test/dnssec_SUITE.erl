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

zone(Config) ->
    Samples = proplists:get_value(dnssec_samples, Config),
    %% Run the validation for every sample in the config
    [validate_zone_sample(Config, Sample) || #dnssec_test_sample{alg = rsa} = Sample <- Samples].

generate_key_struct(Props, Alg, ZoneName) ->
    AlgNo = proplists:get_value(alg, Props),
    Flags = proplists:get_value(flags, Props),
    PubKey = helper_samplekeypl_to_pubkey(Props),
    PubKeyBin = helper_pubkey_to_dnskey_pubkey(Alg, PubKey),
    Data0 = #dns_rrdata_dnskey{
        flags = Flags,
        protocol = 3,
        alg = AlgNo,
        public_key = PubKeyBin
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
        RR#dns_rr{name = dnssec:normalise_dname(Name)}
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
