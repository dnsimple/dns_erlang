-module(dns_tsig_SUITE).
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
            tsig_no_tsig,
            tsig_bad_key,
            tsig_bad_alg,
            tsig_bad_sig,
            tsig_badtime,
            tsig_ok,
            tsig_wire
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    Config.

tsig_no_tsig(_) ->
    MsgBin = dns:encode_message(#dns_message{}),
    Name = <<"name">>,
    Value = <<"value">>,
    ?assertException(error, no_tsig, dns:verify_tsig(MsgBin, Name, Value)).

tsig_bad_key(_) ->
    MsgId = dns:random_id(),
    B64 = <<"abcdefgh">>,
    TSIGData = #dns_rrdata_tsig{
        alg = ?DNS_TSIG_ALG_MD5,
        time = dns:unix_time(),
        fudge = 0,
        mac = B64,
        msgid = MsgId,
        err = 0,
        other = <<>>
    },
    TSIG = #dns_rr{
        name = <<"name_a">>,
        type = ?DNS_TYPE_TSIG,
        ttl = 0,
        data = TSIGData
    },
    Msg = #dns_message{id = MsgId, adc = 1, additional = [TSIG]},
    MsgBin = dns:encode_message(Msg),
    Result = dns:verify_tsig(MsgBin, <<"name_b">>, B64),
    ?assertEqual({error, ?DNS_TSIGERR_BADKEY}, Result).

tsig_bad_alg(_) ->
    Id = dns:random_id(),
    Name = <<"keyname">>,
    Data = #dns_rrdata_tsig{
        alg = <<"null">>,
        time = dns:unix_time(),
        fudge = 0,
        mac = <<"MAC">>,
        msgid = Id,
        err = 0,
        other = <<>>
    },
    RR = #dns_rr{name = Name, type = ?DNS_TYPE_TSIG, ttl = 0, data = Data},
    Msg = #dns_message{id = Id, adc = 1, additional = [RR]},
    MsgBin = dns:encode_message(Msg),
    Result = dns:verify_tsig(MsgBin, Name, <<"secret">>),
    ?assertEqual({error, ?DNS_TSIGERR_BADKEY}, Result).

tsig_bad_sig(_) ->
    Name = <<"keyname">>,
    Value = crypto:strong_rand_bytes(20),
    Msg = #dns_message{},
    SignedMsg = dns:add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Value, 0),
    [#dns_rr{data = TSIGData} = TSIG] = SignedMsg#dns_message.additional,
    BadTSIG = TSIG#dns_rr{data = TSIGData#dns_rrdata_tsig{mac = Value}},
    BadSignedMsg = Msg#dns_message{adc = 1, additional = [BadTSIG]},
    BadSignedMsgBin = dns:encode_message(BadSignedMsg),
    Result = dns:verify_tsig(BadSignedMsgBin, Name, Value),
    ?assertEqual({error, ?DNS_TSIGERR_BADSIG}, Result).

tsig_badtime(_) ->
    Name = <<"keyname">>,
    Secret = crypto:strong_rand_bytes(20),
    Msg = #dns_message{},
    Fudge = 30,
    SignedMsg = dns:add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Secret, 0),
    SignedMsgBin = dns:encode_message(SignedMsg),
    Now = dns:unix_time(),
    [
        begin
            BadNow = Now + (Throwoff * Fudge),
            Options = #{fudge => 30, time => BadNow},
            Result = dns:verify_tsig(SignedMsgBin, Name, Secret, Options),
            ?assertEqual({error, ?DNS_TSIGERR_BADTIME}, Result)
        end
     || Throwoff <- [-2, 2]
    ].

tsig_ok(_) ->
    Name = <<"keyname">>,
    Secret = crypto:strong_rand_bytes(20),
    Algs = [
        ?DNS_TSIG_ALG_MD5,
        ?DNS_TSIG_ALG_SHA1,
        ?DNS_TSIG_ALG_SHA224,
        ?DNS_TSIG_ALG_SHA256,
        ?DNS_TSIG_ALG_SHA384,
        ?DNS_TSIG_ALG_SHA512
    ],
    Msg = #dns_message{},
    Options = #{time => dns:unix_time(), fudge => 30},
    [
        begin
            SignedMsg = dns:add_tsig(Msg, Alg, Name, Secret, 0),
            SignedMsgBin = dns:encode_message(SignedMsg),
            Result =
                case dns:verify_tsig(SignedMsgBin, Name, Secret, Options) of
                    {ok, _MAC} -> ok;
                    Error -> Error
                end,
            ?assertEqual(ok, Result)
        end
     || Alg <- Algs
    ].

tsig_wire(_) ->
    Now = 1292459455,
    Keyname = <<"key.name">>,
    Secret = base64:decode(<<"8F1BRL+xp3gNW1GfbSnlUuvUtxQ=">>),
    Cases = data_samples:tsig(),
    [
        begin
            Result =
                case dns:verify_tsig(Msg, Keyname, Secret, #{time => Now}) of
                    {ok, MAC} when is_binary(MAC) -> ok;
                    X -> X
                end,
            ?assertEqual(ok, Result)
        end
     || {_, Msg} <- Cases
    ].
