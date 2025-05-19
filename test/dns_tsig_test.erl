-module(dns_tsig_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("dns_erlang/include/dns.hrl").

tsig_no_tsig_test() ->
    MsgBin = dns:encode_message(#dns_message{}),
    Name = <<"name">>,
    Value = <<"value">>,
    ?assertException(throw, no_tsig, dns:verify_tsig(MsgBin, Name, Value)).

tsig_bad_key_test() ->
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

tsig_bad_alg_test() ->
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

tsig_bad_sig_test() ->
    application:start(crypto),
    MsgId = dns:random_id(),
    Name = <<"keyname">>,
    Value = crypto:strong_rand_bytes(20),
    Msg = #dns_message{id = MsgId},
    SignedMsg = dns:add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Value, 0),
    [#dns_rr{data = TSIGData} = TSIG] = SignedMsg#dns_message.additional,
    BadTSIG = TSIG#dns_rr{data = TSIGData#dns_rrdata_tsig{mac = Value}},
    BadSignedMsg = Msg#dns_message{adc = 1, additional = [BadTSIG]},
    BadSignedMsgBin = dns:encode_message(BadSignedMsg),
    Result = dns:verify_tsig(BadSignedMsgBin, Name, Value),
    ?assertEqual({error, ?DNS_TSIGERR_BADSIG}, Result).

tsig_badtime_test_() ->
    application:start(crypto),
    MsgId = dns:random_id(),
    Name = <<"keyname">>,
    Secret = crypto:strong_rand_bytes(20),
    Msg = #dns_message{id = MsgId},
    Fudge = 30,
    SignedMsg = dns:add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Secret, 0),
    SignedMsgBin = dns:encode_message(SignedMsg),
    Now = dns:unix_time(),
    [
        ?_test(
            begin
                BadNow = Now + (Throwoff * Fudge),
                Options = #{fudge => 30, time => BadNow},
                Result = dns:verify_tsig(SignedMsgBin, Name, Secret, Options),
                ?assertEqual({error, ?DNS_TSIGERR_BADTIME}, Result)
            end
        )
     || Throwoff <- [-2, 2]
    ].

tsig_ok_test_() ->
    application:start(crypto),
    MsgId = dns:random_id(),
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
    Msg = #dns_message{id = MsgId},
    Options = #{time => dns:unix_time(), fudge => 30},
    [
        {Alg,
            ?_test(
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
            )}
     || Alg <- Algs
    ].

tsig_wire_test_() ->
    application:start(crypto),
    Now = 1292459455,
    Keyname = <<"key.name">>,
    Secret = base64:decode(<<"8F1BRL+xp3gNW1GfbSnlUuvUtxQ=">>),
    {ok, Cases} = file:consult(filename:join("test", "tsig_wire_samples.txt")),
    [
        {Alg,
            ?_test(
                begin
                    Result =
                        case dns:verify_tsig(Msg, Keyname, Secret, #{time => Now}) of
                            {ok, MAC} when is_binary(MAC) -> ok;
                            X -> X
                        end,
                    ?assertEqual(ok, Result)
                end
            )}
     || {Alg, Msg} <- Cases
    ].
