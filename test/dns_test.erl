-module(dns_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("dns_erlang/include/dns.hrl").

message_empty_test() ->
    Msg = #dns_message{},
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

message_query_test() ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

encode_message_max_size_test_() ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Msg3 = Msg#dns_message{adc = 1, additional = [#dns_optrr{udp_payload_size = 512}]},
    [
        ?_assert(begin
            {false, Bin} = dns:encode_message(Msg3, #{}),
            Msg3 =:= dns:decode_message(Bin)
        end),
        ?_assert(begin
            {false, Bin} = dns:encode_message(Msg, #{max_size => 512}),
            Msg =:= dns:decode_message(Bin)
        end),
        ?_assert(begin
            {false, Bin} = dns:encode_message(Msg, #{}),
            Msg =:= dns:decode_message(Bin)
        end)
    ].

encode_message_invalid_size_test_() ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Msg3 = Msg#dns_message{adc = 1, additional = [#dns_optrr{udp_payload_size = 99999999}]},
    [
        ?_assertError(badarg, dns:encode_message(Msg3, #{})),
        ?_assertError(badarg, dns:encode_message(Msg, #{max_size => 999999})),
        ?_assertError(badarg, dns:encode_message(Msg, #{max_size => 413})),
        ?_assertError(badarg, dns:encode_message(Msg, #{max_size => not_an_integer}))
    ].

truncated_query_enforces_opt_record_test_() ->
    QName = <<"txt.example.org">>,
    StringSplit = split_binary_into_chunks(list_to_binary(lists:duplicate(480, $a)), 255),
    TxtRecord = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_TXT,
        ttl = 0,
        data = #dns_rrdata_txt{txt = StringSplit}
    },
    TxtRecordSmall = TxtRecord#dns_rr{data = #dns_rrdata_txt{txt = [<<"hello world">>]}},
    Question = #dns_query{name = QName, type = ?DNS_TYPE_TXT},
    OptRR = #dns_optrr{udp_payload_size = 512},
    Msg0 = #dns_message{
        qc = 1,
        anc = 1,
        questions = [Question],
        answers = [TxtRecord]
    },
    [
        %% Answers are truncated but body and optrr are present in full
        ?_assert(begin
            NSID = #dns_opt_nsid{data = binary:encode_hex(crypto:strong_rand_bytes(8))},
            Ads = [OptRR#dns_optrr{data = [NSID]}],
            Msg = Msg0#dns_message{additional = Ads},
            {false, Encoded} = dns:encode_message(Msg, #{max_size => 512}),
            Decoded = dns:decode_message(Encoded),
            byte_size(Encoded) =< 512 andalso Decoded#dns_message.tc andalso
                ok =:= ?assertMatch([], Decoded#dns_message.answers) andalso
                ok =:= ?assertMatch([Question], Decoded#dns_message.questions) andalso
                ok =:= ?assertMatch([#dns_optrr{data = [_]} | _], Decoded#dns_message.additional)
        end),
        %% Small answers are too truncated
        ?_assert(begin
            NSID = #dns_opt_nsid{data = binary:encode_hex(crypto:strong_rand_bytes(8))},
            Ads = [OptRR#dns_optrr{data = [NSID]}],
            Msg = Msg0#dns_message{
                anc = 2, answers = [TxtRecordSmall, TxtRecord], additional = Ads
            },
            {false, Encoded} = dns:encode_message(Msg, #{max_size => 512}),
            Decoded = dns:decode_message(Encoded),
            byte_size(Encoded) =< 512 andalso Decoded#dns_message.tc andalso
                ok =:= ?assertMatch([], Decoded#dns_message.answers) andalso
                ok =:= ?assertMatch([Question], Decoded#dns_message.questions) andalso
                ok =:= ?assertMatch([#dns_optrr{data = [_]} | _], Decoded#dns_message.additional)
        end),
        %% A too large NSID is dropped, prioritising questions and a bare OptRR record
        ?_assert(begin
            NSID = #dns_opt_nsid{data = binary:encode_hex(crypto:strong_rand_bytes(234))},
            Msg = Msg0#dns_message{additional = [OptRR#dns_optrr{data = [NSID]}]},
            {false, Encoded} = dns:encode_message(Msg, #{max_size => 512}),
            Decoded = dns:decode_message(Encoded),
            byte_size(Encoded) =< 512 andalso Decoded#dns_message.tc andalso
                ok =:= ?assertMatch([], Decoded#dns_message.answers) andalso
                ok =:= ?assertMatch([Question], Decoded#dns_message.questions) andalso
                ok =:= ?assertMatch([#dns_optrr{data = []} | _], Decoded#dns_message.additional)
        end)
    ].

message_other_test() ->
    QName = <<"i            .txt.example.org">>,
    Qs = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
    As = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_TXT,
            ttl = 0,
            data = #dns_rrdata_txt{txt = [QName]}
        }
    ],
    QLen = length(Qs),
    ALen = length(As),
    Msg = #dns_message{qc = QLen, anc = ALen, questions = Qs, answers = As},
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

long_txt_test() ->
    QName = <<"txt.example.org">>,

    % Create a string longer than 255 bytes
    LongString = list_to_binary(lists:duplicate(300, $a)),
    ?assert(byte_size(LongString) > 255),

    % Create a TXT record with the long string TXT record expects a list of strings,
    % each of which must be ≤ 255 bytes in length
    LongStringSplit = split_binary_into_chunks(LongString, 255),

    % Create a DNS message
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
        answers = [
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_TXT,
                ttl = 0,
                data = #dns_rrdata_txt{txt = LongStringSplit}
            }
        ]
    },

    % Encode and decode_message
    Bin = dns:encode_message(Msg),
    DecodedMsg = dns:decode_message(Bin),

    % Get the TXT record from the decoded message
    [#dns_rr{data = #dns_rrdata_txt{txt = DecodedTxt}}] = DecodedMsg#dns_message.answers,

    %% Test that the string was split in exactly two segments of the given sizes
    ?assertEqual([255, 45], [byte_size(L) || L <- DecodedTxt]),

    % If encoding works correctly for long strings,
    % the decoded string joined together should match the original
    ReassembledString = iolist_to_binary(DecodedTxt),
    ?assertEqual(LongString, ReassembledString).

long_txt_not_split_test() ->
    QName = <<"txt.example.org">>,
    % Create a string longer than 255 bytes
    LongStringOfA = list_to_binary(lists:duplicate(300, $a)),
    LongStringOfB = list_to_binary(lists:duplicate(300, $b)),
    % Create a DNS message
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
        answers = [
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_TXT,
                ttl = 0,
                data = #dns_rrdata_txt{txt = [LongStringOfA, LongStringOfB]}
            }
        ]
    },
    % Encode and decode_message
    Bin = dns:encode_message(Msg),
    DecodedMsg = dns:decode_message(Bin),
    % Get the TXT record from the decoded message
    [#dns_rr{data = #dns_rrdata_txt{txt = DecodedTxt}}] = DecodedMsg#dns_message.answers,
    % Assert that all segments in the array are below the 255 byte limit
    ?assert(lists:all(fun(B) -> byte_size(B) =< 255 end, DecodedTxt)),
    % If encoding works correctly for long strings,
    % the decoded string joined together should match the original
    LongString = iolist_to_binary([LongStringOfA, LongStringOfB]),
    ReassembledString = iolist_to_binary(DecodedTxt),
    ?assertEqual(LongString, ReassembledString).

fail_txt_not_list_of_strings_test() ->
    QName = <<"txt.example.org">>,
    % Create a string longer than 255 bytes
    LongString = list_to_binary(lists:duplicate(300, $a)),
    ?assert(byte_size(LongString) > 255),
    % Create a DNS message
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
        answers = [
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_TXT,
                ttl = 0,
                data = #dns_rrdata_txt{txt = LongString}
            }
        ]
    },
    ?assertError(function_clause, dns:encode_message(Msg)).

truncated_txt_test() ->
    QName = <<"txt.example.org">>,
    % Create a string longer than 255 bytes
    LongString = list_to_binary(lists:duplicate(300, $a)),
    LongStringSplit = split_binary_into_chunks(LongString, 255),
    % Create a DNS message
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
        answers = [
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_TXT,
                ttl = 0,
                data = #dns_rrdata_txt{txt = LongStringSplit}
            }
        ]
    },
    Bin = dns:encode_message(Msg),
    Head = binary:part(Bin, 0, 45),
    OneLorem = iolist_to_binary(LongString),
    NewBin = <<Head/binary, 255, OneLorem/binary>>,
    ?assertMatch({truncated, _, _}, dns:decode_message(NewBin)).

trailing_garbage_txt_test() ->
    QName = <<"txt.example.org">>,
    Text = <<"\"Hello\"">>,
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
        answers = [
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_TXT,
                ttl = 0,
                data = #dns_rrdata_txt{txt = [Text]}
            }
        ]
    },
    Bin = dns:encode_message(Msg),
    NewBin = <<Bin/binary, "_">>,
    ?assertMatch({trailing_garbage, _, _}, dns:decode_message(NewBin)).

message_edns_test() ->
    QName = <<"_http._tcp.example.org">>,
    Qs = [#dns_query{name = QName, type = ?DNS_TYPE_PTR}],
    Ans = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_PTR,
            ttl = 42,
            data = #dns_rrdata_ptr{
                dname = <<"Example\ Site._http._tcp.example.org">>
            }
        }
    ],
    LLQ = #dns_opt_llq{
        opcode = ?DNS_LLQOPCODE_SETUP,
        errorcode = ?DNS_LLQERRCODE_NOERROR,
        id = 42,
        leaselife = 7200
    },
    ECS = #dns_opt_ecs{
        family = 1,
        source_prefix_length = 24,
        scope_prefix_length = 0,
        address = <<1, 1, 1>>
    },
    Ads = [
        #dns_optrr{
            udp_payload_size = 4096,
            ext_rcode = 0,
            version = 0,
            dnssec = false,
            data = [LLQ, ECS]
        }
    ],
    Msg = #dns_message{
        qc = length(Qs),
        anc = length(Ans),
        adc = length(Ads),
        questions = Qs,
        answers = Ans,
        additional = Ads
    },
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

missing_additional_section_test() ->
    %% Query for test./IN/A with missing additional section
    Bin = <<192, 46, 0, 32, 0, 1, 0, 0, 0, 0, 0, 1, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1>>,
    ?assertMatch({truncated, _, <<>>}, dns:decode_message(Bin)).

edns_badvers_test() ->
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    BadVersion = #dns_optrr{
        udp_payload_size = 4096,
        version = 42
    },
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [BadVersion]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertMatch([#dns_optrr{ext_rcode = 1, version = 0} | _], Decoded#dns_message.additional).

%%%===================================================================
%%% Record data functions
%%%===================================================================

decode_encode_rrdata_wire_samples_test_() ->
    {ok, Cases} = file:consult(filename:join("test", "rrdata_wire_samples.txt")),
    ToTestName = fun({Class, Type, Bin}) ->
        Fmt = "~p/~p/~n~p",
        Args = [Class, Type, Bin],
        lists:flatten(io_lib:format(Fmt, Args))
    end,
    [
        {
            ToTestName(Case),
            ?_test(
                begin
                    NewBin =
                        case dns_decode:decode_rrdata(TestBin, Class, Type, TestBin) of
                            TestBin when Type =:= 999 -> TestBin;
                            TestBin ->
                                throw(not_decoded);
                            Record ->
                                {Bin, _} = dns_encode:encode_rrdata(
                                    0,
                                    Class,
                                    Record,
                                    #{}
                                ),
                                Bin
                        end,
                    ?assertEqual(TestBin, NewBin)
                end
            )
        }
     || {Class, Type, TestBin} = Case <- Cases
    ].

decode_encode_rrdata_test_() ->
    %% For testing records that don't have wire samples
    Cases = [
        {?DNS_TYPE_MB, #dns_rrdata_mb{madname = <<"example.com">>}},
        {?DNS_TYPE_MG, #dns_rrdata_mg{madname = <<"example.com">>}},
        {?DNS_TYPE_MINFO, #dns_rrdata_minfo{
            rmailbx = <<"a.b">>,
            emailbx = <<"c.d">>
        }},
        {?DNS_TYPE_MR, #dns_rrdata_mr{newname = <<"example.com">>}},
        {?DNS_TYPE_CAA, #dns_rrdata_caa{
            flags = 0, tag = <<"issue">>, value = <<"letsencrypt.org">>
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0, target_name = <<"target.example.com">>, svc_params = #{}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_PORT_NUMBER => 8080}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_ALPN => <<"h2,h3">>}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_ECHCONFIG => <<"123abc">>}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_IPV4HINT => <<"1.2.3.4,1.2.3.5">>}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{
                ?DNS_SVCB_PARAM_IPV6HINT =>
                    <<"2001:0db8:85a3:0000:0000:8a2e:0370:7334,2001:0db8:85a3:0000:0000:8a2e:0370:7335">>
            }
        }}
    ],
    [
        ?_test(
            begin
                {Encoded, _NewCompMap} = dns_encode:encode_rrdata(
                    0,
                    ?DNS_CLASS_IN,
                    Data,
                    #{}
                ),
                Decoded = dns_decode:decode_rrdata(Encoded, ?DNS_CLASS_IN, Type, Encoded),
                ?assertEqual(Data, Decoded)
            end
        )
     || {Type, Data} <- Cases
    ].

%%%===================================================================
%%% EDNS data functions
%%%===================================================================

decode_encode_optdata_test_() ->
    Cases = [
        #dns_opt_llq{
            opcode = ?DNS_LLQOPCODE_SETUP,
            errorcode = ?DNS_LLQERRCODE_NOERROR,
            id = 123,
            leaselife = 456
        },
        #dns_opt_ul{lease = 789},
        #dns_opt_nsid{data = <<"hi">>},
        #dns_opt_ecs{
            family = 1,
            source_prefix_length = 24,
            scope_prefix_length = 0,
            address = <<1, 1, 1>>
        },
        #dns_opt_unknown{id = 999, bin = <<"hi">>}
    ],
    [
        ?_assertEqual([Case], dns_decode:decode_optrrdata(dns_encode:encode_optrrdata([Case])))
     || Case <- Cases
    ].

decode_encode_optdata_owner_test_() ->
    application:start(crypto),
    Cases = [
        #dns_opt_owner{
            seq = rand:uniform(255),
            primary_mac = crypto:strong_rand_bytes(6),
            wakeup_mac = crypto:strong_rand_bytes(6),
            password = crypto:strong_rand_bytes(6)
        },
        #dns_opt_owner{
            seq = rand:uniform(255),
            primary_mac = crypto:strong_rand_bytes(6),
            wakeup_mac = crypto:strong_rand_bytes(6),
            password = crypto:strong_rand_bytes(4)
        },
        #dns_opt_owner{
            seq = rand:uniform(255),
            primary_mac = crypto:strong_rand_bytes(6),
            wakeup_mac = crypto:strong_rand_bytes(6),
            _ = <<>>
        },
        #dns_opt_owner{
            seq = rand:uniform(255),
            primary_mac = crypto:strong_rand_bytes(6),
            _ = <<>>
        }
    ],
    [
        ?_assertEqual([Case], dns_decode:decode_optrrdata(dns_encode:encode_optrrdata([Case])))
     || Case <- Cases
    ].

decode_encode_svcb_params_test() ->
    Cases = [
        {#{}, #{}},
        {#{?DNS_SVCB_PARAM_PORT => 8079}, #{?DNS_SVCB_PARAM_PORT => 8079}},
        {#{port => 8080}, #{?DNS_SVCB_PARAM_PORT => 8080}}
    ],

    [
        ?assertEqual(
            Expected, dns_decode:decode_svcb_svc_params(dns_encode:encode_svcb_svc_params(Input))
        )
     || {Input, Expected} <- Cases
    ].

%%%===================================================================
%%% Domain name functions
%%%===================================================================

decode_dname_2_ptr_test_() ->
    Cases = [{<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, <<3:2, 0:14>>}],
    [
        ?_assertEqual({<<"example">>, <<>>}, dns_decode:decode_dname(DataBin, MsgBin))
     || {MsgBin, DataBin} <- Cases
    ].

decode_dname_decode_loop_test() ->
    Bin = <<3:2, 0:14>>,
    ?assertException(throw, decode_loop, dns_decode:decode_dname(Bin, Bin)).

decode_dname_bad_pointer_test() ->
    Case = <<3:2, 42:14>>,
    ?assertException(throw, bad_pointer, dns_decode:decode_dname(Case, Case)).

encode_dname_1_test_() ->
    Cases = [
        {<<"example">>, <<7, 101, 120, 97, 109, 112, 108, 101, 0>>}
    ],
    [?_assertEqual(Expect, dns_encode:encode_dname(Input)) || {Input, Expect} <- Cases].

encode_dname_3_test_() ->
    {Bin, _CompMap} = dns_encode:encode_dname(#{}, 0, <<"example">>),
    ?_assertEqual(<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, Bin).

encode_dname_4_test_() ->
    {Bin0, CM0} = dns_encode:encode_dname(<<>>, #{}, 0, <<"example">>),
    {Bin1, _} = dns_encode:encode_dname(Bin0, CM0, byte_size(Bin0), <<"example">>),
    {Bin2, _} = dns_encode:encode_dname(Bin0, CM0, byte_size(Bin0), <<"EXAMPLE">>),
    MP = (1 bsl 14),
    MPB = <<0:MP/unit:8>>,
    {_, CM1} = dns_encode:encode_dname(MPB, #{}, MP, <<"example">>),
    Cases = [
        {<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, Bin0},
        {<<7, 101, 120, 97, 109, 112, 108, 101, 0, 192, 0>>, Bin1},
        {Bin1, Bin2},
        {#{}, CM1}
    ],
    [?_assertEqual(Expect, Result) || {Expect, Result} <- Cases].

dname_to_lower_labels_test_() ->
    Cases = [
        {<<>>, []},
        {<<".">>, []},
        {<<"A.B.C">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"A.B.C.">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"A\\.B.c">>, [<<"a.b">>, <<"c">>]},
        {<<"A\\\\.b.C">>, [<<"a\\">>, <<"b">>, <<"c">>]}
    ],
    [?_assertEqual(Expect, dns:dname_to_lower_labels(Arg)) || {Arg, Expect} <- Cases].

dname_to_labels_test_() ->
    Cases = [
        {<<>>, []},
        {<<".">>, []},
        {<<"a.b.c">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"a.b.c.">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"a\\.b.c">>, [<<"a.b">>, <<"c">>]},
        {<<"a\\\\.b.c">>, [<<"a\\">>, <<"b">>, <<"c">>]}
    ],
    [?_assertEqual(Expect, dns:dname_to_labels(Arg)) || {Arg, Expect} <- Cases].

labels_to_dname_test_() ->
    Cases = [
        {[<<"a">>, <<"b">>, <<"c">>], <<"a.b.c">>},
        {[<<"a.b">>, <<"c">>], <<"a\\.b.c">>},
        {[<<"a\\">>, <<"b">>, <<"c">>], <<"a\\\\.b.c">>}
    ],
    [?_assertEqual(Expect, dns:labels_to_dname(Arg)) || {Arg, Expect} <- Cases].

dname_to_upper_test_() ->
    Cases = [{<<"Y">>, <<"Y">>}, {<<"y">>, <<"Y">>}],
    [?_assertEqual(Expect, dns:dname_to_upper(Arg)) || {Arg, Expect} <- Cases].

dname_to_lower_test_() ->
    Cases = [{<<"Y">>, <<"y">>}, {<<"y">>, <<"y">>}],
    [?_assertEqual(Expect, dns:dname_to_lower(Arg)) || {Arg, Expect} <- Cases].

dname_case_conversion_test_() ->
    [
        %% Basic domain name tests
        ?_assertEqual(<<"EXAMPLE.COM">>, dns:dname_to_upper(<<"example.com">>)),
        ?_assertEqual(<<"example.com">>, dns:dname_to_lower(<<"EXAMPLE.COM">>)),

        %% Mixed case input tests
        ?_assertEqual(<<"EXAMPLE.COM">>, dns:dname_to_upper(<<"ExAmPle.CoM">>)),
        ?_assertEqual(<<"example.com">>, dns:dname_to_lower(<<"ExAmPle.CoM">>)),

        %% Tests with subdomains
        ?_assertEqual(<<"WWW.EXAMPLE.COM">>, dns:dname_to_upper(<<"www.example.com">>)),
        ?_assertEqual(
            <<"sub.domain.example.com">>, dns:dname_to_lower(<<"SUB.DOMAIN.EXAMPLE.COM">>)
        ),

        %% Tests with special characters (which should remain unchanged)
        ?_assertEqual(<<"TEST-1.EXAMPLE.COM">>, dns:dname_to_upper(<<"test-1.example.com">>)),
        ?_assertEqual(<<"test_2.example.com">>, dns:dname_to_lower(<<"TEST_2.EXAMPLE.COM">>)),

        %% Tests with dots and escaping (common in DNS)
        ?_assertEqual(
            <<"ESCAPED\\.DOT.EXAMPLE.COM">>, dns:dname_to_upper(<<"escaped\\.dot.example.com">>)
        ),
        ?_assertEqual(
            <<"label\\.with\\.escaped.dots">>, dns:dname_to_lower(<<"LABEL\\.WITH\\.ESCAPED.DOTS">>)
        ),

        %% Tests with empty or single character domains
        ?_assertEqual(<<>>, dns:dname_to_upper(<<>>)),
        ?_assertEqual(<<"a">>, dns:dname_to_lower(<<"A">>)),

        %% Test with long domain name to check chunking behavior
        ?_assertEqual(
            <<"THISISAVERYLONGSUBDOMAINNAMEWITHMANYCHARACTERS.EXAMPLE.COM">>,
            dns:dname_to_upper(<<"thisisaverylongsubdomainnamewithmanycharacters.example.com">>)
        ),

        %% Test with various lengths to ensure all chunk size code paths are tested

        % 2 chars
        ?_assertEqual(<<"AB">>, dns:dname_to_upper(<<"ab">>)),
        % 3 chars
        ?_assertEqual(<<"abc">>, dns:dname_to_lower(<<"ABC">>)),
        % 4 chars
        ?_assertEqual(<<"ABCD">>, dns:dname_to_upper(<<"abcd">>)),
        % 5 chars
        ?_assertEqual(<<"abcde">>, dns:dname_to_lower(<<"ABCDE">>)),
        % 6 chars
        ?_assertEqual(<<"ABCDEF">>, dns:dname_to_upper(<<"abcdef">>)),
        % 7 chars
        ?_assertEqual(<<"abcdefg">>, dns:dname_to_lower(<<"ABCDEFG">>)),
        % 8 chars
        ?_assertEqual(<<"ABCDEFGH">>, dns:dname_to_upper(<<"abcdefgh">>)),

        %% DNS specific examples - common DNS record types
        ?_assertEqual(<<"_SRV._TCP.EXAMPLE.COM">>, dns:dname_to_upper(<<"_srv._tcp.example.com">>)),
        ?_assertEqual(
            <<"_xmpp-server._tcp.example.com">>,
            dns:dname_to_lower(<<"_XMPP-SERVER._TCP.EXAMPLE.COM">>)
        ),

        %% Real-world examples
        ?_assertEqual(<<"NS1.DNSPROVIDER.NET">>, dns:dname_to_upper(<<"ns1.dnsprovider.net">>)),
        ?_assertEqual(<<"mail.example.org">>, dns:dname_to_lower(<<"MAIL.EXAMPLE.ORG">>))
    ].

%% Test specifically checking that case normalization doesn't affect DNS name comparison
dns_case_insensitive_comparison_test_() ->
    [
        ?_assert(dns:compare_dname(<<"example.com">>, <<"EXAMPLE.COM">>)),
        ?_assert(dns:compare_dname(<<"www.EXAMPLE.com">>, <<"WWW.example.COM">>)),
        ?_assert(
            dns:compare_dname(
                dns:dname_to_upper(<<"example.com">>), dns:dname_to_lower(<<"EXAMPLE.COM">>)
            )
        ),
        ?_assert(dns:compare_labels([<<"example">>, <<"com">>], [<<"EXAMPLE">>, <<"COM">>])),
        ?_assert(
            dns:compare_labels([<<"www">>, <<"example">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?_assert(
            dns:compare_labels([<<"www">>, <<"EXAMPLE">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?_assertNot(
            dns:compare_labels([<<"www">>, <<"different">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?_assertNot(
            dns:compare_labels([<<"www">>, <<"example">>], [<<"www">>, <<"example">>, <<"com">>])
        ),
        ?_assertNot(
            dns:compare_labels([<<"www">>, <<"example">>, <<"com">>], [<<"www">>, <<"example">>])
        )
    ].

dname_preserve_dot_test_() ->
    Query = #dns_query{name = <<"example\\.com">>, class = 1, type = 1},
    Message = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Message),
    Decoded = dns:decode_message(Encoded),
    ReEncoded = dns:encode_message(Decoded),
    ReDecoded = dns:decode_message(ReEncoded),
    [
        ?_assertEqual(Message, Decoded),
        ?_assertEqual(Encoded, ReEncoded),
        ?_assertEqual(Message, ReDecoded)
    ].

split_binary_into_chunks(Bin, Chunk) ->
    List = binary_to_list(Bin),
    [iolist_to_binary(lists:sublist(List, X, Chunk)) || X <- lists:seq(1, length(List), Chunk)].
