-module(dns_SUITE).
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
            message_empty,
            message_query,
            encode_message_max_size,
            encode_message_invalid_size,
            truncated_query_enforces_opt_record,
            message_other,
            long_txt,
            long_txt_not_split,
            fail_txt_not_list_of_strings,
            truncated_txt,
            trailing_garbage_txt,
            message_edns,
            missing_additional_section,
            edns_badvers,
            optrr_too_large,
            bad_optrr_too_large,
            decode_encode_rrdata_wire_samples,
            decode_encode_rrdata,
            uri_decode_normalization,
            uri_decode_invalid_error,
            decode_encode_optdata,
            decode_encode_optdata_owner,
            decode_encode_svcb_params,
            svcb_key_ordering_validation,
            svcb_mandatory_self_reference,
            svcb_mandatory_missing_keys,
            svcb_no_default_alpn_length_validation,
            decode_dname_2_ptr,
            decode_dname_decode_loop,
            decode_dname_bad_pointer,
            encode_dname_1,
            encode_dname_3,
            encode_dname_4,
            dname_to_lower_labels,
            dname_to_labels,
            labels_to_dname,
            dname_to_upper,
            dname_to_lower,
            dname_case_conversion,
            dns_case_insensitive_comparison,
            dname_preserve_dot,
            encode_rec_list_accumulates_multiple_records
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    Config.

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

message_empty(_) ->
    Msg = #dns_message{},
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

message_query(_) ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Bin = dns:encode_message(Msg),
    ?assertEqual(Msg, dns:decode_message(Bin)).

encode_message_max_size(_) ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Msg3 = Msg#dns_message{adc = 1, additional = [#dns_optrr{udp_payload_size = 512}]},
    [
        ?assert(begin
            {false, Bin} = dns:encode_message(Msg3, #{}),
            Msg3 =:= dns:decode_message(Bin)
        end),
        ?assert(begin
            {false, Bin} = dns:encode_message(Msg, #{max_size => 512}),
            Msg =:= dns:decode_message(Bin)
        end),
        ?assert(begin
            {false, Bin} = dns:encode_message(Msg, #{}),
            Msg =:= dns:decode_message(Bin)
        end)
    ].

encode_message_invalid_size(_) ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Msg3 = Msg#dns_message{adc = 1, additional = [#dns_optrr{udp_payload_size = 99999999}]},
    [
        ?assertError(badarg, dns:encode_message(Msg3, #{})),
        ?assertError(badarg, dns:encode_message(Msg, #{max_size => 999999})),
        ?assertError(badarg, dns:encode_message(Msg, #{max_size => 413})),
        ?assertError(badarg, dns:encode_message(Msg, #{max_size => not_an_integer}))
    ].

truncated_query_enforces_opt_record(_) ->
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
        ?assert(begin
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
        ?assert(begin
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
        ?assert(begin
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

message_other(_) ->
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

long_txt(_) ->
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

long_txt_not_split(_) ->
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

fail_txt_not_list_of_strings(_) ->
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

truncated_txt(_) ->
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

trailing_garbage_txt(_) ->
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

message_edns(_) ->
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

missing_additional_section(_) ->
    %% Query for test./IN/A with missing additional section
    Bin = <<192, 46, 0, 32, 0, 1, 0, 0, 0, 0, 0, 1, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1>>,
    ?assertMatch({truncated, _, <<>>}, dns:decode_message(Bin)).

edns_badvers(_) ->
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

optrr_too_large(Config) ->
    optrr_too_large(Config, 14).

bad_optrr_too_large(Config) ->
    optrr_too_large(Config, 15).

%% Regression:
%%
%% Ensure we are reserving the right amount of space for OptRR records, which on their minimal
%% size is 11 bytes. We here construct a message that we know barely but correctly fits within
%% 512 bytes, and we test that when re-encoding the original message, it will encode exactly as
%% it is.
optrr_too_large(_Config, Anc) ->
    %% Regression: test `optrr_too_large` going wrong
    QName = iolist_to_binary(lists:duplicate(255, $a)),
    Question = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Answers = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {127, 0, 0, I}}
        }
     || I <- lists:seq(1, Anc)
    ],
    OptRR = #dns_optrr{udp_payload_size = 512},
    Msg = #dns_message{
        qc = 1,
        questions = [Question],
        anc = Anc,
        answers = Answers,
        adc = 1,
        additional = [OptRR]
    },
    case Anc of
        14 ->
            ?assert(byte_size(dns:encode_message(Msg)) =< 512);
        _ ->
            ?assert(byte_size(dns:encode_message(Msg)) > 512)
    end,
    try
        Result = dns:encode_message(Msg, #{max_size => 512}),
        ?assertMatch({false, _}, Result),
        {false, Encoded} = Result,
        ?assert(is_binary(Encoded) andalso byte_size(Encoded) > 0)
    catch
        Error:Reason:Stacktrace ->
            ct:fail("Error: ~p:~p~n~p", [Error, Reason, Stacktrace])
    end.

%%%===================================================================
%%% Record data functions
%%%===================================================================

decode_encode_rrdata_wire_samples(_) ->
    Cases = data_samples:rrdata_wire(),
    [
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
     || {Class, Type, TestBin} <- Cases
    ].

decode_encode_rrdata(_) ->
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
        {?DNS_TYPE_HTTPS, #dns_rrdata_https{
            svc_priority = 0, target_name = <<"target.example.com">>, svc_params = #{}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0, target_name = <<"target.example.com">>, svc_params = #{}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_PORT_NUMBER => 8080}
        }},
        {?DNS_TYPE_ZONEMD, #dns_rrdata_zonemd{
            serial = 2025121100,
            scheme = 1,
            algorithm = ?DNS_ZONEMD_ALG_SHA384,
            hash =
                <<248, 133, 122, 90, 137, 239, 73, 255, 194, 235, 224, 95, 39, 24, 115, 94, 229,
                    116, 172, 159, 230, 143, 71, 48, 131, 240, 245, 75, 250, 57, 200, 24, 1, 228,
                    54, 127, 239, 243, 222, 160, 193, 79, 87, 40, 58, 124, 102, 173>>
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 83,
            target_name = <<"target.example.com">>,
            svc_params = #{
                ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_ALPN, ?DNS_SVCB_PARAM_PORT],
                ?DNS_SVCB_PARAM_ALPN => [<<"h2>>, <<h3">>],
                ?DNS_SVCB_PARAM_PORT => 83
            }
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 83,
            target_name = <<"target.example.com">>,
            svc_params = #{
                ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_ALPN, ?DNS_SVCB_PARAM_PORT],
                ?DNS_SVCB_PARAM_ALPN => [<<"h2>>, <<h3">>],
                ?DNS_SVCB_PARAM_PORT => 83,
                667 => <<"opaque-value">>
            }
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_ALPN => [<<"h2>>, <<h3">>]}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_ECH => <<"123abc">>}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_IPV4HINT => [{1, 2, 3, 4}, {1, 2, 3, 5}]}
        }},
        {?DNS_TYPE_SVCB, #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{
                ?DNS_SVCB_PARAM_IPV6HINT =>
                    [
                        {16#2001, 16#0db8, 16#85a3, 16#0000, 16#0000, 16#8a2e, 16#0370, 16#7334},
                        {16#2001, 16#0db8, 16#85a3, 16#0000, 16#0000, 16#8a2e, 16#0370, 16#7335}
                    ]
            }
        }},
        {?DNS_TYPE_DNSKEY, #dns_rrdata_dnskey{
            flags = 257,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP256SHA256,
            public_key = base64:decode(
                <<"GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==">>
            ),
            keytag = 55648
        }},
        {?DNS_TYPE_DNSKEY, #dns_rrdata_dnskey{
            flags = 257,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP384SHA384,
            public_key = base64:decode(
                <<"xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40">>
            ),
            keytag = 10771
        }},
        {?DNS_TYPE_CDNSKEY, #dns_rrdata_cdnskey{
            flags = 257,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP256SHA256,
            public_key = base64:decode(
                <<"GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==">>
            ),
            keytag = 55648
        }},
        {?DNS_TYPE_CDNSKEY, #dns_rrdata_cdnskey{
            flags = 257,
            protocol = 3,
            alg = ?DNS_ALG_ECDSAP384SHA384,
            public_key = base64:decode(
                <<"xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40">>
            ),
            keytag = 10771
        }},
        % https://datatracker.ietf.org/doc/html/rfc6698#section-2.3 Example 2
        {?DNS_TYPE_TLSA, #dns_rrdata_tlsa{
            usage = 1,
            selector = 1,
            matching_type = 2,
            certificate =
                <<"92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc">>
        }},
        {?DNS_TYPE_OPENPGPKEY, #dns_rrdata_openpgpkey{
            data = base64:decode(
                <<"mQINBFit2jsBEADrbl5vjVxYeAE0g0IDYCBpHirv1Sjlqxx5gjtPhb2YhvyDMXjq">>
            )
        }},
        {?DNS_TYPE_SMIMEA, #dns_rrdata_smimea{
            usage = 3,
            selector = 1,
            matching_type = 1,
            certificate = base64:decode(<<"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA">>)
        }},
        {?DNS_TYPE_WALLET, #dns_rrdata_wallet{
            data = base64:decode(<<"dGVzdC13YWxsZXQtZGF0YQ==">>)
        }},
        {?DNS_TYPE_EUI48, #dns_rrdata_eui48{
            address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E>>
        }},
        {?DNS_TYPE_EUI64, #dns_rrdata_eui64{
            address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E, 16#6F, 16#70>>
        }}
    ],
    [
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
     || {Type, Data} <- Cases
    ].

uri_decode_normalization(_) ->
    %% Test that URI targets are normalized during decoding
    Cases = [
        %% {Input URI, Expected normalized URI}
        {<<"HTTPS://EXAMPLE.COM/">>, <<"https://example.com/">>},
        {<<"http://example.com/path">>, <<"http://example.com/path">>},
        {<<"https://www.example.com/">>, <<"https://www.example.com/">>},
        {<<"HTTPS://EXAMPLE.COM:443/">>, <<"https://example.com/">>}
    ],
    [
        begin
            %% Encode the URI record
            Priority = 10,
            Weight = 1,
            Rdata = #dns_rrdata_uri{
                priority = Priority,
                weight = Weight,
                target = InputURI
            },
            {Encoded, _} = dns_encode:encode_rrdata(0, ?DNS_CLASS_IN, Rdata, #{}),

            %% Decode and verify normalization
            Decoded = dns_decode:decode_rrdata(Encoded, ?DNS_CLASS_IN, ?DNS_TYPE_URI, Encoded),
            #dns_rrdata_uri{
                priority = DecodedPriority,
                weight = DecodedWeight,
                target = DecodedTarget
            } = Decoded,
            ?assertEqual(Priority, DecodedPriority),
            ?assertEqual(Weight, DecodedWeight),
            ?assertEqual(
                ExpectedNormalized,
                DecodedTarget,
                io_lib:format(
                    "URI normalization failed: ~p -> ~p (expected ~p)",
                    [InputURI, DecodedTarget, ExpectedNormalized]
                )
            )
        end
     || {InputURI, ExpectedNormalized} <- Cases
    ].

uri_decode_invalid_error(_) ->
    %% Test that invalid URIs throw {bad_uri, Target, Reason}
    InvalidURIs = [
        <<"not a valid uri">>,
        <<"://invalid">>
    ],
    [
        begin
            Priority = 10,
            Weight = 1,
            %% Create wire format: Priority (16 bits) + Weight (16 bits) + Target
            WireData = <<Priority:16, Weight:16, InvalidURI/binary>>,

            %% Attempt to decode and verify it throws
            try
                _Decoded = dns_decode:decode_rrdata(
                    WireData, ?DNS_CLASS_IN, ?DNS_TYPE_URI, WireData
                ),
                ?assert(false, io_lib:format("Expected throw for invalid URI: ~p", [InvalidURI]))
            catch
                error:{bad_uri, Target, Reason} ->
                    ?assertEqual(InvalidURI, Target),
                    ?assert(
                        is_atom(Reason) orelse is_binary(Reason) orelse is_list(Reason),
                        io_lib:format("Expected Reason to be atom, binary, or list, got: ~p", [
                            Reason
                        ])
                    )
            end
        end
     || InvalidURI <- InvalidURIs
    ].

%%%===================================================================
%%% EDNS data functions
%%%===================================================================

decode_encode_optdata(_) ->
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
        ?assertEqual([Case], dns_decode:decode_optrrdata(dns_encode:encode_optrrdata([Case])))
     || Case <- Cases
    ].

decode_encode_optdata_owner(_) ->
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
        ?assertEqual([Case], dns_decode:decode_optrrdata(dns_encode:encode_optrrdata([Case])))
     || Case <- Cases
    ].

decode_encode_svcb_params(_) ->
    Cases = [
        {#{}, #{}},
        {#{?DNS_SVCB_PARAM_PORT => 8079}, #{?DNS_SVCB_PARAM_PORT => 8079}}
    ],

    [
        ?assertEqual(
            Expected, dns_decode:decode_svcb_svc_params(dns_encode:encode_svcb_svc_params(Input))
        )
     || {Input, Expected} <- Cases
    ].

svcb_key_ordering_validation(_) ->
    %% Test that keys must be in strictly ascending order
    %% Create a binary with keys out of order: port (3) before alpn (1)
    PortKey = ?DNS_SVCB_PARAM_PORT,
    AlpnKey = ?DNS_SVCB_PARAM_ALPN,
    %% Encode port first (wrong order)
    PortBin = <<PortKey:16, 2:16, 443:16>>,
    %% Encode alpn second (should be first)
    AlpnValue = <<2, "h2">>,
    AlpnBin = <<AlpnKey:16, (byte_size(AlpnValue)):16, AlpnValue/binary>>,
    OutOfOrderBin = <<PortBin/binary, AlpnBin/binary>>,
    ?assertException(
        throw,
        {svcb_key_ordering_error, {prev_key, PortKey}, {current_key, AlpnKey}},
        dns_decode:decode_svcb_svc_params(OutOfOrderBin)
    ).

svcb_mandatory_self_reference(_) ->
    %% Test that mandatory cannot reference itself (key 0)
    MandatoryKey = ?DNS_SVCB_PARAM_MANDATORY,
    %% Create mandatory parameter that references itself
    MandatoryValue = <<MandatoryKey:16>>,
    MandatoryBin = <<MandatoryKey:16, (byte_size(MandatoryValue)):16, MandatoryValue/binary>>,
    ?assertException(
        throw,
        {svcb_mandatory_validation_error, {mandatory_self_reference, MandatoryKey}},
        dns_decode:decode_svcb_svc_params(MandatoryBin)
    ).

svcb_mandatory_missing_keys(_) ->
    %% Test that all mandatory keys must exist in SvcParams
    MandatoryKey = ?DNS_SVCB_PARAM_MANDATORY,
    PortKey = ?DNS_SVCB_PARAM_PORT,
    %% Create mandatory parameter that references port, but port is not present
    MandatoryValue = <<PortKey:16>>,
    MandatoryBin = <<MandatoryKey:16, (byte_size(MandatoryValue)):16, MandatoryValue/binary>>,
    ?assertException(
        throw,
        {svcb_mandatory_validation_error, {missing_mandatory_keys, [PortKey]}},
        dns_decode:decode_svcb_svc_params(MandatoryBin)
    ).

svcb_no_default_alpn_length_validation(_) ->
    %% Test that NO_DEFAULT_ALPN must have length 0
    NoDefaultAlpnKey = ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN,
    %% Create NO_DEFAULT_ALPN with non-zero length (should be 0)
    InvalidBin = <<NoDefaultAlpnKey:16, 1:16, 0:8>>,
    ?assertException(
        throw,
        {svcb_bad_no_default_alpn, 1},
        dns_decode:decode_svcb_svc_params(InvalidBin)
    ).

%%%===================================================================
%%% Domain name functions
%%%===================================================================

decode_dname_2_ptr(_) ->
    Cases = [{<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, <<3:2, 0:14>>}],
    [
        ?assertEqual({<<"example">>, <<>>}, dns_decode:decode_dname(DataBin, MsgBin))
     || {MsgBin, DataBin} <- Cases
    ].

decode_dname_decode_loop(_) ->
    Bin = <<3:2, 0:14>>,
    ?assertException(throw, decode_loop, dns_decode:decode_dname(Bin, Bin)).

decode_dname_bad_pointer(_) ->
    Case = <<3:2, 42:14>>,
    ?assertException(throw, bad_pointer, dns_decode:decode_dname(Case, Case)).

encode_dname_1(_) ->
    Cases = [
        {<<"example">>, <<7, 101, 120, 97, 109, 112, 108, 101, 0>>}
    ],
    [?assertEqual(Expect, dns_encode:encode_dname(Input)) || {Input, Expect} <- Cases].

encode_dname_3(_) ->
    {Bin, _CompMap} = dns_encode:encode_dname(#{}, 0, <<"example">>),
    ?assertEqual(<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, Bin).

encode_dname_4(_) ->
    {Bin0, CM0} = dns_encode:encode_append_dname(<<>>, #{}, 0, <<"example">>),
    {Bin1, _} = dns_encode:encode_append_dname(Bin0, CM0, byte_size(Bin0), <<"example">>),
    {Bin2, _} = dns_encode:encode_append_dname(Bin0, CM0, byte_size(Bin0), <<"EXAMPLE">>),
    MP = (1 bsl 14),
    MPB = <<0:MP/unit:8>>,
    {_, CM1} = dns_encode:encode_append_dname(MPB, #{}, MP, <<"example">>),
    Cases = [
        {<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, Bin0},
        {<<7, 101, 120, 97, 109, 112, 108, 101, 0, 192, 0>>, Bin1},
        {Bin1, Bin2},
        {#{}, CM1}
    ],
    [?assertEqual(Expect, Result) || {Expect, Result} <- Cases].

dname_to_lower_labels(_) ->
    Cases = [
        {<<>>, []},
        {<<".">>, []},
        {<<"A.B.C">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"A.B.C.">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"A\\.B.c">>, [<<"a.b">>, <<"c">>]},
        {<<"A\\\\.b.C">>, [<<"a\\">>, <<"b">>, <<"c">>]}
    ],
    [?assertEqual(Expect, dns:dname_to_lower_labels(Arg)) || {Arg, Expect} <- Cases].

dname_to_labels(_) ->
    Cases = [
        {<<>>, []},
        {<<".">>, []},
        {<<"a.b.c">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"a.b.c.">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"a\\.b.c">>, [<<"a.b">>, <<"c">>]},
        {<<"a\\\\.b.c">>, [<<"a\\">>, <<"b">>, <<"c">>]}
    ],
    [?assertEqual(Expect, dns:dname_to_labels(Arg)) || {Arg, Expect} <- Cases].

labels_to_dname(_) ->
    Cases = [
        {[<<"a">>, <<"b">>, <<"c">>], <<"a.b.c">>},
        {[<<"a.b">>, <<"c">>], <<"a\\.b.c">>},
        {[<<"a\\">>, <<"b">>, <<"c">>], <<"a\\\\.b.c">>}
    ],
    [?assertEqual(Expect, dns:labels_to_dname(Arg)) || {Arg, Expect} <- Cases].

dname_to_upper(_) ->
    Cases = [{<<"Y">>, <<"Y">>}, {<<"y">>, <<"Y">>}],
    [?assertEqual(Expect, dns:dname_to_upper(Arg)) || {Arg, Expect} <- Cases].

dname_to_lower(_) ->
    Cases = [{<<"Y">>, <<"y">>}, {<<"y">>, <<"y">>}],
    [?assertEqual(Expect, dns:dname_to_lower(Arg)) || {Arg, Expect} <- Cases].

dname_case_conversion(_) ->
    [
        %% Basic domain name tests
        ?assertEqual(<<"EXAMPLE.COM">>, dns:dname_to_upper(<<"example.com">>)),
        ?assertEqual(<<"example.com">>, dns:dname_to_lower(<<"EXAMPLE.COM">>)),

        %% Mixed case input tests
        ?assertEqual(<<"EXAMPLE.COM">>, dns:dname_to_upper(<<"ExAmPle.CoM">>)),
        ?assertEqual(<<"example.com">>, dns:dname_to_lower(<<"ExAmPle.CoM">>)),

        %% Tests with subdomains
        ?assertEqual(<<"WWW.EXAMPLE.COM">>, dns:dname_to_upper(<<"www.example.com">>)),
        ?assertEqual(
            <<"sub.domain.example.com">>, dns:dname_to_lower(<<"SUB.DOMAIN.EXAMPLE.COM">>)
        ),

        %% Tests with special characters (which should remain unchanged)
        ?assertEqual(<<"TEST-1.EXAMPLE.COM">>, dns:dname_to_upper(<<"test-1.example.com">>)),
        ?assertEqual(<<"test_2.example.com">>, dns:dname_to_lower(<<"TEST_2.EXAMPLE.COM">>)),

        %% Tests with dots and escaping (common in DNS)
        ?assertEqual(
            <<"ESCAPED\\.DOT.EXAMPLE.COM">>, dns:dname_to_upper(<<"escaped\\.dot.example.com">>)
        ),
        ?assertEqual(
            <<"label\\.with\\.escaped.dots">>, dns:dname_to_lower(<<"LABEL\\.WITH\\.ESCAPED.DOTS">>)
        ),

        %% Tests with empty or single character domains
        ?assertEqual(<<>>, dns:dname_to_upper(<<>>)),
        ?assertEqual(<<"a">>, dns:dname_to_lower(<<"A">>)),

        %% Test with long domain name to check chunking behavior
        ?assertEqual(
            <<"THISISAVERYLONGSUBDOMAINNAMEWITHMANYCHARACTERS.EXAMPLE.COM">>,
            dns:dname_to_upper(<<"thisisaverylongsubdomainnamewithmanycharacters.example.com">>)
        ),

        %% Test with various lengths to ensure all chunk size code paths are tested

        % 2 chars
        ?assertEqual(<<"AB">>, dns:dname_to_upper(<<"ab">>)),
        % 3 chars
        ?assertEqual(<<"abc">>, dns:dname_to_lower(<<"ABC">>)),
        % 4 chars
        ?assertEqual(<<"ABCD">>, dns:dname_to_upper(<<"abcd">>)),
        % 5 chars
        ?assertEqual(<<"abcde">>, dns:dname_to_lower(<<"ABCDE">>)),
        % 6 chars
        ?assertEqual(<<"ABCDEF">>, dns:dname_to_upper(<<"abcdef">>)),
        % 7 chars
        ?assertEqual(<<"abcdefg">>, dns:dname_to_lower(<<"ABCDEFG">>)),
        % 8 chars
        ?assertEqual(<<"ABCDEFGH">>, dns:dname_to_upper(<<"abcdefgh">>)),

        %% DNS specific examples - common DNS record types
        ?assertEqual(<<"_SRV._TCP.EXAMPLE.COM">>, dns:dname_to_upper(<<"_srv._tcp.example.com">>)),
        ?assertEqual(
            <<"_xmpp-server._tcp.example.com">>,
            dns:dname_to_lower(<<"_XMPP-SERVER._TCP.EXAMPLE.COM">>)
        ),

        %% Real-world examples
        ?assertEqual(<<"NS1.DNSPROVIDER.NET">>, dns:dname_to_upper(<<"ns1.dnsprovider.net">>)),
        ?assertEqual(<<"mail.example.org">>, dns:dname_to_lower(<<"MAIL.EXAMPLE.ORG">>))
    ].

%% Test specifically checking that case normalization doesn't affect DNS name comparison
dns_case_insensitive_comparison(_) ->
    [
        ?assert(dns:compare_dname(<<"example.com">>, <<"EXAMPLE.COM">>)),
        ?assert(dns:compare_dname(<<"www.EXAMPLE.com">>, <<"WWW.example.COM">>)),
        ?assert(
            dns:compare_dname(
                dns:dname_to_upper(<<"example.com">>), dns:dname_to_lower(<<"EXAMPLE.COM">>)
            )
        ),
        ?assert(dns:compare_labels([<<"example">>, <<"com">>], [<<"EXAMPLE">>, <<"COM">>])),
        ?assert(
            dns:compare_labels([<<"www">>, <<"example">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?assert(
            dns:compare_labels([<<"www">>, <<"EXAMPLE">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?assertNot(
            dns:compare_labels([<<"www">>, <<"different">>, <<"com">>], [
                <<"WWW">>, <<"example">>, <<"COM">>
            ])
        ),
        ?assertNot(
            dns:compare_labels([<<"www">>, <<"example">>], [<<"www">>, <<"example">>, <<"com">>])
        ),
        ?assertNot(
            dns:compare_labels([<<"www">>, <<"example">>, <<"com">>], [<<"www">>, <<"example">>])
        )
    ].

dname_preserve_dot(_) ->
    Query = #dns_query{name = <<"example\\.com">>, class = 1, type = 1},
    Message = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Message),
    Decoded = dns:decode_message(Encoded),
    ReEncoded = dns:encode_message(Decoded),
    ReDecoded = dns:decode_message(ReEncoded),
    [
        ?assertEqual(Message, Decoded),
        ?assertEqual(Encoded, ReEncoded),
        ?assertEqual(Message, ReDecoded)
    ].

%% This test ensures that encode_rec_list correctly accumulates all records,
%% not just the last one. The bug was that the accumulator was being replaced
%% instead of accumulated, causing only the last record to be returned.
encode_rec_list_accumulates_multiple_records(_) ->
    QName = <<"example.com">>,
    %% Create a message with multiple A records in the answers section
    %% This will test encode_rec_list with multiple records
    Answers = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {127, 0, 0, I}}
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 5,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        answers = Answers
    },
    %% Encode and decode the message
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    %% Verify all 5 records are present in the decoded message
    ?assertEqual(5, length(Decoded#dns_message.answers)),
    %% Verify each record matches the original
    [
        ?assertMatch(
            #dns_rr{
                name = QName,
                type = ?DNS_TYPE_A,
                data = #dns_rrdata_a{ip = {127, 0, 0, I}}
            },
            lists:nth(I, Decoded#dns_message.answers)
        )
     || I <- lists:seq(1, 5)
    ],
    %% Also test with multiple OPT records in additional section
    %% This tests encode_message_d_opt which also uses encode_rec_list
    OptRRs = [
        #dns_optrr{
            udp_payload_size = 512 + I,
            data = [#dns_opt_nsid{data = <<"test", I:8>>}]
        }
     || I <- lists:seq(0, 2)
    ],
    MsgWithOpt = Msg#dns_message{
        adc = 3,
        additional = OptRRs
    },
    EncodedOpt = dns:encode_message(MsgWithOpt),
    DecodedOpt = dns:decode_message(EncodedOpt),
    %% Verify all OPT records are present
    ?assertEqual(3, length(DecodedOpt#dns_message.additional)),
    %% Verify we can round-trip encode/decode
    ?assertEqual(Msg, Decoded),
    ?assertEqual(MsgWithOpt, DecodedOpt).

split_binary_into_chunks(Bin, Chunk) ->
    List = binary_to_list(Bin),
    [iolist_to_binary(lists:sublist(List, X, Chunk)) || X <- lists:seq(1, length(List), Chunk)].
