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
            {group, message_basic},
            {group, message_encoding},
            {group, txt_records},
            {group, edns},
            {group, rrdata},
            {group, svcb},
            {group, dname_utilities},
            {group, dname_compression},
            {group, decode_query}
        ]},
        {message_basic, [parallel], [
            message_empty,
            message_query,
            message_other
        ]},
        {message_encoding, [parallel], [
            encode_message_max_size,
            encode_message_invalid_size,
            truncated_query_enforces_opt_record,
            encode_default_message_question_offset_correct
        ]},
        {txt_records, [parallel], [
            long_txt,
            long_txt_not_split,
            fail_txt_not_list_of_strings,
            truncated_txt,
            trailing_garbage_txt
        ]},
        {edns, [parallel], [
            message_edns,
            missing_additional_section,
            edns_badvers,
            optrr_too_large,
            bad_optrr_too_large,
            uri_decode_normalization,
            uri_decode_invalid_error,
            decode_encode_rrdata_wire_samples,
            decode_encode_rrdata,
            decode_encode_optdata,
            decode_encode_optdata_owner
        ]},
        {rrdata, [parallel], [
            decode_encode_rrdata_wire_samples,
            decode_encode_rrdata
        ]},
        {svcb, [parallel], [
            decode_encode_svcb_params,
            svcb_key_ordering_validation,
            svcb_mandatory_self_reference,
            svcb_mandatory_missing_keys,
            svcb_no_default_alpn_length_validation,
            svcb_encode_wire_key_no_value,
            svcb_encode_wire_key_binary_value,
            svcb_encode_wire_key_invalid_value
        ]},
        {dname_utilities, [parallel], [
            dname_preserve_dot,
            encode_rec_list_accumulates_multiple_records
        ]},
        {dname_compression, [parallel], [
            encode_name_compression_with_multiple_records,
            encode_name_compression_with_cname_chain,
            encode_name_compression_with_ns_records,
            encode_name_compression_with_mx_records,
            encode_name_compression_with_soa_record,
            encode_name_compression_with_srv_records,
            encode_name_compression_with_ptr_records,
            encode_name_compression_with_txt_records,
            encode_name_compression_with_multiple_sections,
            encode_soa_rname_compresses_to_mname,
            encode_soa_both_names_compress_to_question,
            encode_soa_position_tracking_correct,
            encode_mx_exchange_compresses_to_name,
            encode_ns_dname_compresses_to_name,
            encode_srv_target_compresses_to_name,
            encode_ptr_dname_compresses_to_name,
            encode_cname_dname_compresses_to_name,
            encode_compression_pointer_valid_range,
            encode_multiple_soa_records_compression
        ]},
        {decode_query, [parallel], [
            decode_query_valid,
            decode_query_zero_questions_with_cookie,
            decode_query_qr_bit_rejected,
            decode_query_tc_bit_rejected,
            decode_query_ancount_rejected,
            decode_query_nscount_rejected,
            decode_query_qdcount_invalid,
            decode_query_notify_allowed,
            decode_query_update_allowed,
            decode_query_too_short,
            decode_query_iquery_notimp,
            decode_query_status_notimp,
            decode_query_reserved_opcode3_notimp,
            decode_query_dso_notimp,
            decode_query_reserved_opcode7_notimp,
            decode_query_notimp_malformed_question
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
            Bin = dns:encode_message(Msg3, #{}),
            is_binary(Bin) andalso Msg3 =:= dns:decode_message(Bin)
        end),
        ?assert(begin
            Bin = dns:encode_message(Msg, #{max_size => 512}),
            is_binary(Bin) andalso Msg =:= dns:decode_message(Bin)
        end),
        ?assert(begin
            Bin = dns:encode_message(Msg, #{}),
            is_binary(Bin) andalso Msg =:= dns:decode_message(Bin)
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
            Encoded = dns:encode_message(Msg, #{max_size => 512}),
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
            Encoded = dns:encode_message(Msg, #{max_size => 512}),
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
            Encoded = dns:encode_message(Msg, #{max_size => 512}),
            Decoded = dns:decode_message(Encoded),
            byte_size(Encoded) =< 512 andalso Decoded#dns_message.tc andalso
                ok =:= ?assertMatch([], Decoded#dns_message.answers) andalso
                ok =:= ?assertMatch([Question], Decoded#dns_message.questions) andalso
                ok =:= ?assertMatch([#dns_optrr{data = []} | _], Decoded#dns_message.additional)
        end)
    ].

%% Regression test: verify that encode_default_message calculates question section
%% name offsets from position 12 (header size) instead of 0. This ensures compression
%% pointers are correct when answer/authority/additional sections reference question names.
%%
%% BEFORE THE FIX: This test would fail because:
%% - encode_append_section was called with <<>> (empty binary)
%% - Compression map entries were created with positions 0-11 (in header)
%% - When answer/authority/additional sections compressed to question names,
%%   compression pointers pointed to positions 0-11 (invalid, in header)
%% - Decoding would throw bad_pointer or decode_loop errors
%%
%% AFTER THE FIX: Compression pointers correctly point to positions 12+ (in question section)
encode_default_message_question_offset_correct(_) ->
    QName = <<"example.com">>,
    Question = #dns_query{name = QName, type = ?DNS_TYPE_A},
    %% Create records in all sections that reference the same name as the question
    %% This ensures compression is tested across all sections
    Answer = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {1, 2, 3, 4}}
    },
    Authority = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = <<"ns1.example.com">>}
    },
    Additional = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_AAAA,
        ttl = 3600,
        data = #dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 1}}
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        auc = 1,
        adc = 1,
        questions = [Question],
        answers = [Answer],
        authority = [Authority],
        additional = [Additional]
    },
    %% Use encode_message with max_size to trigger encode_message_default
    %% which uses encode_append_section with the buggy <<>> accumulator
    Encoded = dns:encode_message(Msg, #{max_size => 512}),
    %% BEFORE THE FIX: Decoding would fail with bad_pointer or decode_loop
    %% because compression pointers point to positions 0-11 (header bytes)
    %% which don't contain valid DNS name encoding
    %%
    %% AFTER THE FIX: Decoding succeeds because compression pointers point to
    %% positions 12+ (question section) which contain valid DNS name encoding
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    %% Verify all sections decoded correctly
    ?assertMatch(
        #dns_message{
            questions = [#dns_query{name = QName}],
            answers = [#dns_rr{name = QName}],
            authority = [#dns_rr{name = QName}],
            additional = [#dns_rr{name = QName}]
        },
        Decoded
    ).

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
    %% Create a valid large domain name using multiple labels (max 63 bytes each)
    %% 4 labels of 62 bytes each = 4 * 63 (length byte + label) + 1 (root) = 253 bytes (valid, < 255)
    Label63 = iolist_to_binary(lists:duplicate(62, $a)),
    QName = dns_domain:join([Label63, Label63, Label63, Label63]),
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
            Encoded = dns:encode_message(Msg),
            ?assert(byte_size(Encoded) =< 512, Anc);
        _ ->
            Encoded = dns:encode_message(Msg),
            ?assert(byte_size(Encoded) > 512, Anc)
    end,
    Result = dns:encode_message(Msg, #{max_size => 512}),
    ?assert(is_binary(Result) andalso byte_size(Result) > 0).

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
        error,
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
        error,
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
        error,
        {svcb_mandatory_validation_error, {missing_mandatory_keys, [PortKey]}},
        dns_decode:decode_svcb_svc_params(MandatoryBin)
    ).

svcb_no_default_alpn_length_validation(_) ->
    %% Test that NO_DEFAULT_ALPN must have length 0
    NoDefaultAlpnKey = ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN,
    %% Create NO_DEFAULT_ALPN with non-zero length (should be 0)
    InvalidBin = <<NoDefaultAlpnKey:16, 1:16, 0:8>>,
    ?assertException(
        error,
        {svcb_bad_no_default_alpn, 1},
        dns_decode:decode_svcb_svc_params(InvalidBin)
    ).

svcb_encode_wire_key_no_value(_) ->
    RR = #dns_rrdata_svcb{
        svc_priority = 12,
        target_name = ~"svc.example.com",
        svc_params = #{123 => none}
    },
    ?assertMatch(
        <<0, 12, 3, "svc", 7, "example", 3, "com", 0, 0, 123, 0, 0>>,
        dns_encode:encode_rrdata(0, RR)
    ).

svcb_encode_wire_key_binary_value(_) ->
    RR = #dns_rrdata_svcb{
        svc_priority = 15,
        target_name = ~"svc.example.com",
        svc_params = #{65534 => ~"hello=world"}
    },
    ?assertMatch(
        <<0, 15, 3, "svc", 7, "example", 3, "com", 0, 255, 254, 0, 11, "hello=world">>,
        dns_encode:encode_rrdata(0, RR)
    ).

svcb_encode_wire_key_invalid_value(_) ->
    RR = #dns_rrdata_svcb{
        svc_priority = 15,
        target_name = ~"svc.example.com",
        svc_params = #{123 => [invalid, values]}
    },
    ?assertError(
        {invalid_svcparam_format, [invalid, values]},
        dns_encode:encode_rrdata(0, RR)
    ).

%%%===================================================================
%%% dname_utilities Tests
%%%===================================================================

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

decode_query_valid(_) ->
    %% Valid query: QDCount=1, ANCount=0, NSCount=0, Opcode=0, QR=0
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_query(Encoded),
    ?assertEqual(Msg, Decoded).

decode_query_zero_questions_with_cookie(_) ->
    %% RFC 7873: Cookie-only queries may have QDCount=0 when an OPT record with a COOKIE option
    %% is present in the additional section.
    ClientCookie = <<"12345678">>,
    Cookie = #dns_opt_cookie{client = ClientCookie},
    OptRR = #dns_optrr{data = [Cookie]},
    Msg = #dns_message{
        qc = 0,
        adc = 1,
        questions = [],
        additional = [OptRR]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_query(Encoded),
    ?assertEqual(0, Decoded#dns_message.qc),
    ?assertEqual([], Decoded#dns_message.questions),
    ?assertEqual(1, Decoded#dns_message.adc),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedCookie] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(ClientCookie, DecodedCookie#dns_opt_cookie.client).

decode_query_qr_bit_rejected(_) ->
    %% Query with QR=1 (response) should be rejected
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    %% Modify header to set QR=1
    <<Id:16, _QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
        ADC:16, Rest/binary>> = Encoded,
    ModifiedHeader =
        <<Id:16, 1:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
            ADC:16>>,
    ModifiedBin = <<ModifiedHeader/binary, Rest/binary>>,
    ?assertMatch({formerr, undefined, _}, dns:decode_query(ModifiedBin)).

decode_query_tc_bit_rejected(_) ->
    %% Query with TC=1 (truncated) should be rejected
    %% Queries should never be truncated per RFC 1035
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    %% Modify header to set TC=1
    <<Id:16, QR:1, OC:4, _AA:1, _TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
        ADC:16, Rest/binary>> = Encoded,
    ModifiedHeader =
        <<Id:16, QR:1, OC:4, 0:1, 1:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
            ADC:16>>,
    ModifiedBin = <<ModifiedHeader/binary, Rest/binary>>,
    ?assertMatch({formerr, undefined, _}, dns:decode_query(ModifiedBin)).

decode_query_ancount_rejected(_) ->
    %% Query with ANCount=1 should be rejected
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    %% Modify header to set ANCount=1
    <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, _ANC:16, AUC:16,
        ADC:16, Rest/binary>> = Encoded,
    ModifiedHeader =
        <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, 1:16, AUC:16,
            ADC:16>>,
    ModifiedBin = <<ModifiedHeader/binary, Rest/binary>>,
    ?assertMatch({formerr, undefined, _}, dns:decode_query(ModifiedBin)).

decode_query_nscount_rejected(_) ->
    %% Query with NSCount=1 should be rejected
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    %% Modify header to set NSCount (AUC)=1
    <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, _AUC:16,
        ADC:16, Rest/binary>> = Encoded,
    ModifiedHeader =
        <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RC:4, QC:16, ANC:16, 1:16,
            ADC:16>>,
    ModifiedBin = <<ModifiedHeader/binary, Rest/binary>>,
    ?assertMatch({formerr, undefined, _}, dns:decode_query(ModifiedBin)).

decode_query_qdcount_invalid(_) ->
    %% Query with QDCount=2 should be rejected
    QName = <<"example.com">>,
    Query1 = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Query2 = #dns_query{name = <<"test.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 2, questions = [Query1, Query2]},
    Encoded = dns:encode_message(Msg),
    %% decode_query should reject QDCount=2 for opcode 0
    ?assertMatch({formerr, undefined, _}, dns:decode_query(Encoded)),
    %% But decode_message should still work
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded).

decode_query_notify_allowed(_) ->
    %% NOTIFY (opcode 4) should be allowed even with Answer/Authority records
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_SOA},
    Answer = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns1.example.com">>,
            rname = <<"admin.example.com">>,
            serial = 1,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        auc = 1,
        oc = 4,
        questions = [Query],
        answers = [Answer],
        authority = [Answer]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_query(Encoded),
    ?assertMatch(#dns_message{oc = 4, anc = 1, auc = 1}, Decoded).

decode_query_update_allowed(_) ->
    %% UPDATE (opcode 5) should be allowed even with Answer/Authority records
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_SOA},
    Answer = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {127, 0, 0, 1}}
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        auc = 1,
        oc = 5,
        questions = [Query],
        answers = [Answer],
        authority = [Answer]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_query(Encoded),
    ?assertMatch(#dns_message{oc = 5, anc = 1, auc = 1}, Decoded).

decode_query_too_short(_) ->
    %% Binary shorter than 12 bytes should be rejected
    ShortBin = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>,
    ?assertMatch({formerr, undefined, _}, dns:decode_query(ShortBin)),
    %% Empty binary
    ?assertMatch({formerr, undefined, _}, dns:decode_query(<<>>)).

decode_query_iquery_notimp(_) ->
    %% IQUERY (opcode 1) should return NOTIMP
    %% IQUERY is obsolete per RFC 3425
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, oc = ?DNS_OPCODE_IQUERY, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Result = dns:decode_query(Encoded),
    ?assertMatch(
        {notimp, #dns_message{id = _, oc = ?DNS_OPCODE_IQUERY, rc = ?DNS_RCODE_NOTIMP, qr = true},
            _},
        Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(?DNS_OPCODE_IQUERY, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc),
    ?assertEqual(true, NotImpMsg#dns_message.qr),
    ?assertEqual(0, NotImpMsg#dns_message.anc),
    ?assertEqual(0, NotImpMsg#dns_message.auc),
    ?assertEqual(0, NotImpMsg#dns_message.adc),
    %% Question should be preserved if parsing succeeds
    ?assertEqual(1, NotImpMsg#dns_message.qc),
    ?assertMatch([#dns_query{name = QName}], NotImpMsg#dns_message.questions).

decode_query_status_notimp(_) ->
    %% STATUS (opcode 2) should return NOTIMP
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, oc = ?DNS_OPCODE_STATUS, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Result = dns:decode_query(Encoded),
    ?assertMatch(
        {notimp, #dns_message{id = _, oc = ?DNS_OPCODE_STATUS, rc = ?DNS_RCODE_NOTIMP, qr = true},
            _},
        Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(?DNS_OPCODE_STATUS, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc).

decode_query_reserved_opcode3_notimp(_) ->
    %% Reserved/Unassigned opcode 3 should return NOTIMP
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, oc = 3, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Result = dns:decode_query(Encoded),
    ?assertMatch(
        {notimp, #dns_message{id = _, oc = 3, rc = ?DNS_RCODE_NOTIMP, qr = true}, _}, Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(3, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc).

decode_query_dso_notimp(_) ->
    %% DSO (DNS Stateful Operations, opcode 6) should return NOTIMP
    %% DSO is defined in RFC 8490 but is for stateful operations over TCP/TLS
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, oc = ?DNS_OPCODE_DSO, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Result = dns:decode_query(Encoded),
    ?assertMatch(
        {notimp, #dns_message{id = _, oc = ?DNS_OPCODE_DSO, rc = ?DNS_RCODE_NOTIMP, qr = true}, _},
        Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(?DNS_OPCODE_DSO, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc).

decode_query_reserved_opcode7_notimp(_) ->
    %% Reserved/Unassigned opcode 7 should return NOTIMP
    QName = <<"example.com">>,
    Query = #dns_query{name = QName, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, oc = 7, questions = [Query]},
    Encoded = dns:encode_message(Msg),
    Result = dns:decode_query(Encoded),
    ?assertMatch(
        {notimp, #dns_message{id = _, oc = 7, rc = ?DNS_RCODE_NOTIMP, qr = true}, _}, Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(7, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc).

decode_query_notimp_malformed_question(_) ->
    %% NOTIMP case with malformed question section
    %% The question parsing should fail, but NOTIMP should still be returned
    %% with empty question list (qc=0, questions=[])
    Id = 12345,
    %% Header format: <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, 0:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16, ADC:16>>
    %% For IQUERY (opcode 1): QR=0, OC=1, AA=0, TC=0, RD=0, RA=0, Z=0, AD=0, CD=0, RC=0, QC=1
    %% Flags byte 1: QR=0, OC=1 (0001), AA=0, TC=0, RD=0, RA=0, Z=0
    %%   = 0 0001 0 0 0 0 0 = 0001 0000 = 16
    %% Flags byte 2: AD=0, CD=0, RC=0 (0000)
    %%   = 0 0 0000 = 0000 0000 = 0
    Header = <<Id:16, 0:1, 1:4, 0:1, 0:1, 0:1, 0:1, 0:1, 0:1, 0:1, 0:4, 1:16, 0:16, 0:16, 0:16>>,
    %% Malformed question: label length byte > 63 (invalid per RFC 1035)
    %% This will cause decode_message_questions to fail
    MalformedQuestion = <<200, 100, 101, 102, 0, ?DNS_TYPE_A:16, ?DNS_CLASS_IN:16>>,
    MsgBin = <<Header/binary, MalformedQuestion/binary>>,
    Result = dns:decode_query(MsgBin),
    ?assertMatch(
        {notimp,
            #dns_message{
                id = Id,
                oc = ?DNS_OPCODE_IQUERY,
                rc = ?DNS_RCODE_NOTIMP,
                qr = true,
                qc = 0,
                questions = []
            },
            _},
        Result
    ),
    {notimp, NotImpMsg, _} = Result,
    ?assertEqual(Id, NotImpMsg#dns_message.id),
    ?assertEqual(?DNS_OPCODE_IQUERY, NotImpMsg#dns_message.oc),
    ?assertEqual(?DNS_RCODE_NOTIMP, NotImpMsg#dns_message.rc),
    ?assertEqual(true, NotImpMsg#dns_message.qr),
    %% Question parsing failed, so qc should be 0 and questions should be empty
    ?assertEqual(0, NotImpMsg#dns_message.qc),
    ?assertEqual([], NotImpMsg#dns_message.questions).

%%%===================================================================
%%% Name compression tests
%%%===================================================================

%% Create a message with multiple A records sharing the same name
%% This tests that compression pointers are correctly calculated
encode_name_compression_with_multiple_records(_) ->
    QName = <<"example.com">>,
    Answers = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {127, 0, 0, I}}
        }
     || I <- lists:seq(1, 10)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 10,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        answers = Answers
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(10, length(Decoded#dns_message.answers)),
    %% Verify all records decode correctly
    lists:foreach(
        fun(I) ->
            RR = lists:nth(I, Decoded#dns_message.answers),
            ?assertEqual(QName, RR#dns_rr.name),
            ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
            ?assertMatch(#dns_rrdata_a{ip = {127, 0, 0, I}}, RR#dns_rr.data)
        end,
        lists:seq(1, 10)
    ),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test CNAME chains with name compression
encode_name_compression_with_cname_chain(_) ->
    BaseName = <<"www.example.com">>,
    CName1 = <<"cname1.example.com">>,
    CName2 = <<"cname2.example.com">>,
    Answers = [
        #dns_rr{
            name = BaseName,
            type = ?DNS_TYPE_CNAME,
            ttl = 3600,
            data = #dns_rrdata_cname{dname = CName1}
        },
        #dns_rr{
            name = CName1,
            type = ?DNS_TYPE_CNAME,
            ttl = 3600,
            data = #dns_rrdata_cname{dname = CName2}
        },
        #dns_rr{
            name = CName2,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
        }
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 3,
        questions = [#dns_query{name = BaseName, type = ?DNS_TYPE_A}],
        answers = Answers
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(3, length(Decoded#dns_message.answers)),
    %% Verify the records decode correctly (names may be compressed differently)
    [RR1, RR2, RR3] = Decoded#dns_message.answers,
    ?assertEqual(BaseName, RR1#dns_rr.name),
    ?assertEqual(?DNS_TYPE_CNAME, RR1#dns_rr.type),
    ?assertMatch(#dns_rrdata_cname{dname = CName1}, RR1#dns_rr.data),
    ?assertEqual(CName1, RR2#dns_rr.name),

    ?assertEqual(?DNS_TYPE_CNAME, RR2#dns_rr.type),
    ?assertMatch(#dns_rrdata_cname{dname = CName2}, RR2#dns_rr.data),
    ?assertEqual(CName2, RR3#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR3#dns_rr.type),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR3#dns_rr.data).

%% Test NS records with name compression
encode_name_compression_with_ns_records(_) ->
    ZoneName = <<"example.com">>,
    NSRecords = [
        #dns_rr{
            name = ZoneName,
            type = ?DNS_TYPE_NS,
            ttl = 3600,
            data = #dns_rrdata_ns{dname = <<"ns", (integer_to_binary(I))/binary, ".example.com">>}
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        auc = 5,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_NS}],
        authority = NSRecords
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(5, length(Decoded#dns_message.authority)),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test MX records with name compression
encode_name_compression_with_mx_records(_) ->
    DomainName = <<"example.com">>,
    MXRecords = [
        #dns_rr{
            name = DomainName,
            type = ?DNS_TYPE_MX,
            ttl = 3600,
            data = #dns_rrdata_mx{
                preference = I * 10,
                exchange = <<"mx", (integer_to_binary(I))/binary, ".example.com">>
            }
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 5,
        questions = [#dns_query{name = DomainName, type = ?DNS_TYPE_MX}],
        answers = MXRecords
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(5, length(Decoded#dns_message.answers)),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test SOA record with name compression
encode_name_compression_with_soa_record(_) ->
    ZoneName = <<"example.com">>,
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns1.example.com">>,
            rname = <<"admin.example.com">>,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_SOA}],
        authority = [SOA]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(1, length(Decoded#dns_message.authority)),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test SRV records with name compression
encode_name_compression_with_srv_records(_) ->
    ServiceName = <<"_http._tcp.example.com">>,
    SRVRecords = [
        #dns_rr{
            name = ServiceName,
            type = ?DNS_TYPE_SRV,
            ttl = 3600,
            data = #dns_rrdata_srv{
                priority = 10,
                weight = I,
                port = 80 + I,
                target = <<"server", (integer_to_binary(I))/binary, ".example.com">>
            }
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 5,
        questions = [#dns_query{name = ServiceName, type = ?DNS_TYPE_SRV}],
        answers = SRVRecords
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(5, length(Decoded#dns_message.answers)),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test PTR records with name compression
encode_name_compression_with_ptr_records(_) ->
    PtrName = <<"1.0.0.127.in-addr.arpa">>,
    PTRRecords = [
        #dns_rr{
            name = PtrName,
            type = ?DNS_TYPE_PTR,
            ttl = 3600,
            data = #dns_rrdata_ptr{
                dname = <<"host", (integer_to_binary(I))/binary, ".example.com">>
            }
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 5,
        questions = [#dns_query{name = PtrName, type = ?DNS_TYPE_PTR}],
        answers = PTRRecords
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(5, length(Decoded#dns_message.answers)),
    Encoded2 = dns:encode_message(Decoded),
    ?assertEqual(Encoded, Encoded2).

%% Test TXT records with name compression
encode_name_compression_with_txt_records(_) ->
    DomainName = <<"example.com">>,
    TXTRecords = [
        #dns_rr{
            name = DomainName,
            type = ?DNS_TYPE_TXT,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [<<"text", (integer_to_binary(I))/binary>>]}
        }
     || I <- lists:seq(1, 5)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 5,
        questions = [#dns_query{name = DomainName, type = ?DNS_TYPE_TXT}],
        answers = TXTRecords
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(5, length(Decoded#dns_message.answers)),
    %% Verify round-trip: decoded message should match original
    ?assertEqual(Msg, Decoded).

%% Test name compression across multiple sections (questions, answers, authority, additional)
encode_name_compression_with_multiple_sections(_) ->
    DomainName = <<"example.com">>,
    Questions = [#dns_query{name = DomainName, type = ?DNS_TYPE_A}],
    Answers = [
        #dns_rr{
            name = DomainName,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 0, 2, I}}
        }
     || I <- lists:seq(1, 3)
    ],
    Authority = [
        #dns_rr{
            name = DomainName,
            type = ?DNS_TYPE_NS,
            ttl = 3600,
            data = #dns_rrdata_ns{
                dname = <<"ns", (integer_to_binary(I))/binary, ".", DomainName/binary>>
            }
        }
     || I <- lists:seq(1, 2)
    ],
    Additional = [
        #dns_rr{
            name = <<"ns", (integer_to_binary(I))/binary, ".", DomainName/binary>>,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {192, 0, 2, 10 + I}}
        }
     || I <- lists:seq(1, 2)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 3,
        auc = 2,
        adc = 2,
        questions = Questions,
        answers = Answers,
        authority = Authority,
        additional = Additional
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(1, length(Decoded#dns_message.questions)),
    ?assertEqual(3, length(Decoded#dns_message.answers)),
    ?assertEqual(2, length(Decoded#dns_message.authority)),
    ?assertEqual(2, length(Decoded#dns_message.additional)),
    %% Verify questions
    [Q] = Decoded#dns_message.questions,
    ?assertEqual(DomainName, Q#dns_query.name),
    %% Verify answers
    lists:foreach(
        fun(I) ->
            RR = lists:nth(I, Decoded#dns_message.answers),
            ?assertEqual(DomainName, RR#dns_rr.name),
            ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
            ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, I}}, RR#dns_rr.data)
        end,
        lists:seq(1, 3)
    ),
    %% Verify authority
    lists:foreach(
        fun(I) ->
            RR = lists:nth(I, Decoded#dns_message.authority),
            ?assertEqual(DomainName, RR#dns_rr.name),
            ?assertEqual(?DNS_TYPE_NS, RR#dns_rr.type),
            ExpectedDName = <<"ns", (integer_to_binary(I))/binary, ".", DomainName/binary>>,
            ?assertMatch(#dns_rrdata_ns{dname = ExpectedDName}, RR#dns_rr.data)
        end,
        lists:seq(1, 2)
    ),
    %% Verify additional
    lists:foreach(
        fun(I) ->
            RR = lists:nth(I, Decoded#dns_message.additional),
            ExpectedName = <<"ns", (integer_to_binary(I))/binary, ".", DomainName/binary>>,
            ExpectedIP = {192, 0, 2, 10 + I},
            ?assertEqual(ExpectedName, RR#dns_rr.name),
            ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
            ?assertMatch(#dns_rrdata_a{ip = ExpectedIP}, RR#dns_rr.data)
        end,
        lists:seq(1, 2)
    ).

%%%===================================================================
%%% Regression tests for name compression bugs
%%%===================================================================

%% Regression: SOA record where rname should compress to mname
%% This tests that when encoding rname after mname in SOA, the compression
%% map is correctly updated and rname can reference mname if they share suffixes
encode_soa_rname_compresses_to_mname(_) ->
    ZoneName = <<"example.com">>,
    MName = <<"ns1.example.com">>,
    RName = <<"admin.example.com">>,
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = MName,
            rname = RName,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_SOA}],
        authority = [SOA]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(1, length(Decoded#dns_message.authority)),
    [DecodedSOA] = Decoded#dns_message.authority,
    ?assertEqual(ZoneName, DecodedSOA#dns_rr.name),
    ?assertEqual(?DNS_TYPE_SOA, DecodedSOA#dns_rr.type),
    #dns_rrdata_soa{
        mname = DecodedMName,
        rname = DecodedRName
    } = DecodedSOA#dns_rr.data,
    %% Both names should decode correctly
    ?assertEqual(MName, DecodedMName),
    ?assertEqual(RName, DecodedRName),
    %% Verify round-trip
    ?assertEqual(Msg, Decoded).

%% Regression: SOA record where both mname and rname should compress to question name
%% This tests compression across sections (question -> authority RR data)
encode_soa_both_names_compress_to_question(_) ->
    ZoneName = <<"example.com">>,
    MName = <<"ns1.example.com">>,
    RName = <<"admin.example.com">>,
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = MName,
            rname = RName,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_SOA}],
        authority = [SOA]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    %% Verify the encoded message can be decoded without errors
    ?assertMatch(#dns_message{}, Decoded).

%% Regression: Position tracking when encoding SOA with multiple domain names
%% This ensures that positions are calculated relative to message start, not fragment start
encode_soa_position_tracking_correct(_) ->
    ZoneName = <<"example.com">>,
    %% Use names that share common suffixes to test compression
    MName = <<"ns1.example.com">>,
    RName = <<"admin.example.com">>,
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = MName,
            rname = RName,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_SOA}],
        authority = [SOA]
    },
    Encoded = dns:encode_message(Msg),
    %% Decode and verify no compression pointer errors (like bad_pointer)
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    %% Verify compression pointers are within valid range (0-16383)
    %% by checking the encoded binary doesn't contain invalid pointers
    %% A compression pointer is: 11xxxxxx xxxxxxxx where xxxxxxxx xxxxxxxx < 16384
    %% Invalid would be >= 16384, which would be >= 0xC000
    %% We verify by ensuring decode succeeds
    ?assertMatch(#dns_message{}, Decoded).

%% Regression: MX record where exchange should compress to record name
encode_mx_exchange_compresses_to_name(_) ->
    DomainName = <<"example.com">>,
    Exchange = <<"mail.example.com">>,
    MX = #dns_rr{
        name = DomainName,
        type = ?DNS_TYPE_MX,
        ttl = 3600,
        data = #dns_rrdata_mx{
            preference = 10,
            exchange = Exchange
        }
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = DomainName, type = ?DNS_TYPE_MX}],
        answers = [MX]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    [DecodedMX] = Decoded#dns_message.answers,
    #dns_rrdata_mx{exchange = DecodedExchange} = DecodedMX#dns_rr.data,
    ?assertEqual(Exchange, DecodedExchange).

%% Regression: NS record where dname should compress to record name
encode_ns_dname_compresses_to_name(_) ->
    ZoneName = <<"example.com">>,
    NSDName = <<"ns1.example.com">>,
    NS = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = NSDName}
    },
    Msg = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_NS}],
        authority = [NS]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    [DecodedNS] = Decoded#dns_message.authority,
    #dns_rrdata_ns{dname = DecodedDName} = DecodedNS#dns_rr.data,
    ?assertEqual(NSDName, DecodedDName).

%% Regression: SRV record where target should compress to record name
encode_srv_target_compresses_to_name(_) ->
    ServiceName = <<"_http._tcp.example.com">>,
    Target = <<"server.example.com">>,
    SRV = #dns_rr{
        name = ServiceName,
        type = ?DNS_TYPE_SRV,
        ttl = 3600,
        data = #dns_rrdata_srv{
            priority = 10,
            weight = 5,
            port = 80,
            target = Target
        }
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = ServiceName, type = ?DNS_TYPE_SRV}],
        answers = [SRV]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    [DecodedSRV] = Decoded#dns_message.answers,
    #dns_rrdata_srv{target = DecodedTarget} = DecodedSRV#dns_rr.data,
    ?assertEqual(Target, DecodedTarget).

%% Regression: PTR record where dname should compress
encode_ptr_dname_compresses_to_name(_) ->
    PtrName = <<"1.0.0.127.in-addr.arpa">>,
    DName = <<"host.example.com">>,
    PTR = #dns_rr{
        name = PtrName,
        type = ?DNS_TYPE_PTR,
        ttl = 3600,
        data = #dns_rrdata_ptr{dname = DName}
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = PtrName, type = ?DNS_TYPE_PTR}],
        answers = [PTR]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    [DecodedPTR] = Decoded#dns_message.answers,
    #dns_rrdata_ptr{dname = DecodedDName} = DecodedPTR#dns_rr.data,
    ?assertEqual(DName, DecodedDName).

%% Regression: CNAME record where dname should compress to record name
encode_cname_dname_compresses_to_name(_) ->
    BaseName = <<"www.example.com">>,
    CNameTarget = <<"cname.example.com">>,
    CNAME = #dns_rr{
        name = BaseName,
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{dname = CNameTarget}
    },
    Msg = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = BaseName, type = ?DNS_TYPE_CNAME}],
        answers = [CNAME]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    [DecodedCNAME] = Decoded#dns_message.answers,
    #dns_rrdata_cname{dname = DecodedDName} = DecodedCNAME#dns_rr.data,
    ?assertEqual(CNameTarget, DecodedDName).

%% Regression: Compression pointers must be within valid range (0-16383)
%% This test ensures compression pointers are never >= 16384 (0xC000)
encode_compression_pointer_valid_range(_) ->
    %% Create a message with many records to test compression pointer calculation
    QName = <<"example.com">>,
    Answers = [
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_A,
            ttl = 3600,
            data = #dns_rrdata_a{ip = {127, 0, 0, I}}
        }
     || I <- lists:seq(1, 50)
    ],
    Msg = #dns_message{
        qc = 1,
        anc = 50,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        answers = Answers
    },
    Encoded = dns:encode_message(Msg),
    %% Decode should succeed without bad_pointer errors
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    %% Verify all answers decoded correctly
    ?assertEqual(50, length(Decoded#dns_message.answers)).

%% Regression: Multiple SOA records with compression
%% This tests that compression map is correctly maintained across multiple SOA records
encode_multiple_soa_records_compression(_) ->
    Zone1 = <<"zone1.example.com">>,
    Zone2 = <<"zone2.example.com">>,
    SOA1 = #dns_rr{
        name = Zone1,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns1.example.com">>,
            rname = <<"admin.example.com">>,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    SOA2 = #dns_rr{
        name = Zone2,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns2.example.com">>,
            rname = <<"admin.example.com">>,
            serial = 2024010102,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        }
    },
    Msg = #dns_message{
        qc = 2,
        auc = 2,
        questions = [
            #dns_query{name = Zone1, type = ?DNS_TYPE_SOA},
            #dns_query{name = Zone2, type = ?DNS_TYPE_SOA}
        ],
        authority = [SOA1, SOA2]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(2, length(Decoded#dns_message.authority)),
    %% Verify round-trip
    ?assertEqual(Msg, Decoded).

split_binary_into_chunks(Bin, Chunk) ->
    List = binary_to_list(Bin),
    [iolist_to_binary(lists:sublist(List, X, Chunk)) || X <- lists:seq(1, length(List), Chunk)].
