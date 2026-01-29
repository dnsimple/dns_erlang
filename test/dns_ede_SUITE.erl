-module(dns_ede_SUITE).
%%% EDNS Extended DNS Error Tests - RFC 8914 https://datatracker.ietf.org/doc/html/rfc8914
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
            basic_ede,
            ede_with_text,
            other_error,
            unsupported_dnskey_algorithm,
            dnssec_bogus,
            dnskey_missing,
            prohibited,
            not_ready,
            info_code_only,
            info_code_and_extra_text,
            empty_ede,
            multiple_ede,
            utf8_extra_text
        ]}
    ].

%% Test basic EDE with info_code only (no extra text)
basic_ede(_) ->
    InfoCode = 18,
    Ede = #dns_opt_ede{info_code = InfoCode},
    OptRR = #dns_optrr{data = [Ede]},
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertEqual(InfoCode, Ede#dns_opt_ede.info_code),
    ?assertEqual(<<>>, Ede#dns_opt_ede.extra_text),
    ?assertEqual(Msg, dns:decode_message(dns:encode_message(Msg))),
    % Test that we can decode what we encode
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedEde] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(InfoCode, DecodedEde#dns_opt_ede.info_code),
    ?assertEqual(<<>>, DecodedEde#dns_opt_ede.extra_text).

%% Test EDE with info_code and extra_text
ede_with_text(_) ->
    InfoCode = 18,
    % DNSSEC Bogus
    ExtraText = ~"signature too short",
    Ede = #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText},
    OptRR = #dns_optrr{data = [Ede]},
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertEqual(InfoCode, Ede#dns_opt_ede.info_code),
    ?assertEqual(ExtraText, Ede#dns_opt_ede.extra_text),
    ?assertEqual(Msg, dns:decode_message(dns:encode_message(Msg))),
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedEde] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(InfoCode, DecodedEde#dns_opt_ede.info_code),
    ?assertEqual(ExtraText, DecodedEde#dns_opt_ede.extra_text).

%% Test various EDE info codes from RFC 8914
other_error(Config) ->
    info_code_test(Config, 0, ~"Other Error").
unsupported_dnskey_algorithm(Config) ->
    info_code_test(Config, 1, ~"Unsupported DNSKEY Algorithm").
dnssec_bogus(Config) ->
    info_code_test(Config, 6, ~"DNSSEC Bogus").
dnskey_missing(Config) ->
    info_code_test(Config, 9, ~"DNSKEY Missing").
prohibited(Config) ->
    info_code_test(Config, 18, ~"Prohibited").
not_ready(Config) ->
    info_code_test(Config, 22, ~"Not Ready").

info_code_test(_Config, InfoCode, ExtraText) ->
    Ede = #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText},
    OptRR = #dns_optrr{data = [Ede]},
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    % Test round-trip encoding/decoding
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),
    % Verify decoded EDE fields
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedEde] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(InfoCode, DecodedEde#dns_opt_ede.info_code),
    ?assertEqual(ExtraText, DecodedEde#dns_opt_ede.extra_text).

info_code_only(_) ->
    InfoCode = 6,
    Ede = #dns_opt_ede{info_code = InfoCode},
    Encoded = dns_encode:encode_optrrdata([Ede]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),
    ?assertEqual(InfoCode, Decoded#dns_opt_ede.info_code),
    ?assertEqual(<<>>, Decoded#dns_opt_ede.extra_text).

info_code_and_extra_text(_) ->
    InfoCode = 18,
    ExtraText = ~"not authorized",
    Ede = #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText},
    Encoded = dns_encode:encode_optrrdata([Ede]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),
    ?assertEqual(InfoCode, Decoded#dns_opt_ede.info_code),
    ?assertEqual(ExtraText, Decoded#dns_opt_ede.extra_text).

%% Test empty EDE option (wire format)
empty_ede(_) ->
    % Manually craft an EDE with empty data
    EmptyEdeBin = <<
        % ID
        0,
        0,
        % Flags
        0,
        0,
        % Questions: 1
        0,
        1,
        % Answers: 0
        0,
        0,
        % Authority: 0
        0,
        0,
        % Additional: 1
        0,
        1,
        % Question name
        7,
        "example",
        3,
        "com",
        0,
        % Type: A
        0,
        1,
        % Class: IN
        0,
        1,
        % Root domain for OPT
        0,
        % Type: OPT
        0,
        41,
        % UDP payload size
        16,
        0,
        % Extended flags
        0,
        0,
        0,
        0,
        % RDATA length
        0,
        4,
        % Option code: EDE (15)
        0,
        15,
        % Option length: 0
        0,
        0
    >>,
    Decoded = dns:decode_message(EmptyEdeBin),
    [OptRR] = Decoded#dns_message.additional,
    [Ede] = OptRR#dns_optrr.data,
    ?assertEqual(0, Ede#dns_opt_ede.info_code),
    ?assertEqual(<<>>, Ede#dns_opt_ede.extra_text).

%% Test multiple EDE options in the same message
multiple_ede(_) ->
    Ede1 = #dns_opt_ede{info_code = 6, extra_text = ~"DNSSEC Bogus"},
    Ede2 = #dns_opt_ede{info_code = 9, extra_text = ~"Key missing"},
    OptRR = #dns_optrr{data = [Ede1, Ede2]},
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedEde1, DecodedEde2] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(6, DecodedEde1#dns_opt_ede.info_code),
    ?assertEqual(~"DNSSEC Bogus", DecodedEde1#dns_opt_ede.extra_text),
    ?assertEqual(9, DecodedEde2#dns_opt_ede.info_code),
    ?assertEqual(~"Key missing", DecodedEde2#dns_opt_ede.extra_text).

%% Test EDE with UTF-8 extra text
utf8_extra_text(_) ->
    InfoCode = 0,
    ExtraText = ~"Error: Validación falló",
    Ede = #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText},
    OptRR = #dns_optrr{data = [Ede]},
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedEde] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(InfoCode, DecodedEde#dns_opt_ede.info_code),
    ?assertEqual(ExtraText, DecodedEde#dns_opt_ede.extra_text).
