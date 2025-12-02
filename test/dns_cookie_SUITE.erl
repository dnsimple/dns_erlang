-module(dns_cookie_SUITE).
%%% EDNS Cookie Tests - RFC 7873 https://datatracker.ietf.org/doc/html/rfc7873#section-4

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
            {group, encode},
            {group, cookies},
            {group, invalid},
            {group, boundaries}
        ]},
        {encode, [parallel], [
            encode_decode_client_msg,
            encode_decode_server_msg,
            error_encode_too_small,
            error_encode_bad_msg,
            direct_decode_encode_client_only,
            direct_decode_encode_client_server,
            multiple_cookies,
            realistic_cookie,
            random_cookie
        ]},
        {cookies, [parallel], [
            client_only_cookie,
            client_server_cookie_8b,
            client_server_cookie_9b,
            client_server_cookie_16b,
            client_server_cookie_24b,
            client_server_cookie_32b
        ]},
        {invalid, [parallel], [
            client_too_small,
            client_too_large,
            server_too_small,
            server_too_large,
            no_client_field,
            malformed_wire_cookie_no_data,
            malformed_wire_cookie_insufficient_data
        ]},
        {boundaries, [parallel], [
            boundary_server_cookie_minimum,
            boundary_server_cookie_maximum,
            boundary_server_cookie_invalid_too_small,
            boundary_server_cookie_invalid_too_large
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    ok.

encode_decode_client_msg(_) ->
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, adc = 1, questions = [Query]},
    ClientMsg = Msg#dns_message{
        additional = [#dns_optrr{data = [#dns_opt_cookie{client = <<"abcdefgh">>}]}]
    },
    ?assertEqual(ClientMsg, dns:decode_message(dns:encode_message(ClientMsg))).

encode_decode_server_msg(_) ->
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, adc = 1, questions = [Query]},
    ServerMsg = Msg#dns_message{
        additional = [
            #dns_optrr{
                data = [#dns_opt_cookie{client = <<"abcdefgh">>, server = <<"ijklmnopqrs">>}]
            }
        ]
    },
    ?assertEqual(ServerMsg, dns:decode_message(dns:encode_message(ServerMsg))).

error_encode_too_small(_) ->
    %% Msg as above but client cookie set to <<"small">>
    TooSmallCookie =
        <<66, 248, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111,
            109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 9, 0, 10, 0, 5, 115, 109, 97, 108,
            108>>,
    ?assertError(bad_cookie, dns:decode_message(TooSmallCookie)).

error_encode_bad_msg(_) ->
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, adc = 1, questions = [Query]},
    BadMsg = Msg#dns_message{
        additional = [#dns_optrr{data = [#dns_opt_cookie{server = <<"ijklmnopqrs">>}]}]
    },
    ?assertError(bad_cookie, dns:decode_message(dns:encode_message(BadMsg))).

%% Test direct decode/encode functions
direct_decode_encode_client_only(_) ->
    % Test client-only cookie
    ClientCookie = <<"abcdefgh">>,
    Encoded = dns_encode:encode_optrrdata([#dns_opt_cookie{client = ClientCookie}]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),
    ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
    ?assertEqual(undefined, Decoded#dns_opt_cookie.server).

direct_decode_encode_client_server(_) ->
    % Test client+server cookie
    ClientCookie = <<"12345678">>,
    ServerCookie = <<"serverdata123">>,
    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    Encoded = dns_encode:encode_optrrdata([Cookie]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),
    ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
    ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server).

%% Test multiple cookies in the same message (should work)
multiple_cookies(_) ->
    Cookie1 = #dns_opt_cookie{client = <<"client01">>},
    Cookie2 = #dns_opt_cookie{
        client = <<"client02">>,
        server = <<"server02data">>
    },
    OptRR = #dns_optrr{data = [Cookie1, Cookie2]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedCookie1, DecodedCookie2] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(<<"client01">>, DecodedCookie1#dns_opt_cookie.client),
    ?assertEqual(undefined, DecodedCookie1#dns_opt_cookie.server),
    ?assertEqual(<<"client02">>, DecodedCookie2#dns_opt_cookie.client),
    ?assertEqual(<<"server02data">>, DecodedCookie2#dns_opt_cookie.server).

%% Test valid client-only cookie (8 bytes)
client_only_cookie(_) ->
    ClientCookie = <<"12345678">>,
    Cookie = #dns_opt_cookie{client = ClientCookie},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    % Test that we can decode what we encode
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedCookie] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(8, byte_size(ClientCookie)),
    ?assertEqual(ClientCookie, Cookie#dns_opt_cookie.client),
    ?assertEqual(undefined, Cookie#dns_opt_cookie.server),
    ?assertEqual(Msg, dns:decode_message(dns:encode_message(Msg))),
    ?assertEqual(ClientCookie, DecodedCookie#dns_opt_cookie.client),
    ?assertEqual(undefined, DecodedCookie#dns_opt_cookie.server).

%% Test valid client + server cookie (8 + 8-32 bytes)
client_server_cookie_8b(_) ->
    ServerCookie = <<"12345678">>,
    client_server_cookie(?FUNCTION_NAME, ServerCookie).
client_server_cookie_9b(_) ->
    ServerCookie = <<"123456789">>,
    client_server_cookie(?FUNCTION_NAME, ServerCookie).
client_server_cookie_16b(_) ->
    ServerCookie = <<"1234567890123456">>,
    client_server_cookie(?FUNCTION_NAME, ServerCookie).
client_server_cookie_24b(_) ->
    ServerCookie = <<"123456789012345678901234">>,
    client_server_cookie(?FUNCTION_NAME, ServerCookie).
client_server_cookie_32b(_) ->
    ServerCookie = <<"12345678901234567890123456789012">>,
    client_server_cookie(?FUNCTION_NAME, ServerCookie).

client_server_cookie(TestCase, ServerCookie) ->
    ClientCookie = <<"abcdefgh">>,
    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ServerSize = byte_size(ServerCookie),
    ?assert(ServerSize >= 8),
    ?assert(ServerSize =< 32),
    ?assertEqual(ClientCookie, Cookie#dns_opt_cookie.client, TestCase),
    ?assertEqual(ServerCookie, Cookie#dns_opt_cookie.server, TestCase),

    % Test round-trip encoding/decoding
    Encoded = dns:encode_message(Msg),
    Decoded = dns:decode_message(Encoded),
    ?assertEqual(Msg, Decoded),

    % Verify decoded cookie fields
    [DecodedOptRR] = Decoded#dns_message.additional,
    [DecodedCookie] = DecodedOptRR#dns_optrr.data,
    ?assertEqual(ClientCookie, DecodedCookie#dns_opt_cookie.client, TestCase),
    ?assertEqual(ServerCookie, DecodedCookie#dns_opt_cookie.server, TestCase).

client_too_small(_) ->
    % Client cookie too small (< 8 bytes)
    Cookie = #dns_opt_cookie{client = <<"small">>},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertError(bad_cookie, dns:encode_message(Msg)).

client_too_large(_) ->
    % Client cookie too large (> 8 bytes)
    Cookie = #dns_opt_cookie{client = <<"toolarge123">>},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertError(bad_cookie, dns:encode_message(Msg)).

server_too_small(_) ->
    % Server cookie too small (< 8 bytes)
    Cookie = #dns_opt_cookie{
        client = <<"12345678">>,
        server = <<"small">>
    },
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertError(bad_cookie, dns:encode_message(Msg)).

server_too_large(_) ->
    % Server cookie too large (> 32 bytes)
    Cookie = #dns_opt_cookie{
        client = <<"12345678">>,
        % 33 bytes
        server = <<"123456789012345678901234567890123">>
    },
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertError(bad_cookie, dns:encode_message(Msg)).

no_client_field(_) ->
    % Cookie with no client field
    Cookie = #dns_opt_cookie{server = <<"12345678">>},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    ?assertError(bad_cookie, dns:encode_message(Msg)).

malformed_wire_cookie_no_data(_) ->
    % Manually craft a malformed cookie with empty data
    BadBin = <<
        % ID
        0,
        0,
        % QR=0, Opcode=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
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
        % UDP payload size: 4096
        16,
        0,
        % Extended RCODE
        0,
        % Version
        0,
        % Flags
        0,
        0,
        % RDATA length: 4
        0,
        4,
        % Option code: COOKIE (10)
        0,
        10,
        % Option length: 0 (invalid!)
        0,
        0
    >>,
    ?assertError(bad_cookie, dns:decode_message(BadBin)).

malformed_wire_cookie_insufficient_data(_) ->
    BadBin = <<
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
        9,
        % Option code: COOKIE (10)
        0,
        10,
        % Option length: 5
        0,
        5,
        % 5 bytes (invalid!)
        "small"
    >>,
    ?assertError(bad_cookie, dns:decode_message(BadBin)).

boundary_server_cookie_minimum(_) ->
    boundary_server_cookie_test_valid(?FUNCTION_NAME, <<"12345678">>).

boundary_server_cookie_maximum(_) ->
    boundary_server_cookie_test_valid(?FUNCTION_NAME, <<"12345678901234567890123456789012">>).

boundary_server_cookie_invalid_too_small(_) ->
    boundary_server_cookie_test_invalid(?FUNCTION_NAME, <<"1234567">>).

boundary_server_cookie_invalid_too_large(_) ->
    boundary_server_cookie_test_invalid(?FUNCTION_NAME, <<"123456789012345678901234567890123">>).

%% Test boundary conditions for server cookie length
boundary_server_cookie_test_valid(TestCase, ServerCookie) ->
    ClientCookie = <<"12345678">>,
    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    % Should encode successfully
    Encoded = dns_encode:encode_optrrdata([Cookie]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),
    ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client, TestCase),
    ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server, TestCase).

boundary_server_cookie_test_invalid(TestCase, ServerCookie) ->
    ClientCookie = <<"12345678">>,
    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    ?assertError(bad_cookie, dns_encode:encode_optrrdata([Cookie]), TestCase).

%% Test with real-world cookie data (hex values)
realistic_cookie(_) ->
    % Use realistic hex-like cookie values
    ClientCookie = <<16#01, 16#23, 16#45, 16#67, 16#89, 16#AB, 16#CD, 16#EF>>,
    ServerCookie =
        <<16#FE, 16#DC, 16#BA, 16#98, 16#76, 16#54, 16#32, 16#10, 16#00, 16#11, 16#22, 16#33, 16#44,
            16#55, 16#66, 16#77>>,

    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    Encoded = dns_encode:encode_optrrdata([Cookie]),
    [Decoded] = dns_decode:decode_optrrdata(Encoded),

    ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
    ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server),
    ?assertEqual(8, byte_size(Decoded#dns_opt_cookie.client)),
    ?assertEqual(16, byte_size(Decoded#dns_opt_cookie.server)).

%% Performance test with random cookies
random_cookie(_) ->
    % Generate random client and server cookies
    ClientCookie = crypto:strong_rand_bytes(8),
    % Use 16-byte server cookie
    ServerCookie = crypto:strong_rand_bytes(16),
    Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
    OptRR = #dns_optrr{data = [Cookie]},
    Query = #dns_query{name = <<"test.example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{
        qc = 1,
        adc = 1,
        questions = [Query],
        additional = [OptRR]
    },
    % Test multiple iterations
    lists:foreach(
        fun(_) ->
            Encoded = dns:encode_message(Msg),
            Decoded = dns:decode_message(Encoded),
            ?assertEqual(Msg, Decoded)
        end,
        lists:seq(1, 10)
    ).
