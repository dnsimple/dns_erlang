-module(dns_cookie_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%%%===================================================================
%%% EDNS Cookie Tests - RFC 7873 https://datatracker.ietf.org/doc/html/rfc7873#section-4
%%%===================================================================

edns_cookie_test_() ->
    Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, adc = 1, questions = [Query]},
    ClientMsg = Msg#dns_message{
        additional = [#dns_optrr{data = [#dns_opt_cookie{client = <<"abcdefgh">>}]}]
    },
    ServerMsg = Msg#dns_message{
        additional = [
            #dns_optrr{
                data = [#dns_opt_cookie{client = <<"abcdefgh">>, server = <<"ijklmnopqrs">>}]
            }
        ]
    },
    BadMsg = Msg#dns_message{
        additional = [#dns_optrr{data = [#dns_opt_cookie{server = <<"ijklmnopqrs">>}]}]
    },
    %% Msg as above but client cookie set to <<"small">>
    TooSmallCookie =
        <<66, 248, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111,
            109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 9, 0, 10, 0, 5, 115, 109, 97, 108,
            108>>,
    [
        ?_assertEqual(ClientMsg, dns:decode_message(dns:encode_message(ClientMsg))),
        ?_assertEqual(ServerMsg, dns:decode_message(dns:encode_message(ServerMsg))),
        ?_assertError(bad_cookie, dns:decode_message(TooSmallCookie)),
        ?_assertError(bad_cookie, dns:decode_message(dns:encode_message(BadMsg)))
    ].

%% Test valid client-only cookie (8 bytes)
client_only_cookie_test_() ->
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
    [
        ?_assertEqual(8, byte_size(ClientCookie)),
        ?_assertEqual(ClientCookie, Cookie#dns_opt_cookie.client),
        ?_assertEqual(undefined, Cookie#dns_opt_cookie.server),
        ?_assertEqual(Msg, dns:decode_message(dns:encode_message(Msg))),
        ?_test(begin
            % Test that we can decode what we encode
            Encoded = dns:encode_message(Msg),
            Decoded = dns:decode_message(Encoded),
            [DecodedOptRR] = Decoded#dns_message.additional,
            [DecodedCookie] = DecodedOptRR#dns_optrr.data,
            ?assertEqual(ClientCookie, DecodedCookie#dns_opt_cookie.client),
            ?assertEqual(undefined, DecodedCookie#dns_opt_cookie.server)
        end)
    ].

%% Test valid client + server cookie (8 + 8-32 bytes)
client_server_cookie_test_() ->
    ClientCookie = <<"abcdefgh">>,

    % Test all valid server cookie lengths (8-32 bytes)
    ServerCookies = [
        % 8 bytes (minimum)
        <<"12345678">>,
        % 9 bytes
        <<"123456789">>,
        % 16 bytes
        <<"1234567890123456">>,
        % 24 bytes
        <<"123456789012345678901234">>,
        % 32 bytes (maximum)
        <<"12345678901234567890123456789012">>
    ],

    Tests = lists:map(
        fun(ServerCookie) ->
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
            TestName = io_lib:format("server_cookie_~p_bytes", [ServerSize]),

            {
                lists:flatten(TestName),
                ?_test(begin
                    ?assert(ServerSize >= 8),
                    ?assert(ServerSize =< 32),
                    ?assertEqual(ClientCookie, Cookie#dns_opt_cookie.client),
                    ?assertEqual(ServerCookie, Cookie#dns_opt_cookie.server),

                    % Test round-trip encoding/decoding
                    Encoded = dns:encode_message(Msg),
                    Decoded = dns:decode_message(Encoded),
                    ?assertEqual(Msg, Decoded),

                    % Verify decoded cookie fields
                    [DecodedOptRR] = Decoded#dns_message.additional,
                    [DecodedCookie] = DecodedOptRR#dns_optrr.data,
                    ?assertEqual(ClientCookie, DecodedCookie#dns_opt_cookie.client),
                    ?assertEqual(ServerCookie, DecodedCookie#dns_opt_cookie.server)
                end)
            }
        end,
        ServerCookies
    ),

    Tests.

%% Test invalid cookie formats
invalid_cookie_test_() ->
    [
        % Client cookie too small (< 8 bytes)
        ?_test(begin
            Cookie = #dns_opt_cookie{client = <<"small">>},
            OptRR = #dns_optrr{data = [Cookie]},
            Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
            Msg = #dns_message{
                qc = 1,
                adc = 1,
                questions = [Query],
                additional = [OptRR]
            },
            ?assertError(bad_cookie, dns:encode_message(Msg))
        end),

        % Client cookie too large (> 8 bytes)
        ?_test(begin
            Cookie = #dns_opt_cookie{client = <<"toolarge123">>},
            OptRR = #dns_optrr{data = [Cookie]},
            Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
            Msg = #dns_message{
                qc = 1,
                adc = 1,
                questions = [Query],
                additional = [OptRR]
            },
            ?assertError(bad_cookie, dns:encode_message(Msg))
        end),

        % Server cookie too small (< 8 bytes)
        ?_test(begin
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
            ?assertError(bad_cookie, dns:encode_message(Msg))
        end),

        % Server cookie too large (> 32 bytes)
        ?_test(begin
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
            ?assertError(bad_cookie, dns:encode_message(Msg))
        end),

        % Cookie with no client field
        ?_test(begin
            Cookie = #dns_opt_cookie{server = <<"12345678">>},
            OptRR = #dns_optrr{data = [Cookie]},
            Query = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
            Msg = #dns_message{
                qc = 1,
                adc = 1,
                questions = [Query],
                additional = [OptRR]
            },
            ?assertError(bad_cookie, dns:encode_message(Msg))
        end)
    ].

%% Test malformed wire format cookies
malformed_wire_cookie_test_() ->
    [
        % Cookie with no data (empty)
        ?_test(begin
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
            ?assertError(bad_cookie, dns:decode_message(BadBin))
        end),

        % Cookie with insufficient client data (< 8 bytes)
        ?_test(begin
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
            ?assertError(bad_cookie, dns:decode_message(BadBin))
        end)
    ].

%% Test direct decode/encode functions
direct_decode_encode_test_() ->
    [
        % Test client-only cookie
        ?_test(begin
            ClientCookie = <<"abcdefgh">>,
            Encoded = dns_encode:encode_optrrdata([#dns_opt_cookie{client = ClientCookie}]),
            [Decoded] = dns_decode:decode_optrrdata(Encoded),
            ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
            ?assertEqual(undefined, Decoded#dns_opt_cookie.server)
        end),

        % Test client+server cookie
        ?_test(begin
            ClientCookie = <<"12345678">>,
            ServerCookie = <<"serverdata123">>,
            Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
            Encoded = dns_encode:encode_optrrdata([Cookie]),
            [Decoded] = dns_decode:decode_optrrdata(Encoded),
            ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
            ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server)
        end)
    ].

%% Test boundary conditions for server cookie length
boundary_server_cookie_test_() ->
    ClientCookie = <<"12345678">>,

    % Test exact boundary cases
    BoundaryCases = [
        % Minimum valid
        {8, <<"12345678">>},
        % Maximum valid
        {32, <<"12345678901234567890123456789012">>}
    ],

    % Test just outside boundaries
    InvalidCases = [
        % Too small
        {7, <<"1234567">>},
        % Too large
        {33, <<"123456789012345678901234567890123">>}
    ],

    ValidTests = lists:map(
        fun({Size, ServerCookie}) ->
            TestName = io_lib:format("boundary_valid_~p_bytes", [Size]),
            Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},

            {
                lists:flatten(TestName),
                ?_test(begin
                    % Should encode successfully
                    Encoded = dns_encode:encode_optrrdata([Cookie]),
                    [Decoded] = dns_decode:decode_optrrdata(Encoded),
                    ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
                    ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server)
                end)
            }
        end,
        BoundaryCases
    ),

    InvalidTests = lists:map(
        fun({Size, ServerCookie}) ->
            TestName = io_lib:format("boundary_invalid_~p_bytes", [Size]),
            Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},

            {
                lists:flatten(TestName),
                ?_test(begin
                    % Should fail to encode
                    ?assertError(bad_cookie, dns_encode:encode_optrrdata([Cookie]))
                end)
            }
        end,
        InvalidCases
    ),

    ValidTests ++ InvalidTests.

%% Test multiple cookies in the same message (should work)
multiple_cookies_test_() ->
    [
        ?_test(begin
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

            % Should encode and decode successfully
            Encoded = dns:encode_message(Msg),
            Decoded = dns:decode_message(Encoded),

            [DecodedOptRR] = Decoded#dns_message.additional,
            [DecodedCookie1, DecodedCookie2] = DecodedOptRR#dns_optrr.data,

            ?assertEqual(<<"client01">>, DecodedCookie1#dns_opt_cookie.client),
            ?assertEqual(undefined, DecodedCookie1#dns_opt_cookie.server),
            ?assertEqual(<<"client02">>, DecodedCookie2#dns_opt_cookie.client),
            ?assertEqual(<<"server02data">>, DecodedCookie2#dns_opt_cookie.server)
        end)
    ].

%% Test with real-world cookie data (hex values)
realistic_cookie_test_() ->
    [
        ?_test(begin
            % Use realistic hex-like cookie values
            ClientCookie = <<16#01, 16#23, 16#45, 16#67, 16#89, 16#AB, 16#CD, 16#EF>>,
            ServerCookie =
                <<16#FE, 16#DC, 16#BA, 16#98, 16#76, 16#54, 16#32, 16#10, 16#00, 16#11, 16#22,
                    16#33, 16#44, 16#55, 16#66, 16#77>>,

            Cookie = #dns_opt_cookie{client = ClientCookie, server = ServerCookie},
            Encoded = dns_encode:encode_optrrdata([Cookie]),
            [Decoded] = dns_decode:decode_optrrdata(Encoded),

            ?assertEqual(ClientCookie, Decoded#dns_opt_cookie.client),
            ?assertEqual(ServerCookie, Decoded#dns_opt_cookie.server),
            ?assertEqual(8, byte_size(Decoded#dns_opt_cookie.client)),
            ?assertEqual(16, byte_size(Decoded#dns_opt_cookie.server))
        end)
    ].

%% Performance test with random cookies
random_cookie_test_() ->
    {setup, fun() -> application:start(crypto) end, fun(_) -> application:stop(crypto) end, [
        ?_test(begin
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
            )
        end)
    ]}.
