-module(dns_domain_SUITE).
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
            {group, split_tests},
            {group, join_tests},
            {group, escape_tests},
            {group, case_tests},
            {group, to_wire_tests},
            {group, from_wire_tests},
            {group, compression_tests},
            {group, reversibility_tests}
        ]},
        {split_tests, [parallel], [
            split_basic,
            split_empty_cases,
            split_escaped_chars,
            split_trailing_dots,
            split_boundaries,
            split_errors
        ]},
        {join_tests, [parallel], [
            join_basic,
            join_empty_cases,
            join_escaped_chars
        ]},
        {escape_tests, [parallel], [
            escape_label_iter_basic,
            escape_label_iter_edge_cases,
            unescape_label_basic,
            unescape_label_edge_cases,
            escape_unescape_roundtrip
        ]},
        {case_tests, [parallel], [
            to_lower_basic,
            to_lower_chunking,
            to_upper_basic,
            to_upper_chunking,
            case_roundtrip,
            case_conversion_comprehensive
        ]},
        {comparison_tests, [parallel], [
            are_equal_basic,
            are_equal_labels_basic
        ]},
        {to_wire_tests, [parallel], [
            to_wire_basic,
            to_wire_empty_cases,
            to_wire_boundaries,
            to_wire_errors
        ]},
        {from_wire_tests, [parallel], [
            from_wire_basic,
            from_wire_trailing_data,
            from_wire_boundaries,
            from_wire_chunked_escaping,
            from_wire_errors
        ]},
        {compression_tests, [parallel], [
            compression_encoding_basic,
            compression_encoding_multiple,
            compression_encoding_prior_only,
            compression_encoding_invalid_pointer,
            compression_encoding_position_limit,
            compression_encoding_case_insensitive,
            compression_encoding_errors,
            compression_decoding_basic,
            compression_decoding_nested,
            compression_decoding_chain,
            compression_decoding_first_label_pointer,
            compression_decoding_empty_after_pointer,
            compression_decoding_errors,
            compression_errors
        ]},
        {reversibility_tests, [parallel], [
            split_join_roundtrip,
            wire_roundtrip,
            wire_roundtrip_with_escapes
        ]}
    ].

%% ============================================================================
%% Split Tests
%% ============================================================================

split_basic(_) ->
    Cases = [
        {<<"example.com">>, [<<"example">>, <<"com">>]},
        {<<"www.example.com">>, [<<"www">>, <<"example">>, <<"com">>]},
        {<<"a.b.c">>, [<<"a">>, <<"b">>, <<"c">>]},
        {<<"a.b.c.d.e">>, [<<"a">>, <<"b">>, <<"c">>, <<"d">>, <<"e">>]},
        {<<"test">>, [<<"test">>]},
        {<<"singlelabel">>, [<<"singlelabel">>]}
    ],
    [?assertEqual(Expect, dns_domain:split(Input)) || {Input, Expect} <- Cases].

split_empty_cases(_) ->
    Cases = [
        {<<>>, []},
        {<<$.>>, []}
    ],
    [?assertEqual(Expect, dns_domain:split(Input)) || {Input, Expect} <- Cases].

split_escaped_chars(_) ->
    Cases = [
        {<<"escaped\\.dot.com">>, [<<"escaped.dot">>, <<"com">>]},
        {<<"back\\\\slash.com">>, [<<"back\\slash">>, <<"com">>]},
        {<<"a\\.b.c">>, [<<"a.b">>, <<"c">>]},
        {<<"a\\\\b.c">>, [<<"a\\b">>, <<"c">>]},
        {<<"a\\.b\\\\c.d">>, [<<"a.b\\c">>, <<"d">>]},
        {<<"mixed\\.dots\\\\and\\\\.backslashes">>, [<<"mixed.dots\\and\\">>, <<"backslashes">>]}
    ],
    [?assertEqual(Expect, dns_domain:split(Input)) || {Input, Expect} <- Cases].

split_trailing_dots(_) ->
    Cases = [
        {<<"example.com.">>, [<<"example">>, <<"com">>]},
        {<<"test.">>, [<<"test">>]}
    ],
    [?assertEqual(Expect, dns_domain:split(Input)) || {Input, Expect} <- Cases].

split_boundaries(_) ->
    %% Label at exactly 63 bytes (max) - should succeed
    Label63 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    Name63 = <<Label63/binary, ".com">>,
    Wire63 = dns_domain:to_wire(Name63),
    ?assertEqual(<<63, Label63/binary, 3, "com", 0>>, Wire63),
    ?assertEqual([Label63, <<"com">>], dns_domain:split(Name63)).

%% ============================================================================
%% Join Tests
%% ============================================================================

join_basic(_) ->
    SubDomains = [
        {[<<"example">>, <<"com">>], <<"example.com">>},
        {[<<"www">>, <<"example">>, <<"com">>], <<"www.example.com">>},
        {[<<"a">>, <<"b">>, <<"c">>], <<"a.b.c">>},
        {[<<"a">>, <<"b">>, <<"c">>, <<"d">>, <<"e">>], <<"a.b.c.d.e">>},
        {[<<"test">>], <<"test">>},
        {[<<"singlelabel">>], <<"singlelabel">>}
    ],
    [?assertEqual(Expect, dns_domain:join(Input, subdomain)) || {Input, Expect} <- SubDomains],
    Fqdns = [
        {[<<"example">>, <<"com">>], <<"example.com.">>},
        {[<<"www">>, <<"example">>, <<"com">>], <<"www.example.com.">>},
        {[<<"www">>, <<"example">>, <<"com.">>], <<"www.example.com\\..">>},
        {[<<"a">>, <<"b">>, <<"c">>], <<"a.b.c.">>},
        {[<<"a">>, <<"b">>, <<"c">>, <<"d">>, <<"e">>], <<"a.b.c.d.e.">>},
        {[<<"test">>], <<"test.">>},
        {[<<"singlelabel">>], <<"singlelabel.">>}
    ],
    [?assertEqual(Expect, dns_domain:join(Input, fqdn)) || {Input, Expect} <- Fqdns].

join_empty_cases(_) ->
    ?assertEqual(<<>>, dns_domain:join([], subdomain)),
    ?assertEqual(<<".">>, dns_domain:join([], fqdn)).

join_escaped_chars(_) ->
    Cases = [
        {[<<"test.label">>, <<"com">>], <<"test\\.label.com">>},
        {[<<"test\label">>, <<"com">>], <<"testlabel.com">>},
        {[<<"test\\label">>, <<"com">>], <<"test\\\\label.com">>},
        {[<<"a.b">>, <<"c">>], <<"a\\.b.c">>},
        {[<<"a\\">>, <<"b">>], <<"a\\\\.b">>},
        {[<<"a.b\\c">>], <<"a\\.b\\\\c">>},
        {[<<"a.b\\c.d">>], <<"a\\.b\\\\c\\.d">>}
    ],
    [?assertEqual(Expect, dns_domain:join(Input)) || {Input, Expect} <- Cases].

%% ============================================================================
%% Escape Tests
%% ============================================================================

escape_label_iter_basic(_) ->
    Cases = [
        {<<"normal">>, <<"normal">>},
        {<<"abc">>, <<"abc">>},
        {<<"test123">>, <<"test123">>},
        {<<"has.dot">>, <<"has\\.dot">>},
        {<<"has\\backslash">>, <<"has\\\\backslash">>},
        {<<"has.both\\here">>, <<"has\\.both\\\\here">>},
        {<<>>, <<>>},
        {<<"a">>, <<"a">>}
    ],
    [?assertEqual(Expect, dns_domain:escape_label(Input)) || {Input, Expect} <- Cases].

escape_label_iter_edge_cases(_) ->
    Cases = [
        {<<".">>, <<"\\.">>},
        {<<"\\">>, <<"\\\\">>},
        {<<".\\">>, <<"\\.\\\\">>},
        {<<"\\.">>, <<"\\\\\\.">>},
        {<<"a.b\\c">>, <<"a\\.b\\\\c">>}
    ],
    [?assertEqual(Expect, dns_domain:escape_label(Input)) || {Input, Expect} <- Cases].

unescape_label_basic(_) ->
    Cases = [
        {<<"normal">>, <<"normal">>},
        {<<"abc">>, <<"abc">>},
        {<<"test123">>, <<"test123">>},
        {<<"has\\.dot">>, <<"has.dot">>},
        {<<"has\\\\backslash">>, <<"has\\backslash">>},
        {<<"has\\.both\\\\here">>, <<"has.both\\here">>},
        {<<>>, <<>>},
        {<<"a">>, <<"a">>}
    ],
    [?assertEqual(Expect, dns_domain:unescape_label(Input)) || {Input, Expect} <- Cases].

unescape_label_edge_cases(_) ->
    Cases = [
        {<<"\\.">>, <<".">>},
        {<<"\\\\">>, <<"\\">>},
        {<<"\\.\\\\">>, <<".\\">>},
        {<<"\\\\\\.">>, <<"\\.">>},
        {<<"a\\.b\\\\c">>, <<"a.b\\c">>},
        {<<"test\123">>, <<"testS">>},
        {<<"t\\est">>, <<"t\\est">>},
        %% Multiple escapes
        {<<"test\\.label\\.here">>, <<"test.label.here">>},
        {<<"test\\\\label\\\\here">>, <<"test\\label\\here">>},
        {<<"mixed\\.dots\\\\and\\\\.backslashes">>, <<"mixed.dots\\and\\.backslashes">>}
    ],
    [?assertEqual(Expect, dns_domain:unescape_label(Input)) || {Input, Expect} <- Cases].

escape_unescape_roundtrip(_) ->
    %% Test that escape_label and unescape_label are inverses
    TestCases = [
        <<"normal">>,
        <<"abc">>,
        <<"test123">>,
        <<"has.dot">>,
        <<"has\\backslash">>,
        <<"has.both\\here">>,
        <<".">>,
        <<"\\">>,
        <<".\\">>,
        <<"\\.">>,
        <<"a.b\\c">>,
        <<>>,
        <<"a">>,
        <<"test.label.here">>,
        <<"test\\label\\here">>,
        <<"mixed.dots\\and\\.backslashes">>
    ],
    [
        begin
            Escaped = dns_domain:escape_label(Original),
            Unescaped = dns_domain:unescape_label(Escaped),
            ?assertEqual(Original, Unescaped, io_lib:format("Roundtrip failed for ~p", [Original]))
        end
     || Original <- TestCases
    ],
    %% Also test reverse: unescape then escape
    EscapedCases = [
        <<"test\\.label">>,
        <<"test\\\\label">>,
        <<"has\\.both\\\\here">>,
        <<"\\.">>,
        <<"\\\\">>
    ],
    [
        begin
            Unescaped = dns_domain:unescape_label(Escaped),
            ReEscaped = dns_domain:escape_label(Unescaped),
            ?assertEqual(
                Escaped, ReEscaped, io_lib:format("Reverse roundtrip failed for ~p", [Escaped])
            )
        end
     || Escaped <- EscapedCases
    ].

%% ============================================================================
%% Case Conversion Tests
%% ============================================================================

to_lower_basic(_) ->
    Cases = [
        {<<>>, <<>>},
        {<<"EXAMPLE.COM">>, <<"example.com">>},
        {<<"Example.Com">>, <<"example.com">>},
        {<<"example.com">>, <<"example.com">>},
        {<<"A">>, <<"a">>},
        {<<"Z">>, <<"z">>},
        {<<"a">>, <<"a">>},
        {<<"z">>, <<"z">>},
        {<<"123">>, <<"123">>},
        {<<"!@#$%">>, <<"!@#$%">>}
    ],
    [?assertEqual(Expect, dns_domain:to_lower(Input)) || {Input, Expect} <- Cases].

to_lower_chunking(_) ->
    %% Test all chunking sizes: 8, 7, 6, 5, 4, 3, 2, 1 bytes
    %% Clauses are checked in order, so we need sizes that match each specific clause
    %% Based on modulo analysis:
    %% - 8-byte clause: sizes where rem 8 = 0 (8, 16, 24, ...)
    %% - 7-byte clause: sizes where rem 7 = 0 but rem 8 != 0 (7, 14, 21, ...)
    %% - 6-byte clause: sizes where rem 6 = 0 but rem 8 != 0 and rem 7 != 0 (6, 18, 22, ...)
    %% - 5-byte clause: sizes where rem 5 = 0 but rem 8,7,6 != 0 (5, 15, 20, 25, ...)
    %% - 4-byte clause: sizes where rem 4 = 0 but rem 8,7,6,5 != 0 (4, 12, ...)
    %% - 3-byte clause: sizes where rem 3 = 0 but rem 8,7,6,5,4 != 0 (3, 9, ...)
    %% - 2-byte clause: sizes where rem 2 = 0 but rem 8,7,6,5,4,3 != 0 (2, ...)
    %% - 1-byte clause: fallback (1, 11, 13, 17, 19, 23, ...)
    Cases = [
        %% 8 bytes (rem 8 = 0) - matches 8-byte clause
        {<<"ABCDEFGH">>, <<"abcdefgh">>},
        {<<"ABCDEFGHIJKLMNOP">>, <<"abcdefghijklmnop">>},
        {<<"ABCDEFGHIJKLMNOPQRSTUVWX">>, <<"abcdefghijklmnopqrstuvwx">>},
        %% 7 bytes (rem 7 = 0, rem 8 != 0) - matches 7-byte clause
        {<<"ABCDEFG">>, <<"abcdefg">>},
        {<<"ABCDEFGHIJKLM">>, <<"abcdefghijklm">>},
        {<<"ABCDEFGHIJKLMNOPQRS">>, <<"abcdefghijklmnopqrs">>},
        %% 6 bytes (rem 6 = 0, rem 8 != 0, rem 7 != 0) - matches 6-byte clause
        %% 6: rem8=6, rem7=6, rem6=0 ✓
        {<<"ABCDEF">>, <<"abcdef">>},
        %% 18: rem8=2, rem7=4, rem6=0 ✓
        {<<"ABCDEFGHIJKLMNOPQR">>, <<"abcdefghijklmnopqr">>},
        %% 22: rem8=6, rem7=1, rem6=4, but wait - 22 rem 6 = 4, not 0
        %% Let me recalculate: 22 rem 6 = 4, so it won't match 6-byte clause
        %% Actually 18 is good, let's use that
        %% 6 bytes: 6, 18 (rem8=2, rem7=4, rem6=0), 30 (rem8=6, rem7=2, rem6=0)
        {<<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcd">>, <<"abcdefghijklmnopqrstuvwxyzabcd">>},
        %% 5 bytes (rem 5 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0) - matches 5-byte clause
        %% 5: rem8=5, rem7=5, rem6=5, rem5=0 ✓
        {<<"ABCDE">>, <<"abcde">>},
        %% 15: rem8=7, rem7=1, rem6=3, rem5=0 ✓
        {<<"ABCDEFGHIJKLMNO">>, <<"abcdefghijklmno">>},
        %% 20: rem8=4, rem7=6, rem6=2, rem5=0 ✓
        {<<"ABCDEFGHIJKLMNOPQRST">>, <<"abcdefghijklmnopqrst">>},
        %% 4 bytes (rem 4 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0)
        %% 4: rem8=4, rem7=4, rem6=4, rem5=4, rem4=0 ✓
        {<<"ABCD">>, <<"abcd">>},
        %% 12: rem8=4, rem7=5, rem6=0 - wait, 12 rem 6 = 0, so it matches 6-byte clause, not 4-byte
        %% Need a size divisible by 4 but not by 8,7,6,5: 4, 28 (rem8=4, rem7=0 - no), 32 (rem8=0 - no)
        %% Actually, 4 itself works, but for a longer one: 44? rem8=4, rem7=2, rem6=2, rem5=4, rem4=0 ✓
        {<<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl">>,
            <<"abcdefghijklmnopqrstuvwxyzabcdefghijkl">>},
        %% 3 bytes (rem 3 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0, rem 4 != 0)
        %% 3: rem8=3, rem7=3, rem6=3, rem5=3, rem4=3, rem3=0 ✓
        {<<"ABC">>, <<"abc">>},
        %% 9: rem8=1, rem7=2, rem6=3, rem5=4, rem4=1, rem3=0 ✓
        {<<"ABCDEFGHI">>, <<"abcdefghi">>},
        %% 2 bytes (rem 2 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0, rem 4 != 0, rem 3 != 0)
        %% 2: rem8=2, rem7=2, rem6=2, rem5=2, rem4=2, rem3=2, rem2=0 ✓
        {<<"AB">>, <<"ab">>},
        %% 1 byte (fallback - not divisible by any of the above)
        %% 1: all rem != 0 ✓
        {<<"A">>, <<"a">>},
        %% 11: rem8=3, rem7=4, rem6=5, rem5=1, rem4=3, rem3=2, rem2=1 ✓
        {<<"ABCDEFGHIJK">>, <<"abcdefghijk">>},
        %% 13: rem8=5, rem7=6, rem6=1, rem5=3, rem4=1, rem3=1, rem2=1 ✓
        {<<"ABCDEFGHIJKLM">>, <<"abcdefghijklm">>},
        %% 17: rem8=1, rem7=3, rem6=5, rem5=2, rem4=1, rem3=2, rem2=1 ✓
        {<<"ABCDEFGHIJKLMNOPQ">>, <<"abcdefghijklmnopq">>},
        %% 19: rem8=3, rem7=5, rem6=1, rem5=4, rem4=3, rem3=1, rem2=1 ✓
        {<<"ABCDEFGHIJKLMNOPQRS">>, <<"abcdefghijklmnopqrs">>},
        %% 23: rem8=7, rem7=2, rem6=5, rem5=3, rem4=3, rem3=2, rem2=1 ✓
        {<<"ABCDEFGHIJKLMNOPQRSTUVW">>, <<"abcdefghijklmnopqrstuvw">>},
        %% Mixed case with chunking
        {<<"EXAMPLE.COM">>, <<"example.com">>},
        {<<"WWW.EXAMPLE.COM">>, <<"www.example.com">>}
    ],
    [?assertEqual(Expect, dns_domain:to_lower(Input)) || {Input, Expect} <- Cases].

to_upper_basic(_) ->
    Cases = [
        {<<>>, <<>>},
        {<<"example.com">>, <<"EXAMPLE.COM">>},
        {<<"Example.Com">>, <<"EXAMPLE.COM">>},
        {<<"EXAMPLE.COM">>, <<"EXAMPLE.COM">>},
        {<<"a">>, <<"A">>},
        {<<"z">>, <<"Z">>},
        {<<"A">>, <<"A">>},
        {<<"Z">>, <<"Z">>},
        {<<"123">>, <<"123">>},
        {<<"!@#$%">>, <<"!@#$%">>}
    ],
    [?assertEqual(Expect, dns_domain:to_upper(Input)) || {Input, Expect} <- Cases].

to_upper_chunking(_) ->
    %% Test all chunking sizes: 8, 7, 6, 5, 4, 3, 2, 1 bytes
    %% Clauses are checked in order, so we need sizes that match each specific clause
    Cases = [
        %% 8 bytes (rem 8 = 0) - matches 8-byte clause
        {<<"abcdefgh">>, <<"ABCDEFGH">>},
        {<<"abcdefghijklmnop">>, <<"ABCDEFGHIJKLMNOP">>},
        {<<"abcdefghijklmnopqrstuvwx">>, <<"ABCDEFGHIJKLMNOPQRSTUVWX">>},
        %% 7 bytes (rem 7 = 0, rem 8 != 0) - matches 7-byte clause
        {<<"abcdefg">>, <<"ABCDEFG">>},
        {<<"abcdefghijklm">>, <<"ABCDEFGHIJKLM">>},
        {<<"abcdefghijklmnopqrs">>, <<"ABCDEFGHIJKLMNOPQRS">>},
        %% 6 bytes (rem 6 = 0, rem 8 != 0, rem 7 != 0) - matches 6-byte clause
        {<<"abcdef">>, <<"ABCDEF">>},
        {<<"abcdefghijklmnopqr">>, <<"ABCDEFGHIJKLMNOPQR">>},
        {<<"abcdefghijklmnopqrstuvwxyzabcd">>, <<"ABCDEFGHIJKLMNOPQRSTUVWXYZABCD">>},
        %% 5 bytes (rem 5 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0) - matches 5-byte clause
        {<<"abcde">>, <<"ABCDE">>},
        {<<"abcdefghijklmno">>, <<"ABCDEFGHIJKLMNO">>},
        {<<"abcdefghijklmnopqrst">>, <<"ABCDEFGHIJKLMNOPQRST">>},
        %% 4 bytes (rem 4 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0)
        {<<"abcd">>, <<"ABCD">>},
        {<<"abcdefghijklmnopqrstuvwxyzabcdefghijkl">>,
            <<"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL">>},
        %% 3 bytes (rem 3 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0, rem 4 != 0)
        {<<"abc">>, <<"ABC">>},
        {<<"abcdefghi">>, <<"ABCDEFGHI">>},
        %% 2 bytes (rem 2 = 0, rem 8 != 0, rem 7 != 0, rem 6 != 0, rem 5 != 0, rem 4 != 0, rem 3 != 0)
        {<<"ab">>, <<"AB">>},
        %% 1 byte (fallback - not divisible by any of the above)
        {<<"a">>, <<"A">>},
        {<<"abcdefghijk">>, <<"ABCDEFGHIJK">>},
        {<<"abcdefghijklmn">>, <<"ABCDEFGHIJKLMN">>},
        {<<"abcdefghijklmnopq">>, <<"ABCDEFGHIJKLMNOPQ">>},
        {<<"abcdefghijklmnopqrs">>, <<"ABCDEFGHIJKLMNOPQRS">>},
        {<<"abcdefghijklmnopqrstuvw">>, <<"ABCDEFGHIJKLMNOPQRSTUVW">>},
        %% Mixed case with chunking
        {<<"example.com">>, <<"EXAMPLE.COM">>},
        {<<"www.example.com">>, <<"WWW.EXAMPLE.COM">>}
    ],
    [?assertEqual(Expect, dns_domain:to_upper(Input)) || {Input, Expect} <- Cases].

case_roundtrip(_) ->
    %% Test that to_lower and to_upper are idempotent and roundtrip correctly
    Cases = [
        <<"EXAMPLE.COM">>,
        <<"example.com">>,
        <<"Example.Com">>,
        <<"WWW.EXAMPLE.COM">>,
        <<"www.example.com">>,
        <<"A.B.C.D.E">>
    ],
    [
        begin
            Lower = dns_domain:to_lower(Name),
            Upper = dns_domain:to_upper(Name),
            %% to_lower should be idempotent
            ?assertEqual(Lower, dns_domain:to_lower(Lower)),
            %% to_upper should be idempotent
            ?assertEqual(Upper, dns_domain:to_upper(Upper)),
            %% Roundtrip: to_upper(to_lower(X)) = to_upper(X)
            ?assertEqual(Upper, dns_domain:to_upper(Lower)),
            %% Roundtrip: to_lower(to_upper(X)) = to_lower(X)
            ?assertEqual(Lower, dns_domain:to_lower(Upper))
        end
     || Name <- Cases
    ].

case_conversion_comprehensive(_) ->
    ToUpperCases = [
        {<<"example.com">>, <<"EXAMPLE.COM">>},
        {<<"ExAmPle.CoM">>, <<"EXAMPLE.COM">>},
        {<<"www.example.com">>, <<"WWW.EXAMPLE.COM">>},
        {<<"test-1.example.com">>, <<"TEST-1.EXAMPLE.COM">>},
        {<<"escaped\\.dot.example.com">>, <<"ESCAPED\\.DOT.EXAMPLE.COM">>},
        {<<>>, <<>>},
        {<<"thisisaverylongsubdomainnamewithmanycharacters.example.com">>,
            <<"THISISAVERYLONGSUBDOMAINNAMEWITHMANYCHARACTERS.EXAMPLE.COM">>},
        {<<"ab">>, <<"AB">>},
        {<<"abcd">>, <<"ABCD">>},
        {<<"abcdef">>, <<"ABCDEF">>},
        {<<"abcdefgh">>, <<"ABCDEFGH">>},
        {<<"_srv._tcp.example.com">>, <<"_SRV._TCP.EXAMPLE.COM">>},
        {<<"ns1.dnsprovider.net">>, <<"NS1.DNSPROVIDER.NET">>}
    ],
    [
        ?assertEqual(Expected, dns_domain:to_upper(Input))
     || {Input, Expected} <- ToUpperCases
    ],
    ToLowerCases = [
        {<<"EXAMPLE.COM">>, <<"example.com">>},
        {<<"ExAmPle.CoM">>, <<"example.com">>},
        {<<"SUB.DOMAIN.EXAMPLE.COM">>, <<"sub.domain.example.com">>},
        {<<"TEST_2.EXAMPLE.COM">>, <<"test_2.example.com">>},
        {<<"LABEL\\.WITH\\.ESCAPED.DOTS">>, <<"label\\.with\\.escaped.dots">>},
        {<<"A">>, <<"a">>},
        {<<"ABC">>, <<"abc">>},
        {<<"ABCDE">>, <<"abcde">>},
        {<<"ABCDEFG">>, <<"abcdefg">>},
        {<<"_XMPP-SERVER._TCP.EXAMPLE.COM">>, <<"_xmpp-server._tcp.example.com">>},
        {<<"MAIL.EXAMPLE.ORG">>, <<"mail.example.org">>}
    ],
    [
        ?assertEqual(Expected, dns_domain:to_lower(Input))
     || {Input, Expected} <- ToLowerCases
    ].

%% ============================================================================
%% To Wire Tests
%% ============================================================================

to_wire_basic(_) ->
    Cases = [
        {<<"example">>, <<7, "example", 0>>},
        {<<"example.com.">>, <<7, "example", 3, "com", 0>>},
        {<<"example.com">>, <<7, "example", 3, "com", 0>>},
        {<<"www.example.com">>, <<3, "www", 7, "example", 3, "com", 0>>},
        {<<"test">>, <<4, "test", 0>>},
        {<<"a.b.c">>, <<1, "a", 1, "b", 1, "c", 0>>}
    ],
    [?assertEqual(Expect, dns_domain:to_wire(Input)) || {Input, Expect} <- Cases].

to_wire_empty_cases(_) ->
    Cases = [
        {<<>>, <<0>>},
        {<<$.>>, <<0>>}
    ],
    [?assertEqual(Expect, dns_domain:to_wire(Input)) || {Input, Expect} <- Cases].

to_wire_boundaries(_) ->
    %% Test label at exactly 63 bytes (max) - should succeed
    Label63 = iolist_to_binary(lists:duplicate(63, "a")),
    Name63 = <<Label63/binary, ".com">>,
    Wire63 = dns_domain:to_wire(Name63),
    ?assertEqual(<<63, Label63/binary, 3, "com", 0>>, Wire63),
    %% Test name at exactly 255 bytes (max) - should succeed
    Labels255 = [<<"a">> || _ <- lists:seq(1, 127)],
    Name255 = dns_domain:join(Labels255),
    Wire255 = dns_domain:to_wire(Name255),
    ?assertEqual(255, byte_size(Wire255)),
    %% Test name at 253 bytes - should succeed
    Labels253 = [<<"a">> || _ <- lists:seq(1, 126)],
    Name253 = dns_domain:join(Labels253),
    Wire253 = dns_domain:to_wire(Name253),
    ?assertEqual(253, byte_size(Wire253)),
    %% Test name that would exceed 255 bytes with <= 127 labels - should error with name_too_long
    %% Use 5 labels of 63 bytes each: 5*64 (length+label) + 1 (root) = 321 bytes > 255
    LongLabel = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    LongName =
        <<LongLabel/binary, ".", LongLabel/binary, ".", LongLabel/binary, ".", LongLabel/binary,
            ".", LongLabel/binary>>,
    ?assertError(name_too_long, dns_domain:to_wire(LongName)).

to_wire_errors(_) ->
    ErrorCases = [
        <<"example..com">>,
        <<"example.com..">>,
        <<"a..b">>
    ],
    [?assertError({invalid_dname, empty_label}, dns_domain:to_wire(Name)) || Name <- ErrorCases],
    %% Label too long (> 63 bytes)
    Label64 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 64)>>),
    ?assertError({label_too_long, _}, dns_domain:to_wire(<<Label64/binary, ".com">>)),
    %% Name too long (> 255 bytes total)
    %% Create a name that exceeds 255 bytes but has <= 127 labels
    LongLabel = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    LongName =
        <<LongLabel/binary, ".", LongLabel/binary, ".", LongLabel/binary, ".", LongLabel/binary,
            ".", LongLabel/binary>>,
    ?assertError(name_too_long, dns_domain:to_wire(LongName)),
    %% Label at 64 bytes (too long) - should error
    Label64 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 64)>>),
    Name64 = <<Label64/binary, ".com">>,
    ?assertError({label_too_long, _}, dns_domain:to_wire(Name64)),
    %% Too many labels (> 127 labels)
    Labels128 = [<<"a">> || _ <- lists:seq(1, 128)],
    Name128 = dns_domain:join(Labels128),
    ?assertError(name_too_long, dns_domain:to_wire(Name128)).

%% ============================================================================
%% From Wire Tests
%% ============================================================================

from_wire_basic(_) ->
    Cases = [
        {<<0>>, {<<>>, <<>>}},
        {<<7, "example", 3, "com", 0>>, {<<"example.com">>, <<>>}},
        {<<3, "www", 7, "example", 3, "com", 0>>, {<<"www.example.com">>, <<>>}},
        {<<4, "test", 0>>, {<<"test">>, <<>>}},
        {<<1, "a", 1, "b", 1, "c", 0>>, {<<"a.b.c">>, <<>>}}
    ],
    [?assertEqual(Expect, dns_domain:from_wire(Input)) || {Input, Expect} <- Cases].

from_wire_trailing_data(_) ->
    Cases = [
        {<<7, "example", 3, "com", 0, 1, 2, 3>>, {<<"example.com">>, <<1, 2, 3>>}},
        {
            <<3, "www", 7, "example", 3, "com", 0, 99, 98, 97>>,
            {<<"www.example.com">>, <<99, 98, 97>>}
        }
    ],
    [?assertEqual(Expect, dns_domain:from_wire(Input)) || {Input, Expect} <- Cases].

from_wire_boundaries(_) ->
    %% Test label at exactly 63 bytes (max) - should succeed
    Label63 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    Wire63 = <<63, Label63/binary, 0>>,
    {Name63, Rest63} = dns_domain:from_wire(Wire63),
    ?assertEqual(Label63, Name63),
    ?assertEqual(<<>>, Rest63),
    %% Test empty label in middle (label length 0)
    WireEmptyLabel = <<3, "www", 0, 7, "example", 3, "com", 0>>,
    {NameEmpty, RestEmpty} = dns_domain:from_wire(WireEmptyLabel),
    ?assertEqual(<<"www">>, NameEmpty),
    ?assertEqual(<<7, "example", 3, "com", 0>>, RestEmpty),
    %% Test name at exactly 255 bytes (max) - should succeed
    Labels255 = [<<"a">> || _ <- lists:seq(1, 127)],
    Name255 = dns_domain:join(Labels255),
    Wire255 = dns_domain:to_wire(Name255),
    {Decoded255, Rest255} = dns_domain:from_wire(Wire255),
    ?assertEqual(255, byte_size(Wire255)),
    ?assertEqual(Name255, Decoded255),
    ?assertEqual(<<>>, Rest255),
    %% Test from_wire with exactly 127 labels (max) - should succeed
    ManyLabels127 = iolist_to_binary(<<<<1, "a">> || _ <- lists:seq(1, 127)>>),
    Wire127 = <<ManyLabels127/binary, 0>>,
    {Name127, Rest127} = dns_domain:from_wire(Wire127),
    ?assertEqual(127, length(dns_domain:split(Name127))),
    ?assertEqual(<<>>, Rest127).

from_wire_chunked_escaping(_) ->
    %% Test escape_label_inline with labels that trigger chunked matching
    %% Tests various chunk sizes (8, 4, 2 bytes) and single-byte fallback
    Cases = [
        %% Label with 8+ safe bytes (triggers 8-byte matching)
        {<<8, "abcdefgh", 0>>, {<<"abcdefgh">>, <<>>}},
        %% Label with 4+ safe bytes (triggers 4-byte matching)
        {<<4, "abcd", 0>>, {<<"abcd">>, <<>>}},
        %% Label with 2+ safe bytes (triggers 2-byte matching)
        {<<2, "ab", 0>>, {<<"ab">>, <<>>}},
        %% Label with dots (triggers single-byte fallback)
        {<<3, "a.b", 0>>, {<<"a\\.b">>, <<>>}},
        %% Label with backslashes (triggers single-byte fallback)
        {<<3, "a\\b", 0>>, {<<"a\\\\b">>, <<>>}},
        %% Long label with mixed safe/unsafe bytes
        {<<13, "abcdefgh.test", 0>>, {<<"abcdefgh\\.test">>, <<>>}}
    ],
    [?assertEqual(Expected, dns_domain:from_wire(Input)) || {Input, Expected} <- Cases].

from_wire_errors(_) ->
    %% Truncated cases
    TruncatedCases = [
        <<>>,
        <<5, "test">>,
        <<10, "short">>,
        <<4, "test", 4, "test">>,
        <<3, "www", 7, "exampl">>
    ],
    [?assertError(truncated, dns_domain:from_wire(Wire)) || Wire <- TruncatedCases],
    %% Invalid label length
    InvalidLengthCases = [
        {64, <<4, "test", 64, "test", 0>>},
        {64, <<64, "test", 0>>},
        {100, <<100, "test", 0>>}
    ],
    [
        ?assertError({invalid_label_length, Len}, dns_domain:from_wire(Wire))
     || {Len, Wire} <- InvalidLengthCases
    ],
    %% Too many labels
    ManyLabels128 = iolist_to_binary(<<<<1, "a">> || _ <- lists:seq(1, 128)>>),
    TooManyLabels = <<ManyLabels128/binary, 0>>,
    ?assertError({too_many_labels, 128}, dns_domain:from_wire(TooManyLabels)),
    %% Test from_wire with label length > 63
    ?assertError({invalid_label_length, 64}, dns_domain:from_wire(<<64, "test", 0>>)),
    ?assertError({invalid_label_length, 100}, dns_domain:from_wire(<<100, "test", 0>>)),
    %% Name too long
    MaxLabel = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    FiveLongLabels =
        <<63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 63,
            MaxLabel/binary, 0>>,
    ?assertError({name_too_long, _}, dns_domain:from_wire(FiveLongLabels)).

%% ============================================================================
%% Compression Tests
%% ============================================================================

compression_encoding_basic(_) ->
    CompMap = #{},
    Pos = 0,
    Name = <<"example.com">>,
    {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, Name),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire1),
    ?assertNotEqual(undefined, maps:get([<<"example">>, <<"com">>], CompMap1, undefined)),
    %% Second encoding should use compression pointer
    Pos2 = byte_size(Wire1),
    {Wire2, _CompMap2} = dns_domain:to_wire(CompMap1, Pos2, Name),
    ?assertEqual(<<192, 0>>, Wire2),
    <<3:2, Ptr:14>> = Wire2,
    ?assertEqual(0, Ptr).

compression_encoding_multiple(_) ->
    CompMap = #{},
    Pos = 0,
    Name1 = <<"example.com">>,
    Name2 = <<"test.org">>,
    %% Encode first name
    {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, Name1),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire1),
    %% Encode second name
    Pos2 = byte_size(Wire1),
    {Wire2, CompMap2} = dns_domain:to_wire(CompMap1, Pos2, Name2),
    ?assertEqual(<<4, "test", 3, "org", 0>>, Wire2),
    %% Encode first name again - should use compression pointer
    Pos3 = Pos2 + byte_size(Wire2),
    {Wire3, CompMap3} = dns_domain:to_wire(CompMap2, Pos3, Name1),
    <<3:2, Ptr1:14>> = Wire3,
    ?assertEqual(0, Ptr1),
    ?assert(Ptr1 < Pos3),
    %% Encode second name again - should use compression pointer
    Pos4 = Pos3 + byte_size(Wire3),
    {Wire4, _CompMap4} = dns_domain:to_wire(CompMap3, Pos4, Name2),
    <<3:2, Ptr2:14>> = Wire4,
    ?assertEqual(Pos2, Ptr2).

compression_encoding_prior_only(_) ->
    CompMap = #{},
    Pos = 0,
    Name1 = <<"example.com">>,
    {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, Name1),
    Pos2 = byte_size(Wire1),
    Name2 = <<"test.org">>,
    {Wire2, CompMap2} = dns_domain:to_wire(CompMap1, Pos2, Name2),
    Pos3 = Pos2 + byte_size(Wire2),
    %% Encode Name1 again - should use compression pointer to Pos (0), not Pos3
    {Wire3, _CompMap3} = dns_domain:to_wire(CompMap2, Pos3, Name1),
    <<3:2, Ptr:14>> = Wire3,
    ?assertEqual(0, Ptr),
    ?assert(Ptr < Pos3).

compression_encoding_invalid_pointer(_) ->
    %% Test that invalid pointers (pointing to current/future position) are handled
    Name = <<"example.com">>,
    %% Create a compression map with an invalid pointer (points to future position)
    InvalidCompMap = #{[<<"example">>, <<"com">>] => 100},
    Pos2 = 50,
    %% Should remove invalid pointer and encode normally (100 >= 50, so invalid)
    {Wire, NewCompMap} = dns_domain:to_wire(InvalidCompMap, Pos2, Name),
    ?assertNotEqual(<<192, 100>>, Wire),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire),
    %% Should have added new pointer at position 50
    ?assertEqual(50, maps:get([<<"example">>, <<"com">>], NewCompMap)),
    %% Test pointer pointing to current position (also invalid, Ptr not < Pos)
    CurrentPosCompMap = #{[<<"example">>, <<"com">>] => 50},
    {Wire2, NewCompMap2} = dns_domain:to_wire(CurrentPosCompMap, 50, Name),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire2),
    ?assertEqual(50, maps:get([<<"example">>, <<"com">>], NewCompMap2)),
    HighPosCompMap = #{[<<"example">>, <<"com">>] => 16385},
    {Wire3, _} = dns_domain:to_wire(HighPosCompMap, 16384, Name),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire3).

compression_encoding_position_limit(_) ->
    %% Test compression map when position exceeds 2^14 - 1 (16383)
    CompMap = #{},
    Name = <<"example.com">>,
    {Wire, NewCompMap} = dns_domain:to_wire(CompMap, 16384, Name),
    ?assertEqual(<<7, "example", 3, "com", 0>>, Wire),
    %% Should not add to compression map when position >= 2^14
    ?assertEqual(undefined, maps:get([<<"example">>, <<"com">>], NewCompMap, undefined)).

compression_encoding_case_insensitive(_) ->
    %% Test that case-insensitive compression works (same name in different cases compresses to same pointer)
    CompMap = #{},
    Pos = 0,
    {Wire0, CM0} = dns_domain:to_wire(CompMap, Pos, <<"example">>),
    %% Append "example" again - should use compression pointer
    {Wire1, _} = dns_domain:to_wire(CM0, byte_size(Wire0), <<"example">>),
    %% Append "EXAMPLE" (case-insensitive, should also use compression)
    {Wire2, _} = dns_domain:to_wire(CM0, byte_size(Wire0), <<"EXAMPLE">>),
    ?assertEqual(<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, Wire0),
    ?assertEqual(<<192, 0>>, Wire1),
    ?assertEqual(Wire1, Wire2).

compression_encoding_errors(_) ->
    %% Test edge cases for to_wire/3 (compression version)
    CompMap = #{},
    Pos = 0,
    %% Empty labels (contiguous dots) - should error
    ErrorCases = [
        <<"example..com">>,
        <<"example.com..">>,
        <<"a..b">>
    ],
    [
        ?assertError({invalid_dname, empty_label}, dns_domain:to_wire(CompMap, Pos, Name))
     || Name <- ErrorCases
    ],
    %% Label too long (> 63 bytes) - should error
    Label64 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 64)>>),
    Name64 = <<Label64/binary, ".com">>,
    ?assertError({label_too_long, _}, dns_domain:to_wire(CompMap, Pos, Name64)),
    %% Name too long (> 255 bytes total) with <= 127 labels - should error
    %% Use 5 labels of 63 bytes each: 5*64 (length+label) + 1 (root) = 321 bytes > 255
    LongLabel = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    LongName = <<
        LongLabel/binary,
        ".",
        LongLabel/binary,
        ".",
        LongLabel/binary,
        ".",
        LongLabel/binary,
        ".",
        LongLabel/binary
    >>,
    ?assertError(name_too_long, dns_domain:to_wire(CompMap, Pos, LongName)),
    %% Too many labels (> 127 labels) - should error
    Labels128 = [<<"a">> || _ <- lists:seq(1, 128)],
    Name128 = dns_domain:join(Labels128),
    ?assertError(name_too_long, dns_domain:to_wire(CompMap, Pos, Name128)),
    %% Test that valid names still work
    ValidName = <<"example.com">>,
    {_Wire, _NewCompMap} = dns_domain:to_wire(CompMap, Pos, ValidName).

compression_decoding_basic(_) ->
    MsgBin = <<7, "example", 3, "com", 0, 192, 0>>,
    Cases = [
        {{<<7, 101, 120, 97, 109, 112, 108, 101, 0>>, <<3:2, 0:14>>}, {<<"example">>, <<>>}},
        {{MsgBin, MsgBin}, {<<"example.com">>, <<192, 0>>}},
        {{MsgBin, <<192, 0>>}, {<<"example.com">>, <<>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- Cases
    ].

compression_decoding_nested(_) ->
    %% Build message with nested compression
    CompMap = #{},
    Pos = 0,
    Name1 = <<"example.com">>,
    {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, Name1),
    Pos2 = byte_size(Wire1),
    Name2 = <<"www.example.com">>,
    {Wire2, CompMap2} = dns_domain:to_wire(CompMap1, Pos2, Name2),
    Pos3 = Pos2 + byte_size(Wire2),
    {Wire3, _CompMap3} = dns_domain:to_wire(CompMap2, Pos3, Name2),
    MsgBin = <<Wire1/binary, Wire2/binary, Wire3/binary>>,
    Rest1 = <<Wire2/binary, Wire3/binary>>,
    Rest2 = <<Wire3/binary>>,
    Cases = [
        {{MsgBin, MsgBin}, {Name1, Rest1}},
        {{MsgBin, Rest1}, {Name2, Rest2}},
        {{MsgBin, Rest2}, {Name2, <<>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- Cases
    ].

compression_decoding_chain(_) ->
    %% Test decoding a chain of compression pointers
    MsgBin = <<7, "example", 3, "com", 0, 192, 0, 192, 0, 192, 0>>,
    Rest1 = <<192, 0, 192, 0, 192, 0>>,
    Rest2 = <<192, 0, 192, 0>>,
    Rest3 = <<192, 0>>,
    Cases = [
        {{MsgBin, MsgBin}, {<<"example.com">>, Rest1}},
        {{MsgBin, Rest1}, {<<"example.com">>, Rest2}},
        {{MsgBin, Rest2}, {<<"example.com">>, Rest3}},
        {{MsgBin, Rest3}, {<<"example.com">>, <<>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- Cases
    ].

compression_decoding_first_label_pointer(_) ->
    %% Test compression pointer as first label (from_wire_first_compressed with pointer)
    MsgBin = <<7, "example", 3, "com", 0, 192, 0>>,
    Cases = [
        {{MsgBin, <<192, 0>>}, {<<"example.com">>, <<>>}},
        {{MsgBin, <<192, 0, 1, 2, 3>>}, {<<"example.com">>, <<1, 2, 3>>}},
        {{MsgBin, <<0, 1, 2, 3>>}, {<<>>, <<1, 2, 3>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- Cases
    ],
    %% Test from_wire_first_compressed with empty data (truncated)
    ?assertError(truncated, dns_domain:from_wire(MsgBin, <<>>)),
    %% Test from_wire_first_compressed with truncated label
    ?assertError(truncated, dns_domain:from_wire(MsgBin, <<5, "ab">>)).

compression_decoding_empty_after_pointer(_) ->
    %% Test empty data after compression pointer
    CompMap = #{},
    {Wire1, CompMap1} = dns_domain:to_wire(CompMap, 0, <<"example.com">>),
    Pos2 = byte_size(Wire1),
    {Wire2, _} = dns_domain:to_wire(CompMap1, Pos2, <<"test.example.com">>),
    MsgBin2 = <<Wire1/binary, Wire2/binary>>,
    Rest1 = Wire2,
    {Wire3, CompMap3} = dns_domain:to_wire(#{}, 0, <<"test.com">>),
    Pos4 = byte_size(Wire3),
    {Wire4, _} = dns_domain:to_wire(CompMap3, Pos4, <<"test.com">>),
    MsgBin3 = <<Wire3/binary, Wire4/binary>>,
    Rest3 = Wire4,
    Cases = [
        {{MsgBin2, MsgBin2}, {<<"example.com">>, Rest1}},
        {{MsgBin2, Rest1}, {<<"test.example.com">>, <<>>}},
        {{MsgBin3, MsgBin3}, {<<"test.com">>, Rest3}},
        {{MsgBin3, Rest3}, {<<"test.com">>, <<>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- Cases
    ].

compression_decoding_errors(_) ->
    MsgBin = <<7, "example", 3, "com", 0>>,
    %% Truncation after compression pointer
    TruncatedCases = [
        {<<192, 0, 5>>, {<<"example.com">>, <<5>>}},
        {<<192, 0, 5, "ab">>, {<<"example.com">>, <<5, "ab">>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(MsgBin, Input))
     || {Input, Expected} <- TruncatedCases
    ],
    %% Nested compression pointers (verifies Count accumulation)
    BaseMsg = <<7, "example", 3, "com", 0>>,
    SecondName = <<3, "www", 192, 0>>,
    FullMsg = <<BaseMsg/binary, SecondName/binary>>,
    NestedCases = [
        {SecondName, {<<"www.example.com">>, <<>>}},
        {<<192, 13>>, {<<"www.example.com">>, <<>>}}
    ],
    [
        ?assertEqual(Expected, dns_domain:from_wire(FullMsg, Input))
     || {Input, Expected} <- NestedCases
    ],
    %% Errors in from_wire_rest_compressed
    %% Too many labels (127 labels) - success
    ManyLabels127 = iolist_to_binary(<<<<1, "a">> || _ <- lists:seq(1, 127)>>),
    Wire127 = <<ManyLabels127/binary, 0>>,
    FullMsg127 = <<MsgBin/binary, Wire127/binary>>,
    {_, RestAfterFirst} = dns_domain:from_wire(FullMsg127, FullMsg127),
    {Name127Decoded, _} = dns_domain:from_wire(FullMsg127, RestAfterFirst),
    ?assertEqual(127, length(dns_domain:split(Name127Decoded))),
    %% Too many labels (128 labels) - error in rest_compressed
    ManyLabels128 = iolist_to_binary(<<<<1, "a">> || _ <- lists:seq(1, 128)>>),
    Wire128 = <<ManyLabels128/binary, 0>>,
    FullMsg128 = <<MsgBin/binary, Wire128/binary>>,
    {_, RestAfterFirst128} = dns_domain:from_wire(FullMsg128, FullMsg128),
    MaxLabel = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 63)>>),
    %% Name that exceeds 255 bytes in wire format (4 labels of 63 bytes = 4 * 64 = 256)
    LongNameMsg4 =
        <<63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 0>>,
    FullMsgLong4 = <<MsgBin/binary, LongNameMsg4/binary>>,
    {_, RestAfterFirst4} = dns_domain:from_wire(FullMsgLong4, FullMsgLong4),
    %% Name too long in from_wire_first_compressed guard (line 568)
    %% Process labels to TotalSize = 254, then compression pointer: 254 + 2 = 256
    %% This calls from_wire_first_compressed with TotalSize = 256, triggering the guard
    %% 3 labels of 63 bytes (192) + 1 label of 61 bytes (62) = 254 bytes
    %% Then compression pointer: +2 = 256
    MaxLabel61 = iolist_to_binary(<<<<$a>> || _ <- lists:seq(1, 61)>>),
    NameWithPtr =
        <<63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 61, MaxLabel61/binary, 192,
            0>>,
    FullMsgWithPtr = <<MsgBin/binary, NameWithPtr/binary>>,
    LongNameMsg =
        <<63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 63, MaxLabel/binary, 63,
            MaxLabel/binary, 0>>,
    RestErrorCases = [
        %% Bad compression pointer (first label)
        {{MsgBin, <<192, 20>>}, {bad_pointer, 20}},
        {{MsgBin, <<3:2, 42:14>>}, {bad_pointer, 42}},
        %% Invalid label length (first label)
        {{MsgBin, <<64, "test", 0>>}, {invalid_label_length, 64}},
        {{MsgBin, <<100, "test", 0>>}, {invalid_label_length, 100}},
        %% Invalid label length in rest_compressed (subsequent label)
        {{MsgBin, <<3, "www", 64, "test", 0>>}, {invalid_label_length, 64}},
        {{MsgBin, <<3, "www", 100, "test", 0>>}, {invalid_label_length, 100}},
        %% Too many labels in rest_compressed (128 labels)
        {{FullMsg128, RestAfterFirst128}, {too_many_labels, 128}},
        %% Name too long (wire format size exceeds 255)
        %% 5 labels of 63 bytes: error after 4th label (4 * 64 = 256)
        {{LongNameMsg, LongNameMsg}, {name_too_long, 256}},
        %% 4 labels of 63 bytes in rest_compressed: error after 4th label (4 * 64 = 256)
        {{FullMsgLong4, RestAfterFirst4}, {name_too_long, 256}},
        %% Name too long in from_wire_first_compressed guard (line 568)
        {{FullMsgWithPtr, NameWithPtr}, {name_too_long, 256}},
        %% Bad pointer and truncation in rest_compressed
        {{MsgBin, <<3, "www", 192, 20>>}, {bad_pointer, 20}},
        %% Truncated: empty binary after label (line 603)
        {{MsgBin, <<3, "www">>}, truncated},
        %% Truncated: label length byte but insufficient data (line 632)
        {{MsgBin, <<3, "www", 5, "ab">>}, truncated},
        %% decode_loop - self-referencing pointer in first_compressed: Count 0 -> 2 -> 4, 4 > 2
        {{<<3:2, 42:14>>, <<3:2, 42:14>>}, {bad_pointer, 42}},
        {{<<3:2, 0:14>>, <<3:2, 0:14>>}, decode_loop}
        %% Note: decode_loop in rest_compressed (line 617) appears unreachable in practice.
        %% It requires NewCount = Count + 2 > byte_size(MsgBin) where Count > 0 in rest_compressed.
        %% Count starts at 0 when entering rest_compressed, so we'd need byte_size(MsgBin) < 2,
        %% which is impossible since we need at least 2 bytes for the compression pointer itself.
        %% Even with nested resolutions where Count > 0, the message must be large enough to
        %% contain the structure, making this path mathematically unreachable.
    ],
    [
        ?assertError(Expected, dns_domain:from_wire(MsgInput, DataInput))
     || {{MsgInput, DataInput}, Expected} <- RestErrorCases
    ].

%% ============================================================================
%% Comparison Tests
%% ============================================================================

are_equal_basic(_) ->
    Cases = [
        {{<<"example.com">>, <<"EXAMPLE.COM">>}, true},
        {{<<"www.EXAMPLE.com">>, <<"WWW.example.COM">>}, true},
        {{dns_domain:to_upper(<<"example.com">>), dns_domain:to_lower(<<"EXAMPLE.COM">>)}, true},
        {{<<"example.com">>, <<"different.com">>}, false},
        {{<<"example.com">>, <<"example.org">>}, false},
        {{<<>>, <<>>}, true},
        {{<<"example.com">>, <<>>}, false}
    ],
    [
        ?assertEqual(Expected, dns_domain:are_equal(NameA, NameB))
     || {{NameA, NameB}, Expected} <- Cases
    ].

are_equal_labels_basic(_) ->
    Cases = [
        {{[<<"example">>, <<"com">>], [<<"EXAMPLE">>, <<"COM">>]}, true},
        {{[<<"www">>, <<"example">>, <<"com">>], [<<"WWW">>, <<"example">>, <<"COM">>]}, true},
        {{[<<"www">>, <<"EXAMPLE">>, <<"com">>], [<<"WWW">>, <<"example">>, <<"COM">>]}, true},
        {{[<<"www">>, <<"different">>, <<"com">>], [<<"WWW">>, <<"example">>, <<"COM">>]}, false},
        {{[<<"www">>, <<"example">>], [<<"www">>, <<"example">>, <<"com">>]}, false},
        {{[<<"www">>, <<"example">>, <<"com">>], [<<"www">>, <<"example">>]}, false},
        {{[], []}, true}
    ],
    [
        ?assertEqual(Expected, dns_domain:are_equal_labels(LabelsA, LabelsB))
     || {{LabelsA, LabelsB}, Expected} <- Cases
    ].

%% ============================================================================
%% Reversibility Tests
%% ============================================================================

split_join_roundtrip(_) ->
    SplitJoin = [
        <<"example.com">>,
        <<"www.example.com">>,
        <<"a.b.c.d.e">>,
        <<"escaped\\.dot.com">>,
        <<"back\\\\slash.com">>,
        <<"mixed\\.dots\\\\and\\\\.backslashes">>
    ],
    [?assertEqual(Name, dns_domain:join(dns_domain:split(Name))) || Name <- SplitJoin],
    JoinSplit = [
        [<<"example">>, <<"com">>],
        [<<"www">>, <<"example">>, <<"com">>],
        [<<"a">>, <<"b">>, <<"c">>, <<"d">>, <<"e">>],
        [<<"escaped\\.dot">>, <<"com">>],
        [<<"back\\\\slash">>, <<"com">>],
        [<<"mixed\\.dots\\\\and\\\\.backslashes">>]
    ],
    [?assertEqual(Labels, dns_domain:split(dns_domain:join(Labels))) || Labels <- JoinSplit].

wire_roundtrip(_) ->
    Cases = [
        <<"example.com">>,
        <<"www.example.com">>,
        <<"test">>,
        <<"a.b.c">>
    ],
    [
        begin
            Wire = dns_domain:to_wire(Name),
            {Decoded, <<>>} = dns_domain:from_wire(Wire),
            ?assertEqual(Name, Decoded)
        end
     || Name <- Cases
    ].

wire_roundtrip_with_escapes(_) ->
    Cases = [
        <<"escaped\\.dot.com">>,
        <<"back\\\\slash.com">>,
        <<"mixed\\.dots\\\\and\\\\.backslashes">>
    ],
    [
        begin
            Wire = dns_domain:to_wire(Name),
            {Decoded, <<>>} = dns_domain:from_wire(Wire),
            ?assertEqual(Name, Decoded)
        end
     || Name <- Cases
    ].

%% ============================================================================
%% Error Tests
%% ============================================================================

split_errors(_) ->
    ErrorCases = [
        <<"example..com">>,
        <<"example.com..">>,
        <<"example...com">>,
        <<"..example.com">>,
        <<"example..com..">>,
        <<"a..b..c">>
    ],
    [?assertError({invalid_dname, empty_label}, dns_domain:split(Name)) || Name <- ErrorCases].

compression_errors(_) ->
    %% Test bad compression pointer (points outside message)
    MsgBin = <<7, "example", 3, "com", 0>>,
    BadPointer = <<192, 100>>,
    ?assertError({bad_pointer, 100}, dns_domain:from_wire(MsgBin, BadPointer)),
    %% Test compression pointer pointing beyond message size
    SmallMsg = <<7, "example", 3, "com", 0>>,
    PointerBeyond = <<192, 20>>,
    ?assertError({bad_pointer, 20}, dns_domain:from_wire(SmallMsg, PointerBeyond)).
