%% -*- mode: erlang -*-
%% DNS Zone File Lexer
%%
%% == Specification Sources ==
%%
%% RFC-Defined (Standard):
%%   RFC 1034 §3.6.1 - Resource record conceptual model
%%     https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.1
%%   RFC 1035 §5 - Master file format, basic syntax, $ORIGIN, $INCLUDE
%%     https://datatracker.ietf.org/doc/html/rfc1035#section-5
%%   RFC 1876 §3 - TTL time unit syntax
%%     https://datatracker.ietf.org/doc/html/rfc1876#section-3
%%   RFC 2308 §4 - $TTL directive
%%     https://datatracker.ietf.org/doc/html/rfc2308#section-4
%%   RFC 4291 §2.2 - IPv6 address text representation
%%     https://datatracker.ietf.org/doc/html/rfc4291#section-2.2
%%   RFC 4592 - Wildcards in DNS (clarifies RFC 1034 §4.3.2, §4.3.3)
%%     https://datatracker.ietf.org/doc/html/rfc4592
%%     Allows * as a label (e.g., *.example.com)
%%   RFC 2782 - SRV records with underscore labels (_service._proto.name)
%%     https://datatracker.ietf.org/doc/html/rfc2782
%%     Also used by DKIM (RFC 6376), DMARC, and other protocols
%%   RFC 3597 - Handling of Unknown DNS Resource Record Types
%%     https://datatracker.ietf.org/doc/html/rfc3597
%%     Generic syntax: TYPE###, CLASS###, \# length hexdata
%%     Enables forward compatibility with future RR types
%%
%% Convenience Extensions (Non-Standard):
%%   Hexadecimal escapes (\xHH) - Convenience alternative to \DDD
%%     Not in RFC 1035, but widely supported in modern implementations
%%     \xHH where HH is 2 hex digits (00-FF), e.g., \x41 = 'A'
%%
%% BIND Extensions (Non-Standard):
%%   $GENERATE - BIND-specific directive for generating multiple RRs
%%     Not in any RFC. See: https://bind9.readthedocs.io/en/latest/chapter3.html
%%     Warning: May reduce portability to other DNS software
%%   Time unit 'y' (years) - BIND extension for time values
%%     Not in RFC 1876 or RFC 2308, but supported by BIND and others
%%     1 year = 31536000 seconds (365 days, no leap year adjustment)

Definitions.

% Whitespace
WS        = [\s\t]
NL        = \r?\n

% Comments start with semicolon (RFC 1035 §5.1)
COMMENT   = ;[^\n]*

% Directives:
% - ORIGIN and INCLUDE: RFC 1035 §5.1
% - TTL: RFC 2308 §4
% - GENERATE: BIND extension (non-standard)
ORIGIN    = \$ORIGIN
INCLUDE   = \$INCLUDE
TTL       = \$TTL
GENERATE  = \$GENERATE

% Special characters (RFC 1035 §5.1)
% @ represents current origin
% Parentheses for multi-line records
AT        = @
DOT       = \.
LPAREN    = \(
RPAREN    = \)
COMMA     = ,

% Numbers
INT       = [0-9]+

% Time values (e.g., 1h30m, 2d, 3600) - RFC 1876 §3, RFC 2308 §4
% Compound time values like "1h30m" are matched as a single token
% Standard units: w=weeks, d=days, h=hours, m=minutes, s=seconds
% Extension: y=years (BIND extension, 365 days, no leap year)
TIME_NUM  = [0-9]+
TIME_UNIT = [ywdhms]
TIME_VALUE = ({TIME_NUM}{TIME_UNIT}+)+

% Domain name labels - RFC 1035 §2.3.1 with extensions
% Standard characters: a-z, A-Z, 0-9, hyphen (-)
% Extensions supported:
%   * (asterisk) - RFC 4592: Wildcard labels (*.example.com)
%   _ (underscore) - RFC 2782: Service labels (_tcp, _http, etc.)
%                    Also used by DKIM (RFC 6376), DMARC
%   : (colon) - For IPv6 addresses and service names
%   +/= (plus, slash, equals) - RFC 4648: Base64 encoding (equals for padding)
% Note: RFC 1035 hostnames cannot start with digit or hyphen,
%       but zone file labels are more permissive
% Note: = is used for base64 padding and also as EQUALS token, but standalone = will
% still match EQUALS since LABEL requires at least one non-= character
LABEL_CHAR = [a-zA-Z0-9\-_*:+\/=]
LABEL      = [a-zA-Z0-9\-_*:+\/=][a-zA-Z0-9\-_*:+\/=]*

% IP addresses
IPV4      = [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}

% IPv6 - RFC 4291 §2.2 (Text Representation of Addresses)
% Matches most common IPv6 address formats including compressed notation (::)
% Pattern matches:
%   - Full form: 2001:db8:0:0:0:0:0:1
%   - Compressed: 2001:db8::1, ::1, fe80::
%   - Mixed IPv4: ::ffff:192.0.2.1 (lexed as domain, validated semantically)
% Note: Complex edge cases validated using inet:parse_ipv6_address/1
IPV6_SEG  = [0-9a-fA-F]{1,4}
IPV6_FULL = {IPV6_SEG}(:{IPV6_SEG}){7}
IPV6_COMP_START = ::({IPV6_SEG}:)*{IPV6_SEG}?
IPV6_COMP_MID   = ({IPV6_SEG}:)+:({IPV6_SEG}:)*{IPV6_SEG}?
IPV6_COMP_END   = ({IPV6_SEG}:)+::?
IPV6_COMP_ONLY  = ::
IPV6 = ({IPV6_FULL}|{IPV6_COMP_START}|{IPV6_COMP_MID}|{IPV6_COMP_END}|{IPV6_COMP_ONLY})

% Class - RFC 1035
CLASS     = (IN|CH|HS|CS)

% RFC 3597 - Generic RR type and class syntax
% TYPE### where ### is decimal type number (0-65535)
% CLASS### where ### is decimal class number
% \# marks generic RDATA (backslash + hash, then length and hex data)
% The lexer captures the entire \# line as one token
GENERIC_TYPE  = TYPE[0-9]+
GENERIC_CLASS = CLASS[0-9]+
RFC3597_DATA = \\#[\s\t]+[0-9]+([\s\t]+[0-9a-fA-F]+)*

% Record types - all supported types
RTYPE_A        = A
RTYPE_AAAA     = AAAA
RTYPE_NS       = NS
RTYPE_CNAME    = CNAME
RTYPE_SOA      = SOA
RTYPE_PTR      = PTR
RTYPE_MX       = MX
RTYPE_TXT      = TXT
RTYPE_SRV      = SRV
RTYPE_CAA      = CAA
RTYPE_NAPTR    = NAPTR
RTYPE_SSHFP    = SSHFP
RTYPE_TLSA     = TLSA
RTYPE_DS       = DS
RTYPE_DNSKEY   = DNSKEY
RTYPE_RRSIG    = RRSIG
RTYPE_NSEC     = NSEC
RTYPE_NSEC3    = NSEC3
RTYPE_NSEC3PARAM = NSEC3PARAM
RTYPE_CDNSKEY  = CDNSKEY
RTYPE_CDS      = CDS
RTYPE_DNAME    = DNAME
RTYPE_HINFO    = HINFO
RTYPE_MB       = MB
RTYPE_MG       = MG
RTYPE_MR       = MR
RTYPE_MINFO    = MINFO
RTYPE_RP       = RP
RTYPE_AFSDB    = AFSDB
RTYPE_RT       = RT
RTYPE_KEY      = KEY
RTYPE_LOC      = LOC
RTYPE_NXT      = NXT
RTYPE_KX       = KX
RTYPE_CERT     = CERT
RTYPE_DHCID    = DHCID
RTYPE_SPF      = SPF
RTYPE_SVCB     = SVCB
RTYPE_HTTPS    = HTTPS
RTYPE_DLV      = DLV
RTYPE_IPSECKEY = IPSECKEY
RTYPE_ZONEMD   = ZONEMD

% Quoted strings for TXT records, etc.
STRING    = "([^"\\]|\\.)*"

% Generic tokens
EQUALS    = =

Rules.

% Directives
% Note: Macro names (e.g., GENERATE) define regex patterns to match in input text.
%       Token names (e.g., '$generate') are atoms produced by the lexer for the parser.
%       Lowercase token atoms follow Erlang/yecc conventions.
{ORIGIN}       : {token, {'$origin', TokenLine, TokenChars}}.   % RFC 1035 §5.1
{TTL}          : {token, {'$ttl', TokenLine, TokenChars}}.      % RFC 2308 §4
{INCLUDE}      : {token, {'$include', TokenLine, TokenChars}}.  % RFC 1035 §5.1
{GENERATE}     : {token, {'$generate', TokenLine, TokenChars}}. % BIND extension

% Comments - skip them
{COMMENT}      : skip_token.

% Newlines are significant (end of record)
{NL}           : {token, {nl, TokenLine}}.

% Whitespace - significant for field separation
{WS}+          : skip_token.

% Special characters
{AT}           : {token, {'@', TokenLine}}.
{DOT}          : {token, {dot, TokenLine}}.
{LPAREN}       : {token, {lparen, TokenLine}}.
{RPAREN}       : {token, {rparen, TokenLine}}.
{EQUALS}       : {token, {equals, TokenLine}}.
{COMMA}        : {token, {comma, TokenLine}}.

% Class
{CLASS}        : {token, {class, TokenLine, TokenChars}}.

% RFC 3597 - Generic RR type/class syntax (must come before specific record types)
{GENERIC_TYPE}  : {token, {generic_type, TokenLine, TokenChars}}.
{GENERIC_CLASS} : {token, {generic_class, TokenLine, TokenChars}}.
{RFC3597_DATA}  : {token, {rfc3597_data, TokenLine, TokenChars}}.

% Record types - order matters, longest match first
{RTYPE_NSEC3PARAM} : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_ZONEMD}     : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_IPSECKEY}   : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_CDNSKEY}    : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_NSEC3}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_DNSKEY}     : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_RRSIG}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_SSHFP}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_HTTPS}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_NAPTR}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_CNAME}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_DNAME}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_HINFO}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_MINFO}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_AFSDB}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_DHCID}      : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_AAAA}       : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_TLSA}       : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_NSEC}       : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_SVCB}       : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_CERT}       : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_PTR}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_SOA}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_SRV}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_TXT}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_CAA}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_CDS}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_KEY}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_LOC}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_NXT}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_DLV}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_SPF}        : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_NS}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_MX}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_DS}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_RP}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_RT}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_KX}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_MB}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_MG}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_MR}         : {token, {rtype, TokenLine, TokenChars}}.
{RTYPE_A}          : {token, {rtype, TokenLine, TokenChars}}.

% Quoted strings
{STRING}       : {token, {string, TokenLine, extract_string(TokenChars)}}.

% Time values with units (must come before integers and labels - e.g., 1h, 30m, 2d, 1h30m)
{TIME_VALUE}   : {token, {time, TokenLine, parse_time(TokenChars)}}.

% Plain integers (must come before labels to avoid matching as label)
{INT}          : {token, {int, TokenLine, list_to_integer(TokenChars)}}.

% IPv4 addresses (must come before domain names - more specific)
{IPV4}         : {token, {ipv4, TokenLine, TokenChars}}.

% IPv6 addresses (RFC 4291 §2.2) - must come before domain names
% Matches compressed notation (::) and full addresses
% Final validation done semantically using inet:parse_ipv6_address/1
{IPV6}         : {token, {ipv6, TokenLine, TokenChars}}.

% Domain name with dots (must come after IPv4 and time values)
{LABEL}(\.{LABEL})+ : {token, {name, TokenLine, TokenChars}}.

% Standalone label (last, as fallback)
{LABEL}        : {token, {label, TokenLine, TokenChars}}.

Erlang code.

%% Extract string content from quoted string, handling escape sequences
%% RFC 1035 §5.1 defines two escape formats:
%%   \X - where X is any character, means literal X
%%   \DDD - where DDD is a 3-digit decimal (000-255), means that octet value
%% Convenience extension (widely supported):
%%   \xHH - where HH is 2 hex digits (00-FF), e.g., \x41 = 'A'
extract_string([$" | Rest]) ->
    extract_string_content(Rest, []).

extract_string_content([$"], Acc) ->
    lists:reverse(Acc);
extract_string_content([$\\, D1, D2, D3 | Rest], Acc)
        when D1 >= $0, D1 =< $9, D2 >= $0, D2 =< $9, D3 >= $0, D3 =< $9 ->
    %% RFC 1035 §5.1: \DDD decimal escape (000-255)
    Value = (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0),
    case Value =< 255 of
        true ->
            extract_string_content(Rest, [Value | Acc]);
        false ->
            %% Invalid: treat as literal backslash + digits
            extract_string_content([D1, D2, D3 | Rest], [$\\ | Acc])
    end;
extract_string_content([$\\, $x, H1, H2 | Rest], Acc) ->
    %% Convenience extension: \xHH hexadecimal escape (00-FF)
    maybe
        {ok, V1} ?= hex_digit_value(H1),
        {ok, V2} ?= hex_digit_value(H2),
        Value = V1 * 16 + V2,
        extract_string_content(Rest, [Value | Acc])
    else
        _ ->
            %% Invalid hex: treat as literal \x + characters
            extract_string_content([H1, H2 | Rest], [$x, $\\ | Acc])
    end;
extract_string_content([$\\, C | Rest], Acc) ->
    %% RFC 1035 §5.1: \X means literal X (includes common escapes)
    extract_string_content(Rest, [unescape_char(C) | Acc]);
extract_string_content([C | Rest], Acc) ->
    extract_string_content(Rest, [C | Acc]).

%% Convert hex digit to value
hex_digit_value(C) when C >= $0, C =< $9 -> {ok, C - $0};
hex_digit_value(C) when C >= $a, C =< $f -> {ok, C - $a + 10};
hex_digit_value(C) when C >= $A, C =< $F -> {ok, C - $A + 10};
hex_digit_value(_) -> error.

%% Unescape common escape sequences - RFC 1035 §5.1
%% These are convenience mappings; \X for any X means literal X
unescape_char($n) -> $\n;   % Newline (convenience, not in RFC)
unescape_char($t) -> $\t;   % Tab (convenience, not in RFC)
unescape_char($r) -> $\r;   % Carriage return (convenience, not in RFC)
unescape_char($\\) -> $\\;  % Backslash
unescape_char($") -> $";    % Quote
unescape_char(C) -> C.      % Any other character: literal

%% Parse time values like "1h30m", "2d", or "1y" into seconds
%% Standard units (RFC 1876 §3, RFC 2308 §4): w, d, h, m, s
%% Extension (BIND): y (year = 365 days = 31536000 seconds, no leap year)
parse_time(Chars) ->
    parse_time(Chars, 0, 0).

parse_time([], Num, Total) when Num > 0 ->
    Total + Num;  % Treat trailing number as seconds
parse_time([], _Num, Total) ->
    Total;
parse_time([C | Rest], Num, Total) when C >= $0, C =< $9 ->
    parse_time(Rest, Num * 10 + (C - $0), Total);
parse_time([Unit | Rest], Num, Total) ->
    Multiplier = case Unit of
        $y -> 31536000; % year (BIND extension: 365 days, no leap year)
        $w -> 604800;   % week
        $d -> 86400;    % day
        $h -> 3600;     % hour
        $m -> 60;       % minute
        $s -> 1;        % second
        _ -> 1
    end,
    parse_time(Rest, 0, Total + Num * Multiplier).
