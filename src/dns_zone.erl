-module(dns_zone).

-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.

?MODULEDOC("""
DNS Zone File Parser

This module provides functionality to parse DNS zone files according to
[RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) and related
specifications.

## Specification Compliance

### RFC-Defined Features (Standard):
- **[RFC 1035 §5](https://datatracker.ietf.org/doc/html/rfc1035#section-5)**:
  Master file format, resource record syntax
- **[RFC 1034 §3.6.1](https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.1)**:
  Resource record conceptual model
- **[RFC 2308 §4](https://datatracker.ietf.org/doc/html/rfc2308#section-4)**:
  $TTL directive and time unit syntax

### Supported RFC Features:
- All DNS record types supported by this library
- Zone file directives: $ORIGIN, $TTL, $INCLUDE
  ([RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035))
- Multi-line records using parentheses
  ([RFC 1035 §5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1))
- Comments (semicolon to end-of-line,
  [RFC 1035 §5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1))
- Relative and absolute domain names
  ([RFC 1035 §5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1))
- Time values with units: w, d, h, m, s
  ([RFC 2308 §4](https://datatracker.ietf.org/doc/html/rfc2308#section-4))
- All DNS classes: IN, CH, HS, CS
  ([RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035))
- @ symbol for current origin
  ([RFC 1035 §5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1))
- Blank owner names inheriting from previous RR
  ([RFC 1035 §5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1))

### BIND Extensions (Non-Standard):
- **$GENERATE**: BIND-specific directive for generating multiple similar RRs
  * Status: Parsed but NOT implemented (template expansion TODO)
  * Warning: Not portable to all DNS software
  * See: https://bind9.readthedocs.io/en/latest/chapter3.html

The parser uses Erlang's parsetools (leex and yecc) for lexical analysis and parsing.

## Examples

```erl
% Parse a zone file from disk
{ok, Records} = dns_zone:parse_file("example.com.zone").

% Parse zone data from a string
ZoneData = <<\"
example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
                      2024010101 ; serial
                      3600       ; refresh
                      1800       ; retry
                      604800     ; expire
                      86400 )    ; minimum
example.com. 3600 IN NS ns1.example.com.
www 3600 IN A 192.0.2.1
\">>,
{ok, Records} = dns_zone:parse_string(ZoneData).
```
""").

% 4KB, a good default
-define(CHUNK_SIZE, 4096).

-include_lib("dns_erlang/include/dns.hrl").
% -include_lib("parsetools/include/yeccpre.hrl").

%% Public API
-export([parse_file/1, parse_file/2]).
-export([parse_string/1, parse_string/2]).
-export([format_error/1]).

?DOC("""
Options for parsing zone files.

- `origin` - Initial $ORIGIN for relative domain names (default: `<<>>`)
- `default_ttl` - Default TTL for records without explicit TTL (default: `0`)
- `default_class` - Default DNS class (default: `?DNS_CLASS_IN`)
- `base_dir` - Base directory for $INCLUDE directives (default: `""`)
- `filename` - Source filename for error reporting (internal, set by parse_file)
""").
-type parse_options() :: #{
    origin => dns:dname(),
    default_ttl => dns:ttl(),
    default_class => dns:class(),
    base_dir => file:name_all(),
    filename => file:name_all(),
    chunk_size => non_neg_integer()
}.

?DOC("""
Error location information.

- `line` - Line number where error occurred (1-indexed)
- `column` - Column number if available (1-indexed)
- `file` - Filename if parsing from file
""").
-type error_location() :: #{
    line => pos_integer(),
    column => pos_integer() | undefined,
    file => file:filename() | undefined
}.

?DOC("""
Error type classification.

- `file` - File I/O error (e.g., file not found)
- `lexer` - Lexical analysis error (invalid tokens)
- `parser` - Syntax parsing error (grammar violation)
- `semantic` - Semantic validation error (invalid data)
""").
-type error_type() :: file | lexer | parser | semantic.

?DOC("""
Detailed error information with context and suggestions.

- `type` - Classification of the error
- `location` - Where the error occurred (line, column, file)
- `message` - Human-readable error description
- `context` - The line of text where error occurred (if available)
- `suggestion` - Helpful suggestion for fixing the error (if available)
- `details` - Original technical error details
""").
-type error_detail() :: #{
    type := error_type(),
    message := unicode:unicode_binary(),
    location => error_location(),
    context => binary(),
    suggestion => unicode:unicode_binary(),
    details => term()
}.

-export_type([parse_options/0, error_detail/0, error_location/0, error_type/0]).

%% Parser context for maintaining state during parsing
-record(parse_ctx, {
    origin = <<>> :: dns:dname(),
    default_ttl = 0 :: dns:ttl(),
    default_class = ?DNS_CLASS_IN :: dns:class(),
    last_owner = <<>> :: dns:dname(),
    base_dir = "" :: file:name_all(),
    filename = undefined :: file:name_all() | undefined,
    source_lines = [] :: [string()]
}).

-type parse_ctx() :: #parse_ctx{}.

-type rdata() ::
    {int, integer()}
    | {string, string()}
    | {ipv4, string()}
    | {ipv6, string()}
    | {domain, string()}
    | {rfc3597, string()}
    | {rfc3597, string()}.
-type directive() ::
    {directive, origin, dynamic()}
    | {directive, ttl, dynamic()}
    | {directive, include, dynamic()}
    | {directive, include, dynamic(), dynamic()}
    | {directive, generate, dynamic()}.
-type rr() ::
    {rr, Owner :: dynamic(), TTL :: dynamic(), Class :: dynamic(), Type :: dynamic(),
        RData :: [rdata()]}.
-type entry() :: empty | directive() | rr().

%% ============================================================================
%% Public API
%% ============================================================================

?DOC("""
Parse a zone file from disk.

Returns `{ok, Records}` where Records is a list of `#dns_rr{}` records,
or `{error, Reason}` if parsing fails.

## Examples

```erl
{ok, Records} = dns_zone:parse_file("/path/to/zone.db").
```
""").
-spec parse_file(file:filename()) -> {ok, [dns:rr()]} | {error, error_detail()}.
parse_file(Filename) ->
    parse_file(Filename, #{}).

?DOC("""
Parse a zone file from disk with options.

Options (all optional):
- `origin => Domain` - Set the initial $ORIGIN
- `default_ttl => TTL` - Set the default TTL
- `default_class => Class` - Set the default class (defaults to IN)
- `base_dir => Dir` - Set base directory for $INCLUDE directives

## Examples

```erl
{ok, Records} = dns_zone:parse_file("zone.db", #{origin => <<"example.com.">>}).

{ok, Records} = dns_zone:parse_file("zone.db", #{
    origin => <<"example.com.">>,
    default_ttl => 3600
}).
```
""").
-spec parse_file(file:filename(), parse_options()) -> {ok, [dns:rr()]} | {error, error_detail()}.
parse_file(Filename, Options) ->
    ChunkSize = maps:get(chunk_size, Options, ?CHUNK_SIZE),
    case file:open(Filename, [raw, read, {read_ahead, ?CHUNK_SIZE}]) of
        {ok, Device} ->
            InitialState = {Device, 1, [], ChunkSize},
            BaseDir = filename:dirname(Filename),
            Opts = Options#{base_dir => BaseDir, filename => Filename},
            Ctx = init_context(Opts, []),
            do_parse_file(Device, Ctx, InitialState);
        {error, Reason} ->
            {error, make_file_error(Filename, Reason)}
    end.

do_parse_file(Device, Ctx, InitialState) ->
    try dns_zone_parser:parse_and_scan({fun next_tokens/1, [InitialState]}) of
        {ok, Entries} ->
            process_entries(Entries, Ctx, []);
        {error, {lexer, Reason, ELine}} ->
            {error, make_lexer_error(ELine, Reason, Ctx)};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    after
        file:close(Device)
    end.

?DOC("""
Parse zone file content from a string or binary.

## Examples

```erl
ZoneData = <<\"example.com. IN A 192.0.2.1\">>,
{ok, Records} = dns_zone:parse_string(ZoneData).
```
""").
-spec parse_string(binary() | string()) -> {ok, [dns:rr()]} | {error, error_detail()}.
parse_string(Data) ->
    parse_string(Data, #{}).

?DOC("""
Parse zone file content from a string or binary with options.
""").
-spec parse_string(binary() | string(), parse_options()) ->
    {ok, [dns:rr()]} | {error, error_detail()}.
parse_string(Data, Options) when is_list(Data) ->
    parse(Data, Options);
parse_string(Data, Options) when is_binary(Data) ->
    parse(binary_to_list(Data), Options).

?DOC("""
This is the "tokenizer function" that yecc will call.

It holds the state {Device, Line, LexerContinuation}. It attempts to get tokens from the lexer
with an empty buffer, which will trigger a file read if more data is needed.
""").
next_tokens({Device, Line, LexerCont, ChunkSize}) ->
    call_leex(Device, "", Line, LexerCont, ChunkSize).

%% Internal helper to manage the {more, _} loop from leex.
call_leex(Device, Buffer, Line, LexerCont, ChunkSize) ->
    % Call the leex-generated function
    case dns_zone_lexer:tokens(LexerCont, Buffer, Line) of
        {done, {ok, Tokens, EndLine}, NewLexerCont} ->
            % Success! leex processed the buffer and produced tokens.
            % Return them to yecc.
            {ok, Tokens, {Device, EndLine, NewLexerCont}};
        {done, {eof, EndLine}, NewLexerCont} ->
            % leex signaled end-of-file. Pass this to yecc.
            {eof, {Device, EndLine, NewLexerCont}};
        {done, {error, Reason, ELine}, NewLexerCont} ->
            % leex found a syntax error. Pass this to yecc.
            % ct:pal("R: ~p, ELine: ~p, NewLexerCont: ~p~n", [Reason, ELine, NewLexerCont]),
            {error, {lexer, Reason, ELine}, {Device, ELine, NewLexerCont}};
        {more, NewLexerCont} ->
            % leex needs more characters. Read a chunk from the file.
            case file:read(Device, ChunkSize) of
                eof ->
                    % We hit the end of the file.
                    % Feed an empty binary to leex to make it
                    % flush any remaining tokens and return {done, {eof, _}, _}.
                    call_leex(Device, eof, Line, NewLexerCont, ChunkSize);
                {ok, NewData} ->
                    % We got data. Recurse to feed it back to leex.
                    call_leex(Device, NewData, Line, NewLexerCont, ChunkSize);
                {error, Reason} ->
                    % A file read error occurred.
                    {error, {file_read, Reason}, {Device, Line, NewLexerCont}}
            end
    end.

?DOC("""
Main parsing function. Tokenizes input and parses into DNS records.
""").
-spec parse(string(), parse_options()) -> {ok, [dns:rr()]} | {error, error_detail()}.
parse(String, Options) ->
    %% Split source into lines for error context
    SourceLines = string:split(String, "\n", all),
    Ctx = init_context(Options, SourceLines),
    maybe
        {ok, Tokens} ?= tokenize(String, Ctx),
        {ok, ParseTree} ?= lexerize(Tokens, Ctx),
        {ok, Records} ?= process_entries(ParseTree, Ctx, []),
        {ok, Records}
    end.

?DOC("""
Format a parse error into a human-readable string.

Takes an error from `parse_file/1,2` or `parse_string/1,2` and returns
a formatted string suitable for display to users.

## Examples

```erl
case dns_zone:parse_file("bad.zone") of
    {ok, Records} -> ok;
    {error, Error} ->
        io:format("~s", [dns_zone:format_error(Error)])
end.
```
""").
-spec format_error(error_detail()) -> iolist().
format_error(#{type := Type, message := Message} = Error) ->
    Location = maps:get(location, Error, #{}),
    Context = maps:get(context, Error, undefined),
    Suggestion = maps:get(suggestion, Error, undefined),
    [
        format_location(Location, Type),
        "  ",
        Message,
        "\n",
        format_context(Context),
        format_suggestion(Suggestion)
    ].

%% Format location information
-spec format_location(error_location(), error_type()) -> iolist().
format_location(#{line := Line, file := File}, Type) when File /= undefined ->
    io_lib:format("~s at ~s:~p (~p):~n", [capitalize(Type), File, Line, Type]);
format_location(#{file := File}, Type) when File /= undefined ->
    io_lib:format("~s at ~s (~p):~n", [capitalize(Type), File, Type]);
format_location(#{line := Line}, Type) ->
    io_lib:format("~s at line ~p (~p):~n", [capitalize(Type), Line, Type]);
format_location(_Location, Type) ->
    io_lib:format("~s:~n", [capitalize(Type)]).

%% Format context (the source line where error occurred)
-spec format_context(binary() | undefined) -> iolist().
format_context(undefined) ->
    [];
format_context(Context) ->
    ["  | ", Context, "\n"].

%% Format suggestion
-spec format_suggestion(binary() | undefined) -> iolist().
format_suggestion(undefined) ->
    [];
format_suggestion(Suggestion) ->
    ["\nSuggestion:\n  ", Suggestion, "\n"].

%% Capitalize first letter of atom
-spec capitalize(atom()) -> unicode:chardata().
capitalize(Atom) ->
    string:titlecase(atom_to_list(Atom)).

%% ============================================================================
%% Internal Functions
%% ============================================================================

%% Initialize parser context from options
-spec init_context(parse_options(), [string()]) -> parse_ctx().
init_context(Options, SourceLines) ->
    Origin = dns:dname_to_lower(maps:get(origin, Options, <<>>)),
    DefaultTTL = maps:get(default_ttl, Options, 0),
    DefaultClass = maps:get(default_class, Options, ?DNS_CLASS_IN),
    BaseDir = maps:get(base_dir, Options, ""),
    Filename = maps:get(filename, Options, undefined),
    #parse_ctx{
        origin = Origin,
        default_ttl = DefaultTTL,
        default_class = DefaultClass,
        last_owner = Origin,
        base_dir = BaseDir,
        filename = Filename,
        source_lines = SourceLines
    }.

%% Build enhanced error with location and context
-spec make_error(error_type(), binary(), term(), binary() | undefined, parse_ctx()) ->
    error_detail().
make_error(Type, Message, Details, undefined, Ctx) ->
    #{
        type => Type,
        message => Message,
        details => Details,
        location => make_location(undefined, Ctx)
    };
make_error(Type, Message, Details, Suggestion, Ctx) ->
    #{
        type => Type,
        message => Message,
        details => Details,
        suggestion => Suggestion,
        location => make_location(undefined, Ctx)
    }.

%% Get source line by line number
-spec get_source_line(pos_integer(), parse_ctx()) -> binary() | undefined.
get_source_line(Line, #parse_ctx{source_lines = SourceLines}) when Line > 0 ->
    case Line =< length(SourceLines) of
        true -> list_to_binary(lists:nth(Line, SourceLines));
        false -> undefined
    end;
get_source_line(_, _) ->
    undefined.

%% Build file error
-spec make_file_error(file:filename() | undefined, term()) -> error_detail().
make_file_error(Filename, Reason) ->
    Message = io_lib:format("Failed to read file: ~p", [Reason]),
    #{
        type => file,
        message => iolist_to_binary(Message),
        details => {file_error, Reason},
        location => #{file => Filename}
    }.

%% Build error location map
-spec make_location(pos_integer() | undefined, parse_ctx()) -> error_location().
make_location(Line, #parse_ctx{filename = Filename}) when is_integer(Line), Line > 0 ->
    Location = #{line => Line},
    make_filename(Filename, Location);
make_location(_, #parse_ctx{filename = undefined}) ->
    #{};
make_location(_, #parse_ctx{filename = Filename}) ->
    #{file => Filename}.

make_filename(undefined, Acc) -> Acc;
make_filename(F, Acc) -> Acc#{file => F}.

%% Build lexer error
-spec make_lexer_error(pos_integer(), term(), parse_ctx()) -> error_detail().
make_lexer_error(Line, Reason, Ctx) ->
    Message = io_lib:format("Lexical error: ~p", [Reason]),
    Error = #{
        type => lexer,
        message => iolist_to_binary(Message),
        details => {lexer_error, Reason},
        location => make_location(Line, Ctx)
    },
    maybe_append_source_line(Error, Line, Ctx).

%% Build parser error
-spec make_parser_error(term(), parse_ctx()) -> error_detail().
make_parser_error(Reason, Ctx) ->
    Message = io_lib:format("Parse error: ~p", [Reason]),
    %% Try to extract line number from parser error reason
    Line = extract_line_from_parser_error(Reason),
    Error = #{
        type => parser,
        message => iolist_to_binary(Message),
        details => {parser_error, Reason},
        location => make_location(Line, Ctx)
    },
    case Line of
        undefined ->
            Error;
        L ->
            maybe_append_source_line(Error, L, Ctx)
    end.

maybe_append_source_line(Error, Line, Ctx) ->
    case get_source_line(Line, Ctx) of
        undefined -> Error;
        SourceLine -> Error#{context => SourceLine}
    end.

%% Extract line number from parser error tuple
-spec extract_line_from_parser_error(term()) -> pos_integer() | undefined.
extract_line_from_parser_error({Line, _Module, _Message}) when is_integer(Line), Line > 0 ->
    Line;
extract_line_from_parser_error(_) ->
    undefined.

%% Build semantic error
-spec make_semantic_error(term(), parse_ctx()) -> error_detail().
make_semantic_error(Reason, Ctx) ->
    Message = io_lib:format("Semantic error: ~p", [Reason]),
    #{
        type => semantic,
        message => iolist_to_binary(Message),
        details => {semantic_error, Reason},
        location => make_location(undefined, Ctx)
    }.

%% Build error for invalid RDATA with suggestions
-spec make_rdata_error(binary(), list(), parse_ctx()) -> error_detail().
make_rdata_error(TypeName, RData, Ctx) ->
    {Message, Suggestion} = rdata_error_message(TypeName, RData),
    make_error(semantic, Message, {invalid_rdata, TypeName, RData}, Suggestion, Ctx).

%% Generate helpful error messages for RDATA errors
-spec rdata_error_message(binary(), list()) -> {binary(), binary() | undefined}.
rdata_error_message(<<"SSHFP">>, RData) when length(RData) < 3 ->
    {
        <<"Invalid SSHFP record: expected 3 fields ", "(algorithm, fptype, fingerprint), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"SSHFP requires: algorithm fptype \"hexfingerprint\"\n",
            "  Example: example.com. 3600 IN SSHFP 2 1 \"123ABC...\"">>
    };
rdata_error_message(<<"SSHFP">>, _RData) ->
    {
        <<"Invalid SSHFP record: fingerprint must be even-length hex string">>,
        <<"Hex strings must have an even number of characters ", "(each byte = 2 hex digits)">>
    };
rdata_error_message(<<"TLSA">>, RData) when length(RData) < 4 ->
    {
        <<"Invalid TLSA record: expected 4 fields ",
            "(usage, selector, matching-type, cert-data), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"TLSA requires: usage selector matching-type \"hexcertdata\"\n",
            "Example: _443._tcp.example.com. IN TLSA 3 1 1 \"ABC123...\"">>
    };
rdata_error_message(<<"TLSA">>, _RData) ->
    {
        <<"Invalid TLSA record: certificate data must be even-length hex string">>,
        <<"Hex strings must have an even number of characters">>
    };
rdata_error_message(<<"NAPTR">>, RData) when length(RData) < 6 ->
    {
        <<"Invalid NAPTR record: expected 6 fields ",
            "(order, preference, flags, services, regexp, replacement), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"NAPTR requires: order preference \"flags\" \"services\" ", "\"regexp\" replacement\n",
            "Example: example.com. IN NAPTR 100 10 \"S\" \"SIP+D2T\" \"\" ",
            "_sip._tcp.example.com.">>
    };
rdata_error_message(<<"CERT">>, RData) when length(RData) < 4 ->
    {
        <<"Invalid CERT record: expected 4 fields ", "(type, keytag, algorithm, cert-data), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"CERT requires: type keytag algorithm \"certdata\"\n",
            "Example: example.com. IN CERT 1 12345 8 \"MIICXAIBAAKBgQC8\"">>
    };
rdata_error_message(<<"DHCID">>, _RData) ->
    {
        <<"Invalid DHCID record: requires base64-encoded data">>,
        <<"DHCID requires: \"base64data\"\n", "Example: example.com. IN DHCID ",
            "\"AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=\"">>
    };
rdata_error_message(<<"MX">>, _RData) ->
    {
        <<"Invalid MX record: expected preference and mail server">>,
        <<"MX requires: preference mailserver\n",
            "Example: example.com. IN MX 10 mail.example.com.">>
    };
rdata_error_message(<<"SRV">>, _RData) ->
    {
        <<"Invalid SRV record: expected priority, weight, port, and target">>,
        <<"SRV requires: priority weight port target\n",
            "Example: _http._tcp.example.com. IN SRV 10 20 80 www.example.com.">>
    };
rdata_error_message(<<"DS">>, RData) when length(RData) < 4 ->
    {
        <<"Invalid DS record: expected 4 fields ", "(keytag, algorithm, digest-type, digest), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"DS requires: keytag algorithm digest-type \"hexdigest\"\n",
            "Example: example.com. IN DS 12345 8 2 \"49FD46E6C4B45C55D4AC\"">>
    };
rdata_error_message(<<"DS">>, _RData) ->
    {
        <<"Invalid DS record: digest must be even-length hex string">>,
        <<"Hex strings must have an even number of characters">>
    };
rdata_error_message(<<"DNSKEY">>, RData) when length(RData) < 4 ->
    {
        <<"Invalid DNSKEY record: expected 4 fields ",
            "(flags, protocol, algorithm, public-key), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"DNSKEY requires: flags protocol algorithm \"base64publickey\"\n",
            "Example: example.com. IN DNSKEY 256 3 8 \"AwEAAa...\"">>
    };
rdata_error_message(<<"DNSKEY">>, _RData) ->
    {
        <<"Invalid DNSKEY record: public key must be valid base64">>,
        <<"Public key should be base64-encoded key material">>
    };
rdata_error_message(<<"SVCB">>, RData) when length(RData) < 2 ->
    {
        <<"Invalid SVCB record: expected at least 2 fields ", "(priority, target), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"SVCB requires: priority target\n", "Example: example.com. IN SVCB 1 svc.example.com.">>
    };
rdata_error_message(<<"SVCB">>, _RData) ->
    {
        <<"Invalid SVCB record: malformed priority or target">>,
        <<"Priority must be an integer, target must be a domain name">>
    };
rdata_error_message(<<"HTTPS">>, RData) when length(RData) < 2 ->
    {
        <<"Invalid HTTPS record: expected at least 2 fields ", "(priority, target), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"HTTPS requires: priority target\n", "Example: example.com. IN HTTPS 1 .">>
    };
rdata_error_message(<<"HTTPS">>, _RData) ->
    {
        <<"Invalid HTTPS record: malformed priority or target">>,
        <<"Priority must be an integer, target must be a domain name">>
    };
rdata_error_message(TypeName, _RData) ->
    {<<"Invalid ", TypeName/binary, " record: malformed RDATA">>, undefined}.

%% Tokenize input using the lexer
-spec tokenize(string(), parse_ctx()) -> {ok, [dynamic()]} | {error, error_detail()}.
tokenize(String, Ctx) ->
    case dns_zone_lexer:string(String) of
        {ok, Tokens, _EndLine} ->
            {ok, Tokens ++ [{'$end', 99999}]};
        {error, Reason, Line} ->
            {error, make_lexer_error(Line, Reason, Ctx)}
    end.

%% Parse tokens into structured data
-spec lexerize([dynamic()], parse_ctx()) -> {ok, [dynamic()]} | {error, error_detail()}.
lexerize(Tokens, Ctx) ->
    case dns_zone_parser:parse(Tokens) of
        {ok, ParseTree} when is_list(ParseTree) ->
            {ok, ParseTree};
        {error, Reason} ->
            {error, make_parser_error(Reason, Ctx)}
    end.

%% Process parsed entries into DNS records
-spec process_entries([entry()], parse_ctx(), [dns:rr()]) ->
    {ok, [dns:rr()]} | {error, error_detail()}.
process_entries([], _Ctx, Acc) ->
    {ok, lists:reverse(Acc)};
process_entries([Entry | Rest], Ctx, Acc) ->
    case process_entry(Entry, Ctx) of
        {ok, NewCtx, Records} ->
            process_entries(Rest, NewCtx, lists:reverse(Records, Acc));
        {error, #{type := _} = EnhancedError} ->
            {error, EnhancedError}
    end.

%% Process a single entry (directive or resource record)
-spec process_entry(entry(), parse_ctx()) ->
    {ok, parse_ctx(), [dns:rr()]} | {error, tuple() | error_detail()}.
process_entry(empty, Ctx) ->
    {ok, Ctx, []};
process_entry({directive, origin, Origin0}, Ctx) ->
    %% Update the origin
    Origin = dns:dname_to_lower(ensure_binary(Origin0)),
    NewOrigin = ensure_fqdn(Origin),
    NewCtx = Ctx#parse_ctx{origin = NewOrigin, last_owner = NewOrigin},
    {ok, NewCtx, []};
process_entry({directive, ttl, TTL0}, Ctx) ->
    %% Update the default TTL
    TTL = ensure_integer(TTL0),
    NewCtx = Ctx#parse_ctx{default_ttl = TTL},
    {ok, NewCtx, []};
process_entry({directive, include, Filename}, Ctx) when is_list(Filename) ->
    %% Handle $INCLUDE directive
    handle_include(Filename, Ctx#parse_ctx.origin, Ctx);
process_entry({directive, include, Filename, Origin0}, Ctx) when is_list(Filename) ->
    %% Handle $INCLUDE with origin
    Origin = ensure_binary(Origin0),
    NewOrigin = ensure_fqdn(Origin),
    handle_include(Filename, NewOrigin, Ctx);
process_entry({directive, generate, _Content}, Ctx) ->
    %% $GENERATE - BIND extension (non-standard)
    %% Not yet implemented - would require template expansion
    %% Example: $GENERATE 1-100 server-$.example.com. A 192.168.1.$
    %% See: https://bind9.readthedocs.io/en/latest/chapter3.html
    %% TODO: Implement template expansion with range iteration
    {ok, Ctx, []};
process_entry({rr, Owner, TTL0, Class0, Type0, RData0}, Ctx) ->
    %% Process resource record
    TTL = ensure_ttl(TTL0),
    Class = ensure_entry_class(Class0),
    Type = ensure_entry_type(Type0),
    RData = ensure_list(RData0),
    case build_rr(Owner, TTL, Class, Type, RData, Ctx) of
        {ok, RR, NewCtx} ->
            {ok, NewCtx, [RR]};
        {error, Reason} ->
            {error, Reason}
    end;
process_entry(_Entry, Ctx) ->
    {ok, Ctx, []}.

%% RFC 3597 - Preserve tuple structure for generic types/classes
ensure_entry_class({generic_class, _} = Class0) ->
    Class0;
ensure_entry_class(Class0) when is_list(Class0) ->
    Class0;
ensure_entry_class(undefined) ->
    undefined.

%% RFC 3597 - Preserve tuple structure for generic types/classes
ensure_entry_type({generic_type, _} = Type0) ->
    Type0;
ensure_entry_type(Type0) when is_list(Type0) ->
    Type0.

%% Ensure a term is an integer or undefined
-spec ensure_ttl(dynamic()) -> dns:ttl() | undefined.
ensure_ttl(I) when is_integer(I) -> I;
ensure_ttl(_) -> undefined.

%% Build a DNS resource record
-spec build_rr(
    term(),
    dns:ttl() | undefined,
    {generic_class, _} | string() | undefined,
    string() | {generic_type, string()},
    [rdata()],
    parse_ctx()
) -> {ok, dns:rr(), parse_ctx()} | {error, error_detail()}.
build_rr(Owner, TTL, Class, Type, RData, Ctx) ->
    ResolvedOwner = dns:dname_to_lower(resolved_owner(Owner, Ctx)),
    ResolvedTTL = resolved_ttl(TTL, Ctx),
    ResolvedClass = resolved_class(Class, Ctx),
    TypeNum = type_to_number(Type),
    case build_rdata(Type, RData, Ctx) of
        {ok, RDataRecord} ->
            RR = #dns_rr{
                name = ResolvedOwner,
                type = TypeNum,
                class = ResolvedClass,
                ttl = ResolvedTTL,
                data = RDataRecord
            },
            NewCtx = Ctx#parse_ctx{last_owner = ResolvedOwner},
            {ok, RR, NewCtx};
        {error, Reason} ->
            {error, Reason}
    end.

%% Resolve owner name
resolved_owner(undefined, Ctx) ->
    Ctx#parse_ctx.last_owner;
resolved_owner(at_sign, Ctx) ->
    Ctx#parse_ctx.origin;
resolved_owner(at_sign_fqdn, Ctx) ->
    Ctx#parse_ctx.origin;
resolved_owner(Name, Ctx) when is_list(Name) ->
    resolve_name(Name, Ctx#parse_ctx.origin).

%% Use default TTL if not specified
resolved_ttl(undefined, Ctx) -> Ctx#parse_ctx.default_ttl;
resolved_ttl(TTL, _) -> TTL.

%% Use default class if not specified
%% RFC 3597 - Handle generic CLASS### syntax
resolved_class(undefined, Ctx) ->
    Ctx#parse_ctx.default_class;
resolved_class({generic_class, _} = Class, _) ->
    class_to_number(Class);
resolved_class(Class, _) when is_list(Class) ->
    class_to_number(Class).

%% Build RDATA for specific record types
-spec build_rdata(string() | {generic_type, string()}, [rdata()], parse_ctx()) ->
    {ok, dns:rrdata()} | {error, error_detail()}.
%% RFC 3597 - Generic RDATA format: \# length hexdata
%% This can be used with any record type, including known types
build_rdata(_Type, [{rfc3597, RawData}], Ctx) ->
    %% RawData is like <<"\\# 4 C0000201">>
    case parse_rfc3597_token(RawData) of
        {ok, BinaryData} ->
            %% Return raw binary for generic RDATA
            %% Note: This is stored as-is in the dns_rr data field
            {ok, BinaryData};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("A", RData, Ctx) ->
    case RData of
        [{ipv4, IP}] when is_list(IP) ->
            case parse_ipv4(IP) of
                {ok, IPAddr} -> {ok, #dns_rrdata_a{ip = IPAddr}};
                {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
            end;
        [{domain, IP}] when is_list(IP) ->
            %% Sometimes IPv4 is lexed as a domain name
            case parse_ipv4(IP) of
                {ok, IPAddr} -> {ok, #dns_rrdata_a{ip = IPAddr}};
                {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
            end;
        _ ->
            {error, make_semantic_error({invalid_rdata, 'A', RData}, Ctx)}
    end;
build_rdata("AAAA", RData, Ctx) ->
    case RData of
        [{ipv6, IP}] when is_list(IP) ->
            case parse_ipv6(IP) of
                {ok, IPAddr} -> {ok, #dns_rrdata_aaaa{ip = IPAddr}};
                {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
            end;
        [{domain, IP}] when is_list(IP) ->
            %% Sometimes IPv6 is lexed as a domain name
            case parse_ipv6(IP) of
                {ok, IPAddr} -> {ok, #dns_rrdata_aaaa{ip = IPAddr}};
                {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
            end;
        _ ->
            {error, make_semantic_error({invalid_rdata, 'AAAA', RData}, Ctx)}
    end;
build_rdata("NS", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_ns{dname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("CNAME", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_cname{dname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("PTR", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_ptr{dname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("MX", RData, Ctx) ->
    case RData of
        [{int, Pref}, {domain, Exchange}] when is_integer(Pref), is_list(Exchange) ->
            {ok, #dns_rrdata_mx{
                preference = Pref,
                exchange = resolve_name(Exchange, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'MX', RData}, Ctx)}
    end;
build_rdata("TXT", RData, Ctx) ->
    case extract_strings(RData) of
        {ok, Strings} -> {ok, #dns_rrdata_txt{txt = Strings}};
        {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("SOA", RData, Ctx) ->
    case RData of
        [
            {domain, MName},
            {domain, RName},
            {int, Serial},
            {int, Refresh},
            {int, Retry},
            {int, Expire},
            {int, Minimum}
        ] when
            is_list(MName),
            is_list(RName),
            is_integer(Serial),
            is_integer(Refresh),
            is_integer(Retry),
            is_integer(Expire),
            is_integer(Minimum)
        ->
            {ok, #dns_rrdata_soa{
                mname = resolve_name(MName, Ctx#parse_ctx.origin),
                rname = resolve_name(RName, Ctx#parse_ctx.origin),
                serial = Serial,
                refresh = Refresh,
                retry = Retry,
                expire = Expire,
                minimum = Minimum
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'SOA', RData}, Ctx)}
    end;
build_rdata("SRV", RData, Ctx) ->
    case RData of
        [{int, Priority}, {int, Weight}, {int, Port}, {domain, Target}] when
            is_integer(Priority), is_integer(Weight), is_integer(Port), is_list(Target)
        ->
            {ok, #dns_rrdata_srv{
                priority = Priority,
                weight = Weight,
                port = Port,
                target = resolve_name(Target, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'SRV', RData}, Ctx)}
    end;
build_rdata("CAA", RData, Ctx) ->
    case RData of
        [{int, Flags}, {string, Tag}, {string, Value}] when
            is_integer(Flags), is_list(Tag), is_list(Value)
        ->
            {ok, #dns_rrdata_caa{
                flags = Flags,
                tag = list_to_binary(Tag),
                value = list_to_binary(Value)
            }};
        [{int, Flags}, {domain, Tag}, {string, Value}] when
            is_integer(Flags), is_list(Tag), is_list(Value)
        ->
            %% Sometimes tag is parsed as domain
            {ok, #dns_rrdata_caa{
                flags = Flags,
                tag = list_to_binary(Tag),
                value = list_to_binary(Value)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'CAA', RData}, Ctx)}
    end;
build_rdata("DNAME", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_dname{dname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("MB", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_mb{madname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("MG", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_mg{madname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("MR", RData, Ctx) ->
    case extract_domain(RData) of
        {ok, DName} ->
            {ok, #dns_rrdata_mr{newname = resolve_name(DName, Ctx#parse_ctx.origin)}};
        {error, Reason} ->
            {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("HINFO", RData, Ctx) ->
    case RData of
        [{string, CPU}, {string, OS}] when is_list(CPU), is_list(OS) ->
            {ok, #dns_rrdata_hinfo{
                cpu = list_to_binary(CPU),
                os = list_to_binary(OS)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'HINFO', RData}, Ctx)}
    end;
build_rdata("MINFO", RData, Ctx) ->
    case RData of
        [{domain, RMailbx}, {domain, EmailBx}] when is_list(RMailbx), is_list(EmailBx) ->
            {ok, #dns_rrdata_minfo{
                rmailbx = resolve_name(RMailbx, Ctx#parse_ctx.origin),
                emailbx = resolve_name(EmailBx, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'MINFO', RData}, Ctx)}
    end;
build_rdata("RP", RData, Ctx) ->
    case RData of
        [{domain, Mbox}, {domain, Txt}] when is_list(Mbox), is_list(Txt) ->
            {ok, #dns_rrdata_rp{
                mbox = resolve_name(Mbox, Ctx#parse_ctx.origin),
                txt = resolve_name(Txt, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'RP', RData}, Ctx)}
    end;
build_rdata("AFSDB", RData, Ctx) ->
    case RData of
        [{int, Subtype}, {domain, Hostname}] when is_integer(Subtype), is_list(Hostname) ->
            {ok, #dns_rrdata_afsdb{
                subtype = Subtype,
                hostname = resolve_name(Hostname, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'AFSDB', RData}, Ctx)}
    end;
build_rdata("RT", RData, Ctx) ->
    case RData of
        [{int, Preference}, {domain, Host}] when is_integer(Preference), is_list(Host) ->
            {ok, #dns_rrdata_rt{
                preference = Preference,
                host = resolve_name(Host, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'RT', RData}, Ctx)}
    end;
build_rdata("KX", RData, Ctx) ->
    case RData of
        [{int, Preference}, {domain, Exchange}] when
            is_integer(Preference), is_list(Exchange)
        ->
            {ok, #dns_rrdata_kx{
                preference = Preference,
                exchange = resolve_name(Exchange, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_semantic_error({invalid_rdata, 'KX', RData}, Ctx)}
    end;
build_rdata("SPF", RData, Ctx) ->
    case extract_strings(RData) of
        {ok, Strings} -> {ok, #dns_rrdata_spf{spf = Strings}};
        {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("NAPTR", RData, Ctx) ->
    %% NAPTR format: order preference "flags" "services" "regexp" replacement
    case RData of
        [
            {int, Order},
            {int, Preference},
            {string, Flags},
            {string, Services},
            {string, Regexp},
            {domain, Replacement}
        ] when
            is_integer(Order),
            is_integer(Preference),
            is_list(Flags),
            is_list(Services),
            is_list(Regexp),
            is_list(Replacement)
        ->
            {ok, #dns_rrdata_naptr{
                order = Order,
                preference = Preference,
                flags = list_to_binary(Flags),
                services = list_to_binary(Services),
                regexp = list_to_binary(Regexp),
                replacement = resolve_name(Replacement, Ctx#parse_ctx.origin)
            }};
        _ ->
            {error, make_rdata_error(<<"NAPTR">>, RData, Ctx)}
    end;
build_rdata("SSHFP", RData, Ctx) ->
    %% SSHFP format: algorithm fptype fingerprint(hex string)
    case RData of
        [{int, Alg}, {int, FpType}, {string, FpHex}] when
            is_integer(Alg), is_integer(FpType), is_list(FpHex)
        ->
            case hex_to_binary(FpHex) of
                {ok, Fp} ->
                    {ok, #dns_rrdata_sshfp{alg = Alg, fp_type = FpType, fp = Fp}};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"SSHFP">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"SSHFP">>, RData, Ctx)}
    end;
build_rdata("TLSA", RData, Ctx) ->
    %% TLSA format: usage selector matching-type cert-data(hex string)
    case RData of
        [{int, Usage}, {int, Selector}, {int, MatchingType}, {string, CertHex}] when
            is_integer(Usage), is_integer(Selector), is_integer(MatchingType), is_list(CertHex)
        ->
            case hex_to_binary(CertHex) of
                {ok, Cert} ->
                    {ok, #dns_rrdata_tlsa{
                        usage = Usage,
                        selector = Selector,
                        matching_type = MatchingType,
                        certificate = Cert
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"TLSA">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"TLSA">>, RData, Ctx)}
    end;
build_rdata("CERT", RData, Ctx) ->
    %% CERT format: type keytag algorithm cert-data(base64 or hex string)
    case RData of
        [{int, Type}, {int, KeyTag}, {int, Alg}, {string, CertData}] when
            is_integer(Type), is_integer(KeyTag), is_integer(Alg), is_list(CertData)
        ->
            %% Try hex first, fall back to base64
            Cert =
                case hex_to_binary(CertData) of
                    {ok, Binary} ->
                        Binary;
                    {error, _} ->
                        %% Try base64
                        try
                            base64:decode(CertData)
                        catch
                            _:_ ->
                                ensure_binary(CertData)
                        end
                end,
            {ok, #dns_rrdata_cert{type = Type, keytag = KeyTag, alg = Alg, cert = Cert}};
        _ ->
            {error, make_rdata_error(<<"CERT">>, RData, Ctx)}
    end;
build_rdata("DHCID", RData, Ctx) ->
    %% DHCID format: base64-encoded data (single string)
    case RData of
        [{string, Base64Data}] when is_list(Base64Data) ->
            try
                Data = base64:decode(Base64Data),
                {ok, #dns_rrdata_dhcid{data = Data}}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"DHCID">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"DHCID">>, RData, Ctx)}
    end;
build_rdata("DS", RData, Ctx) ->
    %% DS format: keytag algorithm digest-type digest(hex string)
    %% RFC 4034 - Delegation Signer
    case RData of
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {string, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            case hex_to_binary(DigestHex) of
                {ok, Digest} ->
                    {ok, #dns_rrdata_ds{
                        keytag = KeyTag,
                        alg = Alg,
                        digest_type = DigestType,
                        digest = Digest
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"DS">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"DS">>, RData, Ctx)}
    end;
build_rdata("DNSKEY", RData, Ctx) ->
    %% DNSKEY format: flags protocol algorithm public-key(base64 string)
    %% RFC 4034 - DNS Public Key
    case RData of
        [{int, Flags}, {int, Protocol}, {int, Alg}, {string, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            try
                PublicKey = base64:decode(PublicKeyB64),
                %% Calculate keytag (RFC 4034 Appendix B)
                KeyTag = calculate_keytag(Flags, Protocol, Alg, PublicKey),
                {ok, #dns_rrdata_dnskey{
                    flags = Flags,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey,
                    keytag = KeyTag
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"DNSKEY">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"DNSKEY">>, RData, Ctx)}
    end;
build_rdata("SVCB", RData, Ctx) ->
    %% SVCB format: priority target [svcparams...]
    %% RFC 9460 - Service Binding
    %% For now, we parse priority and target, svcparams are not yet supported
    case RData of
        [{int, Priority}, {domain, Target}] when is_integer(Priority), is_list(Target) ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_svcb{
                svc_priority = Priority,
                target_name = TargetName,
                svc_params = #{}
            }};
        _ ->
            {error, make_rdata_error(<<"SVCB">>, RData, Ctx)}
    end;
build_rdata("HTTPS", RData, Ctx) ->
    %% HTTPS format: same as SVCB but different type number
    %% RFC 9460 - HTTPS-specific Service Binding
    %% For now, we parse priority and target, svcparams are not yet supported
    case RData of
        [{int, Priority}, {domain, Target}] when is_integer(Priority), is_list(Target) ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_svcb{
                svc_priority = Priority,
                target_name = TargetName,
                svc_params = #{}
            }};
        _ ->
            {error, make_rdata_error(<<"HTTPS">>, RData, Ctx)}
    end;
build_rdata(Type, _RData, Ctx) ->
    %% Unsupported or complex record types (LOC, RRSIG, NSEC, etc.)
    %% These are typically auto-generated or use RFC 3597 format
    {error, make_semantic_error({unsupported_type, Type}, Ctx)}.

%% Calculate DNSKEY keytag (RFC 4034 Appendix B)
-spec calculate_keytag(integer(), integer(), integer(), binary()) -> integer().
calculate_keytag(Flags, Protocol, Alg, PublicKey) ->
    %% Build RDATA in wire format
    RData = <<Flags:16, Protocol:8, Alg:8, PublicKey/binary>>,
    %% Calculate sum of 16-bit words
    Sum = calculate_keytag_sum(RData, 0),
    %% Add the carry bits and return modulo 65536
    ((Sum band 16#FFFF) + (Sum bsr 16)) band 16#FFFF.

%% Sum 16-bit words for keytag calculation
-spec calculate_keytag_sum(binary(), integer()) -> integer().
calculate_keytag_sum(<<A:8, B:8, Rest/binary>>, Acc) ->
    %% Add 16-bit word (big-endian)
    calculate_keytag_sum(Rest, Acc + (A bsl 8) + B);
calculate_keytag_sum(<<A:8>>, Acc) ->
    %% Odd byte at end
    Acc + (A bsl 8);
calculate_keytag_sum(<<>>, Acc) ->
    Acc.

%% Extract a single domain name from RDATA
-spec extract_domain([rdata()]) -> {ok, string()} | {error, term()}.
extract_domain([{domain, Domain}]) when is_list(Domain) ->
    {ok, Domain};
extract_domain(_) ->
    {error, invalid_domain}.

%% Extract string list from RDATA - convert to binaries for TXT records
-spec extract_strings([rdata()]) -> {ok, [binary()]} | {error, term()}.
extract_strings(RData) when is_list(RData) ->
    try
        Strings = [list_to_binary(S) || {string, S} <- RData, is_list(S)],
        {ok, Strings}
    catch
        _:_ -> {error, invalid_strings}
    end.

%% Resolve a name relative to the origin
-spec resolve_name(string(), binary()) -> binary().
resolve_name(Name, Origin) when is_list(Name) ->
    %% Convert string name to binary for final record
    BinName = dns:dname_to_lower(list_to_binary(Name)),
    case is_fqdn(Name) of
        true ->
            BinName;
        false when Origin =:= <<>> ->
            %% No origin set, use as-is
            BinName;
        false ->
            %% Append origin
            <<BinName/binary, ".", Origin/binary>>
    end.

%% Check if a name is fully qualified (ends with dot)
-spec is_fqdn(string()) -> boolean().
is_fqdn([]) -> false;
is_fqdn(Name) -> lists:last(Name) =:= $..

%% Ensure a name is fully qualified - accepts binary, returns binary
-spec ensure_fqdn(binary()) -> binary().
ensure_fqdn(Name) when is_binary(Name) ->
    case binary:last(Name) of
        $. -> Name;
        _ -> <<Name/binary, ".">>
    end.

%% Note: This function is lenient and returns <<>> for invalid input
-spec ensure_binary(iodata()) -> binary().
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) ->
    try
        erlang:iolist_to_binary(L)
    catch
        error:badarg -> <<>>
    end;
ensure_binary(_) ->
    <<>>.

%% Ensure a term is an integer
-spec ensure_integer(term()) -> integer().
ensure_integer(I) when is_integer(I) -> I;
ensure_integer(_) -> 0.

%% Ensure a term is a list
-spec ensure_list(term()) -> list().
ensure_list(L) when is_list(L) -> L;
ensure_list(_) -> [].

%% Parse IPv4 address
-spec parse_ipv4(string()) -> {ok, inet:ip4_address()} | {error, term()}.
parse_ipv4(String) ->
    case inet:parse_ipv4_address(String) of
        {ok, Addr} -> {ok, Addr};
        {error, Reason} -> {error, {invalid_ipv4, Reason}}
    end.

%% Parse IPv6 address
-spec parse_ipv6(string()) -> {ok, inet:ip6_address()} | {error, term()}.
parse_ipv6(String) ->
    case inet:parse_ipv6_address(String) of
        {ok, Addr} -> {ok, Addr};
        {error, Reason} -> {error, {invalid_ipv6, Reason}}
    end.

%% Convert DNS class to number
%% RFC 3597 - Support generic CLASS### syntax
-spec class_to_number(string() | {generic_class, string()}) -> dns:class().
class_to_number({generic_class, ClassStr}) ->
    %% RFC 3597 - CLASS### format
    case parse_generic_class(ClassStr) of
        {ok, ClassNum} -> ClassNum;
        {error, _} -> ?DNS_CLASS_IN
    end;
class_to_number("IN") ->
    ?DNS_CLASS_IN;
class_to_number("CH") ->
    ?DNS_CLASS_CH;
class_to_number("HS") ->
    ?DNS_CLASS_HS;
class_to_number("CS") ->
    ?DNS_CLASS_CS;
class_to_number(_) ->
    ?DNS_CLASS_IN.

%% Convert DNS type to number
%% RFC 3597 - Support generic TYPE### syntax
-spec type_to_number(string() | {generic_type, string()}) -> dns:type().
type_to_number({generic_type, TypeStr}) ->
    %% RFC 3597 - TYPE### format
    case parse_generic_type(TypeStr) of
        {ok, TypeNum} -> TypeNum;
        {error, _} -> ?DNS_TYPE_A
    end;
type_to_number("A") ->
    ?DNS_TYPE_A;
type_to_number("NS") ->
    ?DNS_TYPE_NS;
type_to_number("CNAME") ->
    ?DNS_TYPE_CNAME;
type_to_number("SOA") ->
    ?DNS_TYPE_SOA;
type_to_number("PTR") ->
    ?DNS_TYPE_PTR;
type_to_number("MX") ->
    ?DNS_TYPE_MX;
type_to_number("TXT") ->
    ?DNS_TYPE_TXT;
type_to_number("AAAA") ->
    ?DNS_TYPE_AAAA;
type_to_number("SRV") ->
    ?DNS_TYPE_SRV;
type_to_number("CAA") ->
    ?DNS_TYPE_CAA;
type_to_number("NAPTR") ->
    ?DNS_TYPE_NAPTR;
type_to_number("SSHFP") ->
    ?DNS_TYPE_SSHFP;
type_to_number("TLSA") ->
    ?DNS_TYPE_TLSA;
type_to_number("DS") ->
    ?DNS_TYPE_DS;
type_to_number("DNSKEY") ->
    ?DNS_TYPE_DNSKEY;
type_to_number("RRSIG") ->
    ?DNS_TYPE_RRSIG;
type_to_number("NSEC") ->
    ?DNS_TYPE_NSEC;
type_to_number("NSEC3") ->
    ?DNS_TYPE_NSEC3;
type_to_number("NSEC3PARAM") ->
    ?DNS_TYPE_NSEC3PARAM;
type_to_number("CDNSKEY") ->
    ?DNS_TYPE_CDNSKEY;
type_to_number("CDS") ->
    ?DNS_TYPE_CDS;
type_to_number("DNAME") ->
    ?DNS_TYPE_DNAME;
type_to_number("HINFO") ->
    ?DNS_TYPE_HINFO;
type_to_number("MB") ->
    ?DNS_TYPE_MB;
type_to_number("MG") ->
    ?DNS_TYPE_MG;
type_to_number("MR") ->
    ?DNS_TYPE_MR;
type_to_number("MINFO") ->
    ?DNS_TYPE_MINFO;
type_to_number("RP") ->
    ?DNS_TYPE_RP;
type_to_number("AFSDB") ->
    ?DNS_TYPE_AFSDB;
type_to_number("RT") ->
    ?DNS_TYPE_RT;
type_to_number("KEY") ->
    ?DNS_TYPE_KEY;
type_to_number("LOC") ->
    ?DNS_TYPE_LOC;
type_to_number("NXT") ->
    ?DNS_TYPE_NXT;
type_to_number("KX") ->
    ?DNS_TYPE_KX;
type_to_number("CERT") ->
    ?DNS_TYPE_CERT;
type_to_number("DHCID") ->
    ?DNS_TYPE_DHCID;
type_to_number("SPF") ->
    ?DNS_TYPE_SPF;
type_to_number("SVCB") ->
    ?DNS_TYPE_SVCB;
type_to_number("HTTPS") ->
    ?DNS_TYPE_HTTPS;
type_to_number("DLV") ->
    ?DNS_TYPE_DLV;
type_to_number("IPSECKEY") ->
    ?DNS_TYPE_IPSECKEY;
type_to_number(_) ->
    ?DNS_TYPE_A.

%% Handle $INCLUDE directive
-spec handle_include(string(), binary(), parse_ctx()) ->
    {ok, parse_ctx(), [dns:rr()]} | {error, tuple() | error_detail()}.
handle_include(Filename, Origin, Ctx) ->
    FullPath = full_filename_path(Ctx#parse_ctx.base_dir, Filename),
    IncludeOpts = #{
        origin => Origin,
        default_ttl => Ctx#parse_ctx.default_ttl,
        default_class => Ctx#parse_ctx.default_class,
        base_dir => Ctx#parse_ctx.base_dir
    },
    case parse_file(FullPath, IncludeOpts) of
        {ok, Records} ->
            {ok, Ctx, Records};
        {error, ErrorDetail} ->
            %% Pass through error from included file
            %% Could add include context here if needed
            {error, ErrorDetail}
    end.

%% Construct full path relative to base directory
full_filename_path(Dir, Filename) when Dir =:= "" orelse Dir =:= <<>> ->
    Filename;
full_filename_path(BaseDir, Filename) ->
    filename:join(BaseDir, Filename).

%% RFC 3597 - Parse generic TYPE### syntax
%% Extract the numeric type from "TYPE123" format
-spec parse_generic_type(string()) -> {ok, dns:type()} | {error, term()}.
parse_generic_type("TYPE" ++ Rest) ->
    try list_to_integer(Rest) of
        TypeNum when TypeNum >= 0, TypeNum =< 65535 ->
            {ok, TypeNum};
        _ ->
            {error, {invalid_type_range, Rest}}
    catch
        error:badarg ->
            {error, {invalid_type_format, Rest}}
    end;
parse_generic_type(Other) ->
    {error, {invalid_type_syntax, Other}}.

%% RFC 3597 - Parse generic CLASS### syntax
%% Extract the numeric class from "CLASS32" format
-spec parse_generic_class(string()) -> {ok, dns:class()} | {error, term()}.
parse_generic_class("CLASS" ++ Rest) ->
    try list_to_integer(Rest) of
        ClassNum when ClassNum >= 0, ClassNum =< 65535 ->
            {ok, ClassNum};
        _ ->
            {error, {invalid_class_range, Rest}}
    catch
        error:badarg ->
            {error, {invalid_class_format, Rest}}
    end;
parse_generic_class(Other) ->
    {error, {invalid_class_syntax, Other}}.

%% RFC 3597 - Parse the entire RFC 3597 token: \# length hexdata
%% Input is like "\\# 4 C0000201" or "\\# 0"
-spec parse_rfc3597_token(string()) -> {ok, binary()} | {error, term()}.
parse_rfc3597_token(Token) ->
    %% Remove leading \# and whitespace
    case string:split(Token, " ", all) of
        ["\\#", LengthStr | HexParts] ->
            try list_to_integer(LengthStr) of
                Length ->
                    %% Concatenate all hex parts (they may be space-separated)
                    HexData = lists:flatten(HexParts),
                    parse_rfc3597_rdata(Length, list_to_binary(HexData))
            catch
                error:badarg ->
                    {error, {invalid_rfc3597_length, LengthStr}}
            end;
        _ ->
            {error, {invalid_rfc3597_format, Token}}
    end.

%% RFC 3597 - Parse generic RDATA format: \# length hexdata
%% Converts hex string to binary and validates length
-spec parse_rfc3597_rdata(integer(), binary()) -> {ok, binary()} | {error, term()}.
parse_rfc3597_rdata(Length, <<>>) when Length =:= 0 ->
    %% Empty RDATA is valid if length is 0
    {ok, <<>>};
parse_rfc3597_rdata(Length, HexData) ->
    %% Remove any whitespace from hex data
    CleanHex = binary:replace(HexData, <<" ">>, <<>>, [global]),
    %% Convert hex string to binary
    case hex_to_binary(CleanHex) of
        {ok, BinaryData} ->
            ActualLength = byte_size(BinaryData),
            case ActualLength of
                Length ->
                    {ok, BinaryData};
                _ ->
                    {error, {rfc3597_length_mismatch, Length, ActualLength}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Convert hexadecimal string to binary using OTP 26+ binary:decode_hex/1
-spec hex_to_binary(binary() | string()) -> {ok, binary()} | {error, term()}.
hex_to_binary(HexString) when is_list(HexString) ->
    hex_to_binary(list_to_binary(HexString));
hex_to_binary(HexBin) when is_binary(HexBin) ->
    try
        %% Validate hex string has even length (pairs of hex digits)
        {ok, binary:decode_hex(HexBin)}
    catch
        error:badarg ->
            {error, {invalid_hex_data, HexBin}}
    end.
