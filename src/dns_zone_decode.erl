-module(dns_zone_decode).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-endif.
?MODULEDOC(false).

% 4KB, a good default
-define(CHUNK_SIZE, 4096).

-include_lib("dns_erlang/include/dns.hrl").

-export([parse_file/2, parse_string/2, format_error/1]).

%% Type references from dns_zone
-type parse_options() :: dns_zone:parse_options().
-type error_detail() :: dns_zone:error_detail().
-type error_location() :: dns_zone:error_location().
-type error_type() :: dns_zone:error_type().

%% Parser context for maintaining state during parsing
-record(parse_ctx, {
    origin = <<>> :: dns:dname(),
    default_ttl = 0 :: dns:ttl(),
    default_class = ?DNS_CLASS_IN :: dns:class(),
    last_owner = <<>> :: dns:dname(),
    base_dir = "" :: file:filename_all(),
    filename = undefined :: file:filename_all() | undefined,
    source_lines = [] :: [string()]
}).

-type parse_ctx() :: #parse_ctx{}.

-type rdata() ::
    {int, integer()}
    | {string, string()}
    | {ipv4, string()}
    | {ipv6, string()}
    | {domain, string()}
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

%% Parse a zone file from disk with options.
-spec parse_file(file:filename(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
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

%% Parse zone file content from a string or binary with options.
-spec parse_string(binary() | string(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
parse_string(Data, Options) when is_list(Data) ->
    parse(Data, Options);
parse_string(Data, Options) when is_binary(Data) ->
    parse(binary_to_list(Data), Options).

%% Tokenizer function that yecc calls. Holds state {Device, Line, LexerContinuation}
%% and attempts to get tokens from the lexer, triggering file reads when needed.
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

%% Main parsing function. Tokenizes input and parses into DNS records.
-spec parse(string(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
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

%% Format a parse error into a human-readable string.
-spec format_error(dns_zone:error_detail()) -> iolist().
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
rdata_error_message(<<"ZONEMD">>, RData) when length(RData) < 4 ->
    {
        <<"Invalid ZONEMD record: expected 4 fields ", "(serial, scheme, algorithm, hash), got ",
            (integer_to_binary(length(RData)))/binary>>,
        <<"ZONEMD requires: serial scheme algorithm \"hexhash\"\n",
            "Example: example.com. IN ZONEMD 2025121100 1 1 \"F8857A5A89EF49FF...\"">>
    };
rdata_error_message(<<"ZONEMD">>, _RData) ->
    {
        <<"Invalid ZONEMD record: hash must be even-length hex string">>,
        <<"Hex strings must have an even number of characters">>
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
build_rdata("OPENPGPKEY", RData, Ctx) ->
    %% OPENPGPKEY format: base64-encoded data (single string)
    %% RFC 7929 - OpenPGP Public Key
    case RData of
        [{string, Base64Data}] when is_list(Base64Data) ->
            try
                Data = base64:decode(Base64Data),
                {ok, #dns_rrdata_openpgpkey{data = Data}}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"OPENPGPKEY">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"OPENPGPKEY">>, RData, Ctx)}
    end;
build_rdata("URI", RData, Ctx) ->
    %% URI format: priority weight target
    %% RFC 7553 - The Uniform Resource Identifier (URI) DNS Resource Record
    case RData of
        [{int, Priority}, {int, Weight}, {string, Target}] when
            is_integer(Priority), is_integer(Weight), is_list(Target)
        ->
            BinTarget = unicode:characters_to_binary(Target),
            case uri_string:normalize(BinTarget) of
                {error, _, _} ->
                    {error, make_rdata_error(<<"URI">>, RData, Ctx)};
                NormalizedTarget ->
                    {ok, #dns_rrdata_uri{
                        priority = Priority,
                        weight = Weight,
                        target = NormalizedTarget
                    }}
            end;
        _ ->
            {error, make_rdata_error(<<"URI">>, RData, Ctx)}
    end;
build_rdata("RESINFO", RData, Ctx) ->
    %% RESINFO format: text strings (same as TXT)
    %% RFC 9606 - Resource Information (RESINFO) DNS Resource Record
    case extract_strings(RData) of
        {ok, Strings} -> {ok, #dns_rrdata_resinfo{data = Strings}};
        {error, Reason} -> {error, make_semantic_error(Reason, Ctx)}
    end;
build_rdata("WALLET", RData, Ctx) ->
    %% WALLET format: base64-encoded data (single string)
    case RData of
        [{string, Base64Data}] when is_list(Base64Data) ->
            try
                Data = base64:decode(Base64Data),
                {ok, #dns_rrdata_wallet{data = Data}}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"WALLET">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"WALLET">>, RData, Ctx)}
    end;
build_rdata("SMIMEA", RData, Ctx) ->
    %% SMIMEA format: usage selector matching-type cert-data(hex string)
    %% RFC 8162 - S/MIME cert association (similar to TLSA)
    case RData of
        [{int, Usage}, {int, Selector}, {int, MatchingType}, {string, CertHex}] when
            is_integer(Usage), is_integer(Selector), is_integer(MatchingType), is_list(CertHex)
        ->
            case hex_to_binary(CertHex) of
                {ok, Cert} ->
                    {ok, #dns_rrdata_smimea{
                        usage = Usage,
                        selector = Selector,
                        matching_type = MatchingType,
                        certificate = Cert
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"SMIMEA">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"SMIMEA">>, RData, Ctx)}
    end;
build_rdata("EUI48", RData, Ctx) ->
    %% EUI48 format: 48-bit MAC address (hex string, 12 hex digits)
    %% RFC 7043 - EUI-48 address
    case RData of
        [{string, HexAddr}] when is_list(HexAddr) ->
            case hex_to_binary(HexAddr) of
                {ok, Addr} when byte_size(Addr) =:= 6 ->
                    {ok, #dns_rrdata_eui48{address = Addr}};
                _ ->
                    {error, make_rdata_error(<<"EUI48">>, RData, Ctx)}
            end;
        [{domain, HexAddr}] when is_list(HexAddr) ->
            %% Hex strings may be parsed as domain names
            case hex_to_binary(HexAddr) of
                {ok, Addr} when byte_size(Addr) =:= 6 ->
                    {ok, #dns_rrdata_eui48{address = Addr}};
                _ ->
                    {error, make_rdata_error(<<"EUI48">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"EUI48">>, RData, Ctx)}
    end;
build_rdata("EUI64", RData, Ctx) ->
    %% EUI64 format: 64-bit MAC address (hex string, 16 hex digits)
    %% RFC 7043 - EUI-64 address
    case RData of
        [{string, HexAddr}] when is_list(HexAddr) ->
            case hex_to_binary(HexAddr) of
                {ok, Addr} when byte_size(Addr) =:= 8 ->
                    {ok, #dns_rrdata_eui64{address = Addr}};
                _ ->
                    {error, make_rdata_error(<<"EUI64">>, RData, Ctx)}
            end;
        [{domain, HexAddr}] when is_list(HexAddr) ->
            %% Hex strings may be parsed as domain names
            case hex_to_binary(HexAddr) of
                {ok, Addr} when byte_size(Addr) =:= 8 ->
                    {ok, #dns_rrdata_eui64{address = Addr}};
                _ ->
                    {error, make_rdata_error(<<"EUI64">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"EUI64">>, RData, Ctx)}
    end;
build_rdata("DS", RData, Ctx) ->
    %% DS format: keytag algorithm digest-type digest(hex string)
    %% RFC 4034 - Delegation Signer
    %% Hex strings are often unquoted, so they may be parsed as labels/domains
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
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {domain, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            %% Hex strings are unquoted and may be parsed as domain names
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
build_rdata("CDS", RData, Ctx) ->
    %% CDS format: keytag algorithm digest-type digest(hex string)
    %% RFC 7344 - Child DS
    %% Same format as DS
    case RData of
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {string, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            case hex_to_binary(DigestHex) of
                {ok, Digest} ->
                    {ok, #dns_rrdata_cds{
                        keytag = KeyTag,
                        alg = Alg,
                        digest_type = DigestType,
                        digest = Digest
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"CDS">>, RData, Ctx)}
            end;
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {domain, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            %% Hex strings are unquoted and may be parsed as domain names
            case hex_to_binary(DigestHex) of
                {ok, Digest} ->
                    {ok, #dns_rrdata_cds{
                        keytag = KeyTag,
                        alg = Alg,
                        digest_type = DigestType,
                        digest = Digest
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"CDS">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"CDS">>, RData, Ctx)}
    end;
build_rdata("DLV", RData, Ctx) ->
    %% DLV format: keytag algorithm digest-type digest(hex string)
    %% RFC 4431 - DNSSEC Lookaside Validation
    %% Same format as DS
    case RData of
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {string, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            case hex_to_binary(DigestHex) of
                {ok, Digest} ->
                    {ok, #dns_rrdata_dlv{
                        keytag = KeyTag,
                        alg = Alg,
                        digest_type = DigestType,
                        digest = Digest
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"DLV">>, RData, Ctx)}
            end;
        [{int, KeyTag}, {int, Alg}, {int, DigestType}, {domain, DigestHex}] when
            is_integer(KeyTag), is_integer(Alg), is_integer(DigestType), is_list(DigestHex)
        ->
            %% Hex strings are unquoted and may be parsed as domain names
            case hex_to_binary(DigestHex) of
                {ok, Digest} ->
                    {ok, #dns_rrdata_dlv{
                        keytag = KeyTag,
                        alg = Alg,
                        digest_type = DigestType,
                        digest = Digest
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"DLV">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"DLV">>, RData, Ctx)}
    end;
build_rdata("DNSKEY", RData, Ctx) ->
    %% DNSKEY format: flags protocol algorithm public-key(base64 string)
    %% RFC 4034 - DNS Public Key
    %% Base64 strings are often unquoted, so they may be parsed as labels/domains
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
        [{int, Flags}, {int, Protocol}, {int, Alg}, {domain, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            %% Base64 strings are unquoted and may be parsed as domain names
            %% Convert to string and try to decode
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
build_rdata("CDNSKEY", RData, Ctx) ->
    %% CDNSKEY format: flags protocol algorithm public-key(base64 string)
    %% RFC 7344 - Child DNSKEY
    %% Same format as DNSKEY
    case RData of
        [{int, Flags}, {int, Protocol}, {int, Alg}, {string, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            try
                PublicKey = base64:decode(PublicKeyB64),
                %% Calculate keytag (RFC 4034 Appendix B)
                KeyTag = calculate_keytag(Flags, Protocol, Alg, PublicKey),
                {ok, #dns_rrdata_cdnskey{
                    flags = Flags,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey,
                    keytag = KeyTag
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"CDNSKEY">>, RData, Ctx)}
            end;
        [{int, Flags}, {int, Protocol}, {int, Alg}, {domain, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            %% Base64 strings are unquoted and may be parsed as domain names
            try
                PublicKey = base64:decode(PublicKeyB64),
                %% Calculate keytag (RFC 4034 Appendix B)
                KeyTag = calculate_keytag(Flags, Protocol, Alg, PublicKey),
                {ok, #dns_rrdata_cdnskey{
                    flags = Flags,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey,
                    keytag = KeyTag
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"CDNSKEY">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"CDNSKEY">>, RData, Ctx)}
    end;
build_rdata("KEY", RData, Ctx) ->
    %% KEY format: flags protocol algorithm public-key(base64 string)
    %% RFC 2535 - DNS Security Extensions
    %% Similar to DNSKEY but with different flag structure
    %% Base64 strings are often unquoted, so they may be parsed as labels/domains
    case RData of
        [{int, Flags}, {int, Protocol}, {int, Alg}, {string, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            try
                PublicKey = base64:decode(PublicKeyB64),
                %% Extract flag fields from 16-bit flags value
                %% Type (bits 0-1), XT (bit 3), NameType (bits 6-7), Sig (bits 12-15)
                Type = (Flags bsr 14) band 16#3,
                XT = (Flags bsr 12) band 16#1,
                NameType = (Flags bsr 8) band 16#3,
                Sig = Flags band 16#F,
                {ok, #dns_rrdata_key{
                    type = Type,
                    xt = XT,
                    name_type = NameType,
                    sig = Sig,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"KEY">>, RData, Ctx)}
            end;
        [{int, Flags}, {int, Protocol}, {int, Alg}, {domain, PublicKeyB64}] when
            is_integer(Flags), is_integer(Protocol), is_integer(Alg), is_list(PublicKeyB64)
        ->
            %% Base64 strings are unquoted and may be parsed as domain names
            %% Convert to string and try to decode
            try
                PublicKey = base64:decode(PublicKeyB64),
                %% Extract flag fields from 16-bit flags value
                Type = (Flags bsr 14) band 16#3,
                XT = (Flags bsr 12) band 16#1,
                NameType = (Flags bsr 8) band 16#3,
                Sig = Flags band 16#F,
                {ok, #dns_rrdata_key{
                    type = Type,
                    xt = XT,
                    name_type = NameType,
                    sig = Sig,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"KEY">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"KEY">>, RData, Ctx)}
    end;
build_rdata("SVCB", RData, Ctx) ->
    %% RFC 9460 - Service Binding
    %% SVCB format: priority target [svcparams...]
    %% Service parameters are key=value pairs or just key (for no-default-alpn)
    %% Note: TargetName "." in AliasMode (priority=0) means "service is not available"
    case RData of
        [{int, Priority}, {domain, Target}] when is_integer(Priority), is_list(Target) ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_svcb{
                svc_priority = Priority,
                target_name = TargetName,
                svc_params = #{}
            }};
        [{int, Priority}, {domain, Target} | SvcParams] when
            is_integer(Priority), is_list(Target)
        ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            case parse_svcb_params_from_rdata(SvcParams, Ctx) of
                {ok, Params} ->
                    {ok, #dns_rrdata_svcb{
                        svc_priority = Priority,
                        target_name = TargetName,
                        svc_params = Params
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, make_rdata_error(<<"SVCB">>, RData, Ctx)}
    end;
build_rdata("HTTPS", RData, Ctx) ->
    %% RFC 9460 - HTTPS-specific Service Binding: same as SVCB but different type number
    case RData of
        [{int, Priority}, {domain, Target}] when is_integer(Priority), is_list(Target) ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_https{
                svc_priority = Priority,
                target_name = TargetName,
                svc_params = #{}
            }};
        [{int, Priority}, {domain, Target} | SvcParams] when
            is_integer(Priority), is_list(Target)
        ->
            TargetName = resolve_name(Target, Ctx#parse_ctx.origin),
            case parse_svcb_params_from_rdata(SvcParams, Ctx) of
                {ok, Params} ->
                    {ok, #dns_rrdata_https{
                        svc_priority = Priority,
                        target_name = TargetName,
                        svc_params = Params
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, make_rdata_error(<<"HTTPS">>, RData, Ctx)}
    end;
build_rdata("RRSIG", RData, Ctx) ->
    %% RRSIG format:
    %%      type_covered alg labels original_ttl expiration inception keytag signers_name signature
    %% RFC 4034 - DNSSEC signature
    %% type_covered can be a record type name (like "DS", "NSEC") parsed as rtype or domain
    %% signature is base64-encoded and may be unquoted (parsed as domain/string)
    case RData of
        %% type_covered parsed as domain (from rtype token or label),
        %% then integers, then signers_name, then signature as string or domain (unquoted base64)
        [
            {domain, TypeCovered},
            {int, Alg},
            {int, Labels},
            {int, OriginalTTL},
            {int, Expiration},
            {int, Inception},
            {int, KeyTag},
            {domain, SignersName},
            SignatureToken
        ] when
            is_list(TypeCovered),
            is_integer(Alg),
            is_integer(Labels),
            is_integer(OriginalTTL),
            is_integer(Expiration),
            is_integer(Inception),
            is_integer(KeyTag),
            is_list(SignersName),
            is_tuple(SignatureToken),
            tuple_size(SignatureToken) =:= 2,
            (element(1, SignatureToken) =:= string orelse element(1, SignatureToken) =:= domain)
        ->
            SignatureB64 = element(2, SignatureToken),
            TypeCoveredNum = type_to_number(TypeCovered),
            SignersNameBin = resolve_name(SignersName, Ctx#parse_ctx.origin),
            try
                Signature = base64:decode(SignatureB64),
                {ok, #dns_rrdata_rrsig{
                    type_covered = TypeCoveredNum,
                    alg = Alg,
                    labels = Labels,
                    original_ttl = OriginalTTL,
                    expiration = Expiration,
                    inception = Inception,
                    keytag = KeyTag,
                    signers_name = SignersNameBin,
                    signature = Signature
                }}
            catch
                _:_ ->
                    {error, make_rdata_error(<<"RRSIG">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"RRSIG">>, RData, Ctx)}
    end;
build_rdata("NSEC", RData, Ctx) ->
    %% NSEC format: next_dname type1 type2 type3 ...
    %% RFC 4034 - DNSSEC authenticated denial of existence
    %% Types are record type names (like "NS", "SOA", "RRSIG") parsed as rtype or domain tokens
    case RData of
        [{domain, NextDName} | Types] when is_list(NextDName), length(Types) > 0 ->
            %% Parse type names - they can be rtype tokens (parsed as domain) or labels
            TypeNums = lists:map(
                fun
                    ({domain, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    ({rtype, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    (_) ->
                        %% Invalid type, skip or use 0
                        0
                end,
                Types
            ),
            %% Filter out invalid types (0)
            ValidTypes = [T || T <- TypeNums, T =/= 0],
            NextDNameBin = resolve_name(NextDName, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_nsec{
                next_dname = NextDNameBin,
                types = ValidTypes
            }};
        _ ->
            {error, make_rdata_error(<<"NSEC">>, RData, Ctx)}
    end;
build_rdata("NXT", RData, Ctx) ->
    %% NXT format: next_dname type1 type2 type3 ...
    %% RFC 2535 - DNSSEC authenticated denial of existence (obsoleted by NSEC)
    %% Similar format to NSEC
    case RData of
        [{domain, NextDName} | Types] when is_list(NextDName), length(Types) > 0 ->
            %% Parse type names - they can be rtype tokens (parsed as domain) or labels
            TypeNums = lists:map(
                fun
                    ({domain, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    ({rtype, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    (_) ->
                        %% Invalid type, skip or use 0
                        0
                end,
                Types
            ),
            %% Filter out invalid types (0)
            ValidTypes = [T || T <- TypeNums, T =/= 0],
            NextDNameBin = resolve_name(NextDName, Ctx#parse_ctx.origin),
            {ok, #dns_rrdata_nxt{
                dname = NextDNameBin,
                types = ValidTypes
            }};
        _ ->
            {error, make_rdata_error(<<"NXT">>, RData, Ctx)}
    end;
build_rdata("NSEC3", RData, Ctx) ->
    %% NSEC3 format: hash_alg flags iterations salt hash type1 type2 type3 ...
    %% RFC 5155 - DNSSEC Hashed Authenticated Denial of Existence
    %% Salt can be "-" for empty, otherwise hex string
    %% Hash is base32hex encoded
    case RData of
        [{int, HashAlg}, {int, Flags}, {int, Iterations}, SaltToken, HashToken | Types] when
            is_integer(HashAlg),
            is_integer(Flags),
            is_integer(Iterations),
            length(Types) > 0
        ->
            %% Parse salt (can be "-" for empty, or hex string)
            Salt =
                case SaltToken of
                    {string, "-"} ->
                        <<>>;
                    {string, SaltHex} when is_list(SaltHex) ->
                        case hex_to_binary(SaltHex) of
                            {ok, S} -> S;
                            {error, _} -> <<>>
                        end;
                    {domain, "-"} ->
                        <<>>;
                    {domain, SaltHex} when is_list(SaltHex) ->
                        case hex_to_binary(SaltHex) of
                            {ok, S} -> S;
                            {error, _} -> <<>>
                        end;
                    _ ->
                        <<>>
                end,
            %% Parse hash (base32hex encoded)
            Hash =
                case HashToken of
                    {string, HashB32} when is_list(HashB32) ->
                        try
                            base32:decode(list_to_binary(HashB32), [hex])
                        catch
                            _:_ -> <<>>
                        end;
                    {domain, HashB32} when is_list(HashB32) ->
                        try
                            base32:decode(list_to_binary(HashB32), [hex])
                        catch
                            _:_ -> <<>>
                        end;
                    _ ->
                        <<>>
                end,
            %% Parse type names
            TypeNums = lists:map(
                fun
                    ({domain, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    ({rtype, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    (_) ->
                        0
                end,
                Types
            ),
            ValidTypes = [T || T <- TypeNums, T =/= 0],
            OptOut = (Flags band 16#01) =/= 0,
            {ok, #dns_rrdata_nsec3{
                hash_alg = HashAlg,
                opt_out = OptOut,
                iterations = Iterations,
                salt = Salt,
                hash = Hash,
                types = ValidTypes
            }};
        _ ->
            {error, make_rdata_error(<<"NSEC3">>, RData, Ctx)}
    end;
build_rdata("NSEC3PARAM", RData, Ctx) ->
    %% NSEC3PARAM format: hash_alg flags iterations salt
    %% RFC 5155 - NSEC3 Parameters
    %% Salt can be "-" for empty, otherwise hex string
    case RData of
        [{int, HashAlg}, {int, Flags}, {int, Iterations}, SaltToken] when
            is_integer(HashAlg), is_integer(Flags), is_integer(Iterations)
        ->
            %% Parse salt (can be "-" for empty, or hex string)
            Salt =
                case SaltToken of
                    {string, "-"} ->
                        <<>>;
                    {string, SaltHex} when is_list(SaltHex) ->
                        case hex_to_binary(SaltHex) of
                            {ok, S} -> S;
                            {error, _} -> <<>>
                        end;
                    {domain, "-"} ->
                        <<>>;
                    {domain, SaltHex} when is_list(SaltHex) ->
                        case hex_to_binary(SaltHex) of
                            {ok, S} -> S;
                            {error, _} -> <<>>
                        end;
                    _ ->
                        <<>>
                end,
            {ok, #dns_rrdata_nsec3param{
                hash_alg = HashAlg,
                flags = Flags,
                iterations = Iterations,
                salt = Salt
            }};
        _ ->
            {error, make_rdata_error(<<"NSEC3PARAM">>, RData, Ctx)}
    end;
build_rdata("CSYNC", RData, Ctx) ->
    %% CSYNC format: soa_serial flags type1 type2 type3 ...
    %% RFC 7477 - Child-to-Parent Synchronization in DNS
    case RData of
        [{int, SOASerial}, {int, Flags} | Types] when
            is_integer(SOASerial), is_integer(Flags), length(Types) > 0
        ->
            %% Parse type names - they can be rtype tokens (parsed as domain) or labels
            TypeNums = lists:map(
                fun
                    ({domain, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    ({rtype, TypeName}) when is_list(TypeName) ->
                        type_to_number(TypeName);
                    (_) ->
                        %% Invalid type, skip or use 0
                        0
                end,
                Types
            ),
            %% Filter out invalid types (0)
            ValidTypes = [T || T <- TypeNums, T =/= 0],
            {ok, #dns_rrdata_csync{
                soa_serial = SOASerial,
                flags = Flags,
                types = ValidTypes
            }};
        _ ->
            {error, make_rdata_error(<<"CSYNC">>, RData, Ctx)}
    end;
build_rdata("DSYNC", RData, Ctx) ->
    %% DSYNC format: rrtype scheme port target
    %% RFC 9859 - Delegation Synchronization (DSYNC) DNS Resource Record
    case RData of
        [{domain, RRTypeName}, {int, Scheme}, {int, Port}, {domain, Target}] when
            is_list(RRTypeName),
            is_integer(Scheme),
            Scheme >= 0,
            Scheme =< 255,
            is_integer(Port),
            is_list(Target)
        ->
            RRType = type_to_number(RRTypeName),
            case RRType of
                0 ->
                    {error, make_rdata_error(<<"DSYNC">>, RData, Ctx)};
                _ ->
                    {ok, #dns_rrdata_dsync{
                        rrtype = RRType,
                        scheme = Scheme,
                        port = Port,
                        target = resolve_name(Target, Ctx#parse_ctx.origin)
                    }}
            end;
        _ ->
            {error, make_rdata_error(<<"DSYNC">>, RData, Ctx)}
    end;
build_rdata("ZONEMD", RData, Ctx) ->
    %% ZONEMD format: serial scheme algorithm hash(hex string)
    %% RFC 8976 - Zone Metadata
    case RData of
        [{int, Serial}, {int, Scheme}, {int, Algorithm}, {domain, HashHex}] when
            is_integer(Serial), is_integer(Scheme), is_integer(Algorithm), is_list(HashHex)
        ->
            %% Hash may be parsed as domain (unquoted hex string)
            case hex_to_binary(HashHex) of
                {ok, Hash} ->
                    {ok, #dns_rrdata_zonemd{
                        serial = Serial,
                        scheme = Scheme,
                        algorithm = Algorithm,
                        hash = Hash
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"ZONEMD">>, RData, Ctx)}
            end;
        [{int, Serial}, {int, Scheme}, {int, Algorithm}, {string, HashHex}] when
            is_integer(Serial), is_integer(Scheme), is_integer(Algorithm), is_list(HashHex)
        ->
            %% Hash parsed as quoted string
            case hex_to_binary(HashHex) of
                {ok, Hash} ->
                    {ok, #dns_rrdata_zonemd{
                        serial = Serial,
                        scheme = Scheme,
                        algorithm = Algorithm,
                        hash = Hash
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"ZONEMD">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"ZONEMD">>, RData, Ctx)}
    end;
build_rdata("LOC", RData, Ctx) ->
    %% LOC format: lat lon alt size horiz_prec vert_prec
    %% RFC 1876 - Geographic Location
    %% Simplified format: integers for lat, lon, alt, size, horiz, vert
    %% Coordinates are in 1/1000th of a second (milliseconds of arc)
    case RData of
        [
            {int, Lat},
            {int, Lon},
            {int, Alt},
            {int, Size},
            {int, Horiz},
            {int, Vert}
        ] when
            is_integer(Lat),
            is_integer(Lon),
            is_integer(Alt),
            is_integer(Size),
            is_integer(Horiz),
            is_integer(Vert)
        ->
            {ok, #dns_rrdata_loc{
                size = Size,
                horiz = Horiz,
                vert = Vert,
                lat = Lat,
                lon = Lon,
                alt = Alt
            }};
        _ ->
            {error, make_rdata_error(<<"LOC">>, RData, Ctx)}
    end;
build_rdata("IPSECKEY", RData, Ctx) ->
    %% IPSECKEY format: precedence algorithm gateway public_key(hex)
    %% RFC 4025 - Storing IPsec Keying Material in DNS
    %% Gateway can be IPv4, IPv6, or domain name (0 length = none)
    case RData of
        [{int, Precedence}, {int, Alg}, GatewayToken, {string, PublicKeyHex}] when
            is_integer(Precedence), is_integer(Alg), is_list(PublicKeyHex)
        ->
            Gateway = parse_ipseckey_gateway(GatewayToken, Ctx),
            case hex_to_binary(PublicKeyHex) of
                {ok, PublicKey} ->
                    {ok, #dns_rrdata_ipseckey{
                        precedence = Precedence,
                        alg = Alg,
                        gateway = Gateway,
                        public_key = PublicKey
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"IPSECKEY">>, RData, Ctx)}
            end;
        [{int, Precedence}, {int, Alg}, GatewayToken, {domain, PublicKeyHex}] when
            is_integer(Precedence), is_integer(Alg), is_list(PublicKeyHex)
        ->
            %% Hex strings may be parsed as domain names
            Gateway = parse_ipseckey_gateway(GatewayToken, Ctx),
            case hex_to_binary(PublicKeyHex) of
                {ok, PublicKey} ->
                    {ok, #dns_rrdata_ipseckey{
                        precedence = Precedence,
                        alg = Alg,
                        gateway = Gateway,
                        public_key = PublicKey
                    }};
                {error, _Reason} ->
                    {error, make_rdata_error(<<"IPSECKEY">>, RData, Ctx)}
            end;
        _ ->
            {error, make_rdata_error(<<"IPSECKEY">>, RData, Ctx)}
    end;
build_rdata(Type, _RData, Ctx) ->
    %% Unsupported or complex record types
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
type_to_number("OPENPGPKEY") ->
    ?DNS_TYPE_OPENPGPKEY;
type_to_number("CSYNC") ->
    ?DNS_TYPE_CSYNC;
type_to_number("SMIMEA") ->
    ?DNS_TYPE_SMIMEA;
type_to_number("URI") ->
    ?DNS_TYPE_URI;
type_to_number("RESINFO") ->
    ?DNS_TYPE_RESINFO;
type_to_number("DSYNC") ->
    ?DNS_TYPE_DSYNC;
type_to_number("WALLET") ->
    ?DNS_TYPE_WALLET;
type_to_number("EUI48") ->
    ?DNS_TYPE_EUI48;
type_to_number("EUI64") ->
    ?DNS_TYPE_EUI64;
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
type_to_number("ZONEMD") ->
    ?DNS_TYPE_ZONEMD;
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

%% Parse IPSECKEY gateway field (can be IPv4, IPv6, domain name, or "." for none)
-spec parse_ipseckey_gateway(rdata(), parse_ctx()) -> inet:ip_address() | dns:dname() | <<>>.
parse_ipseckey_gateway({domain, "."}, _Ctx) ->
    <<>>;
parse_ipseckey_gateway({domain, GatewayStr}, Ctx) when is_list(GatewayStr) ->
    %% Try to parse as IP address first, then fall back to domain name
    case inet:parse_address(GatewayStr) of
        {ok, IP} -> IP;
        {error, _} -> resolve_name(GatewayStr, Ctx#parse_ctx.origin)
    end;
parse_ipseckey_gateway({string, GatewayStr}, Ctx) when is_list(GatewayStr) ->
    %% Try to parse as IP address first, then fall back to domain name
    case inet:parse_address(GatewayStr) of
        {ok, IP} -> IP;
        {error, _} -> resolve_name(GatewayStr, Ctx#parse_ctx.origin)
    end;
parse_ipseckey_gateway(_, _Ctx) ->
    <<>>.

%% Parse SVCB/HTTPS service parameters directly from RDATA
%% Handles both parsed key=value pairs and labels containing = (from lexer)
-spec parse_svcb_params_from_rdata([rdata()], parse_ctx()) ->
    {ok, dns:svcb_svc_params()} | {error, error_detail()}.
parse_svcb_params_from_rdata(SvcParams, Ctx) ->
    parse_svcb_params_from_rdata(SvcParams, Ctx, #{}).

-spec parse_svcb_params_from_rdata([rdata()], parse_ctx(), dns:svcb_svc_params()) ->
    {ok, dns:svcb_svc_params()} | {error, error_detail()}.
parse_svcb_params_from_rdata([], Ctx, Acc) ->
    validate_mandatory_params(Acc, Ctx);
parse_svcb_params_from_rdata([{domain, "no-default-alpn"} | Rest], Ctx, Acc) ->
    NewAcc = Acc#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none},
    parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
parse_svcb_params_from_rdata([{domain, "alpn=" ++ Alpn} | Rest], Ctx, Acc) ->
    Protocols = [list_to_binary(string:trim(P)) || P <- string:split(Alpn, ",", all), P =/= ""],
    NewAcc = Acc#{?DNS_SVCB_PARAM_ALPN => Protocols},
    parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
parse_svcb_params_from_rdata([{domain, "port=" ++ PortStr} | Rest], Ctx, Acc) ->
    case string:to_integer(PortStr) of
        {Port, ""} when Port >= 0, Port =< 65535 ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_PORT => Port},
            parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
        _ ->
            {error, make_semantic_error({invalid_port, PortStr}, Ctx)}
    end;
parse_svcb_params_from_rdata([{domain, "ipv4hint=" ++ Value} | Rest], Ctx, Acc) ->
    IPs = [string:trim(IP) || IP <- string:split(Value, ",", all), IP =/= ""],
    case parse_ipv4_list(IPs, Ctx) of
        {ok, IPList} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_IPV4HINT => IPList},
            parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
        {error, Reason} ->
            {error, Reason}
    end;
parse_svcb_params_from_rdata([{domain, "ipv6hint=" ++ Value} | Rest], Ctx, Acc) ->
    IPs = [string:trim(IP) || IP <- string:split(Value, ",", all), IP =/= ""],
    case parse_ipv6_list(IPs, Ctx) of
        {ok, IPList} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_IPV6HINT => IPList},
            parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
        {error, Reason} ->
            {error, Reason}
    end;
parse_svcb_params_from_rdata([{domain, "mandatory=" ++ Mandatory} | Rest], Ctx, Acc) ->
    Keys = [string:trim(K) || K <- string:split(Mandatory, ",", all), K =/= ""],
    case parse_mandatory_keys(Keys, Ctx) of
        {ok, KeyNums} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_MANDATORY => KeyNums},
            parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
        {error, Reason} ->
            {error, Reason}
    end;
parse_svcb_params_from_rdata([{domain, "ech="}, {string, Value} | Rest], Ctx, Acc) ->
    try
        ECHConfig = base64:decode(Value),
        NewAcc = Acc#{?DNS_SVCB_PARAM_ECH => ECHConfig},
        parse_svcb_params_from_rdata(Rest, Ctx, NewAcc)
    catch
        _:Reason ->
            {error, make_semantic_error({invalid_svcparam_format, Reason}, Ctx)}
    end;
parse_svcb_params_from_rdata([{domain, "key" ++ RestStr}, {string, Value} | Rest], Ctx, Acc) ->
    %% Check for unknown key with quoted value: keyNNNNN="value"
    case string:split(RestStr, "=", leading) of
        [KeyNumStr, ""] ->
            case string:to_integer(KeyNumStr) of
                {KeyNum, ""} when KeyNum >= 0, KeyNum =< 65535 ->
                    ValueBin =
                        try
                            base64:decode(Value)
                        catch
                            _:_ -> list_to_binary(Value)
                        end,
                    NewAcc = Acc#{KeyNum => ValueBin},
                    parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
                _ ->
                    {error, make_semantic_error({invalid_key_number, KeyNumStr}, Ctx)}
            end;
        _ ->
            %% Not keyNNNNN= format, error
            {error, make_semantic_error({invalid_svcparam_format, RestStr}, Ctx)}
    end;
parse_svcb_params_from_rdata([{domain, ParamStr}, {string, _} | _], Ctx, _) ->
    {error, make_semantic_error({invalid_svcparam_format, ParamStr}, Ctx)};
parse_svcb_params_from_rdata([{domain, "key" ++ KeyNumStr} | Rest], Ctx, Acc) ->
    %% keyNNNNN (no value, like no-default-alpn)
    case string:to_integer(KeyNumStr) of
        {KeyNum, ""} when KeyNum >= 0, KeyNum =< 65535 ->
            NewAcc = Acc#{KeyNum => none},
            parse_svcb_params_from_rdata(Rest, Ctx, NewAcc);
        _ ->
            {error, make_semantic_error({invalid_svcparam_format, KeyNumStr}, Ctx)}
    end;
parse_svcb_params_from_rdata([Other | _], Ctx, _Acc) ->
    {error, make_semantic_error({invalid_svcparam_format, Other}, Ctx)}.

%% Parse mandatory parameter keys (e.g., "alpn,port" -> [1, 3])
-spec parse_mandatory_keys([string()], parse_ctx()) ->
    {ok, [dns:uint16()]} | {error, error_detail()}.
parse_mandatory_keys(Keys, Ctx) ->
    parse_mandatory_keys(Keys, Ctx, []).

-spec parse_mandatory_keys([string()], parse_ctx(), [dns:uint16()]) ->
    {ok, [dns:uint16()]} | {error, error_detail()}.
parse_mandatory_keys([], _Ctx, Acc) ->
    {ok, lists:reverse(Acc)};
parse_mandatory_keys(["alpn" | Rest], Ctx, Acc) ->
    parse_mandatory_keys(Rest, Ctx, [?DNS_SVCB_PARAM_ALPN | Acc]);
parse_mandatory_keys(["no-default-alpn" | Rest], Ctx, Acc) ->
    parse_mandatory_keys(Rest, Ctx, [?DNS_SVCB_PARAM_NO_DEFAULT_ALPN | Acc]);
parse_mandatory_keys(["port" | Rest], Ctx, Acc) ->
    parse_mandatory_keys(Rest, Ctx, [?DNS_SVCB_PARAM_PORT | Acc]);
parse_mandatory_keys(["ipv4hint" | Rest], Ctx, Acc) ->
    parse_mandatory_keys(Rest, Ctx, [?DNS_SVCB_PARAM_IPV4HINT | Acc]);
parse_mandatory_keys(["ipv6hint" | Rest], Ctx, Acc) ->
    parse_mandatory_keys(Rest, Ctx, [?DNS_SVCB_PARAM_IPV6HINT | Acc]);
parse_mandatory_keys(["key" ++ IntStr | Rest], Ctx, Acc) ->
    KeyNum =
        case string:to_integer(IntStr) of
            {Num, ""} when Num >= 0, Num =< 65535 -> Num;
            _ -> undefined
        end,
    parse_mandatory_keys(Rest, Ctx, [KeyNum | Acc]);
parse_mandatory_keys([Key | _], Ctx, _) ->
    {error, make_semantic_error({invalid_mandatory_key, Key}, Ctx)}.

%% Validate mandatory parameter self-consistency
%% RFC 9460: Keys listed in mandatory parameter must exist in SvcParams
%% and mandatory (key 0) cannot reference itself
-spec validate_mandatory_params(dns:svcb_svc_params(), parse_ctx() | undefined) ->
    {ok, dns:svcb_svc_params()} | {error, error_detail()}.
validate_mandatory_params(#{?DNS_SVCB_PARAM_MANDATORY := MandatoryKeys} = SvcParams, Ctx) ->
    %% Check that mandatory doesn't reference itself (key 0)
    case lists:member(?DNS_SVCB_PARAM_MANDATORY, MandatoryKeys) of
        true ->
            Error = {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY},
            {error, make_semantic_error(Error, Ctx)};
        false ->
            %% Check that all mandatory keys exist in SvcParams
            MissingKeys = [K || K <- MandatoryKeys, not maps:is_key(K, SvcParams)],
            case MissingKeys of
                [] ->
                    {ok, SvcParams};
                _ ->
                    Error = {missing_mandatory_keys, MissingKeys},
                    {error, make_semantic_error(Error, Ctx)}
            end
    end;
validate_mandatory_params(SvcParams, _) ->
    {ok, SvcParams}.

%% Parse a list of IPv4 addresses
-spec parse_ipv4_list([string()], parse_ctx()) ->
    {ok, [inet:ip4_address()]} | {error, error_detail()}.
parse_ipv4_list(IPs, Ctx) ->
    parse_ipv4_list(IPs, Ctx, []).

-spec parse_ipv4_list([string()], parse_ctx(), [inet:ip4_address()]) ->
    {ok, [inet:ip4_address()]} | {error, error_detail()}.
parse_ipv4_list([], _Ctx, Acc) ->
    {ok, lists:reverse(Acc)};
parse_ipv4_list([IP | Rest], Ctx, Acc) ->
    case parse_ipv4(IP) of
        {ok, IPAddr} ->
            parse_ipv4_list(Rest, Ctx, [IPAddr | Acc]);
        {error, Reason} ->
            {error, make_semantic_error({invalid_ipv4_in_hint, IP, Reason}, Ctx)}
    end.

%% Parse a list of IPv6 addresses
-spec parse_ipv6_list([string()], parse_ctx()) ->
    {ok, [inet:ip6_address()]} | {error, error_detail()}.
parse_ipv6_list(IPs, Ctx) ->
    parse_ipv6_list(IPs, Ctx, []).

-spec parse_ipv6_list([string()], parse_ctx(), [inet:ip6_address()]) ->
    {ok, [inet:ip6_address()]} | {error, error_detail()}.
parse_ipv6_list([], _Ctx, Acc) ->
    {ok, lists:reverse(Acc)};
parse_ipv6_list([IP | Rest], Ctx, Acc) ->
    case parse_ipv6(IP) of
        {ok, IPAddr} ->
            parse_ipv6_list(Rest, Ctx, [IPAddr | Acc]);
        {error, Reason} ->
            {error, make_semantic_error({invalid_ipv6_in_hint, IP, Reason}, Ctx)}
    end.
