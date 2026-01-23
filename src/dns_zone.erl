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
    dns_zone_decode:parse_file(Filename, Options).

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
    dns_zone_decode:parse_string(Data, Options);
parse_string(Data, Options) when is_binary(Data) ->
    dns_zone_decode:parse_string(Data, Options).

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
format_error(Error) ->
    dns_zone_decode:format_error(Error).
