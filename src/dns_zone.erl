-module(dns_zone).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
DNS Zone File Parser and Encoder

This module provides functionality to parse and encode DNS zone files according to
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

### Parsing

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

### Encoding

```erl
% Encode a single record
RR = #dns_rr{
    name = <<"www.example.com.">>,
    type = ?DNS_TYPE_A,
    class = ?DNS_CLASS_IN,
    ttl = 3600,
    data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
},
Line = dns_zone:encode_rr(RR, #{origin => <<"example.com.">>, relative_names => true}).
% Returns: "www 3600 IN A 192.0.2.1"

% Encode a complete zone
Records = [...],
ZoneData = dns_zone:encode_string(Records, <<"example.com.">>, #{default_ttl => 3600}).

% Write zone to file
ok = dns_zone:encode_file(Records, <<"example.com.">>, "output.zone").
```
""").

%% Public API
-export([parse_file/1, parse_file/2]).
-export([parse_string/1, parse_string/2]).
-export([encode_file/3, encode_file/4]).
-export([encode_string/2, encode_string/3]).
-export([encode_rr/1, encode_rr/2]).
-export([encode_rdata/2]).
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
    file => file:filename_all() | undefined
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

-export_type([parse_options/0, encode_options/0, error_detail/0, error_location/0, error_type/0]).

?DOC("""
Options for encoding zone files.

- `origin => Domain` - Origin domain for relative name calculation (default: `<<>>`)
- `relative_names => boolean()` - Use @ and relative names (default: `true`)
- `ttl_format => seconds | units` - TTL format: `3600` or `1h` (default: `seconds`)
- `default_ttl => TTL` - Include $TTL directive if set (default: `undefined`)
- `omit_class => boolean()` - Omit IN class (default: `false`)
""").
-type encode_options() :: #{
    origin => dns:dname(),
    relative_names => boolean(),
    ttl_format => seconds | units,
    default_ttl => dns:ttl() | undefined,
    omit_class => boolean()
}.

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
parse_string(Data, Options) ->
    dns_zone_decode:parse_string(Data, Options).

?DOC("""
Encode a list of DNS resource records and write to a zone file.

## Examples

```erl
Records = [...],
ok = dns_zone:encode_file(Records, <<"example.com.">>, "example.com.zone").
```
""").
-spec encode_file([dns:rr()], dns:dname(), file:filename()) -> ok | {error, term()}.
encode_file(Records, Origin, Filename) ->
    encode_file(Records, Origin, Filename, #{}).

?DOC("""
Encode a list of DNS resource records and write to a zone file with options.
""").
-spec encode_file([dns:rr()], dns:dname(), file:filename(), encode_options()) ->
    ok | {error, term()}.
encode_file(Records, Origin, Filename, Options) ->
    dns_zone_encode:encode_file(Records, Origin, Filename, Options).

?DOC("""
Encode a list of DNS resource records to zone file format.

Returns iodata representing the zone file content.

## Examples

```erl
Records = [
    #dns_rr{name = <<"example.com.">>, type = ?DNS_TYPE_SOA, ...},
    #dns_rr{name = <<"example.com.">>, type = ?DNS_TYPE_NS, ...}
],
ZoneData = dns_zone:encode_string(Records, <<"example.com.">>).
```
""").
-spec encode_string([dns:rr()], dns:dname()) -> iodata().
encode_string(Records, Origin) ->
    encode_string(Records, Origin, #{}).

?DOC("""
Encode a list of DNS resource records to zone file format with options.

## Examples

```erl
Records = [...],
ZoneData = dns_zone:encode_string(Records, <<"example.com.">>, #{
    default_ttl => 3600,
    relative_names => true
}).
```
""").
-spec encode_string([dns:rr()], dns:dname(), encode_options()) -> iodata().
encode_string(Records, Origin, Options) ->
    dns_zone_encode:encode_string(Records, Origin, Options).

?DOC("""
Encode a single DNS resource record to zone file format.

Returns a string representing the record in zone file format.

## Examples

```erl
RR = #dns_rr{
    name = <<"www.example.com.">>,
    type = ?DNS_TYPE_A,
    class = ?DNS_CLASS_IN,
    ttl = 3600,
    data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
},
Line = dns_zone:encode_rr(RR).
% Returns: "www.example.com. 3600 IN A 192.0.2.1"
```
""").
-spec encode_rr(dns:rr()) -> iodata().
encode_rr(RR) ->
    encode_rr(RR, #{}).

?DOC("""
Encode a single DNS resource record to zone file format with options.

Options (all optional):
- `origin => Domain` - Origin domain for relative name calculation
- `relative_names => boolean()` - Use @ and relative names (default: `true`)
- `ttl_format => seconds | units` - TTL format: `3600` or `1h` (default: `seconds`)
- `omit_class => boolean()` - Omit IN class (default: `false`)

## Examples

```erl
RR = #dns_rr{
    name = <<"www.example.com.">>,
    type = ?DNS_TYPE_A,
    class = ?DNS_CLASS_IN,
    ttl = 3600,
    data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
},
Line = dns_zone:encode_rr(RR, #{origin => <<"example.com.">>, relative_names => true}).
% Returns: "www 3600 IN A 192.0.2.1"
```
""").
-spec encode_rr(dns:rr(), encode_options()) -> iodata().
encode_rr(RR, Options) ->
    dns_zone_encode:encode_rr(RR, Options).

?DOC("""
Encode RDATA (record data) to zone file format with default options.

## Examples

```erl
% Encode an A record RDATA
RData = #dns_rrdata_a{ip = {192, 0, 2, 1}},
RDataStr = dns_zone:encode_rdata(?DNS_TYPE_A, RData).
% Returns: "192.0.2.1"

% Encode an NS record RDATA
RData = #dns_rrdata_ns{dname = <<"ns1.example.com.">>},
RDataStr = dns_zone:encode_rdata(?DNS_TYPE_NS, RData).
% Returns: "ns1.example.com."
```

For more control over encoding (e.g., relative names, origin), use `encode_rr/2` instead.
""").
-spec encode_rdata(dns:type(), dns:rrdata()) -> iodata().
encode_rdata(Type, RData) ->
    dns_zone_encode:encode_rdata(Type, RData).

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
