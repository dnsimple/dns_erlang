%% DNS Zone File Parser Grammar
%%
%% Parses DNS zone files according to RFC 1035 and related specifications.
%%
%% == Specification Sources ==
%%
%% RFC-Defined (Standard):
%%   RFC 1035 §5 - Master file format, RR syntax, $ORIGIN, $INCLUDE
%%     https://datatracker.ietf.org/doc/html/rfc1035#section-5
%%   RFC 1034 §3.6.1 - Resource record conceptual model
%%     https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.1
%%   RFC 2308 §4 - $TTL directive
%%     https://datatracker.ietf.org/doc/html/rfc2308#section-4
%%
%% BIND Extensions (Non-Standard):
%%   $GENERATE - BIND-specific directive for generating multiple RRs
%%     Not in any RFC. See: https://bind9.readthedocs.io/en/latest/chapter3.html
%%     Warning: Currently parsed but not implemented (template expansion TODO)
%%
%% Supports:
%% - Directives: $ORIGIN, $TTL, $INCLUDE (RFC), $GENERATE (BIND, not implemented)
%% - All standard DNS record types
%% - Multi-line records with parentheses (RFC 1035 §5.1)
%% - Comments and whitespace handling (RFC 1035 §5.1)
%% - Relative and absolute domain names (RFC 1035 §5.1)

Nonterminals
    zone
    entries
    entry
    directive
    resource_record
    owner_name
    ttl_value
    class_value
    rdata
    rdata_elements
    rdata_elements_maybe
    paren_section
    paren_content
    paren_item
    rdata_element
    domain_name
    integer
    quoted_string
    rtype_value.

Terminals
    '$origin' '$ttl' '$include' '$generate'
    rtype class
    generic_type generic_class
    rfc3597_data
    name label string
    int time
    ipv4 ipv6
    '@' dot lparen rparen
    nl.

%% Note: rtype tokens can appear in RDATA for records like RRSIG where
%% record type names are part of the data (e.g., "RRSIG DS ...")

Rootsymbol zone.

%% Expected shift/reduce conflicts due to RFC 1035's flexible field ordering
%% (TTL and class can appear in either order or be omitted)
Expect 20.

%% ============================================================================
%% Zone Structure
%% ============================================================================

zone -> entries : '$1'.
zone -> '$empty' : [].

entries -> entry : ['$1'].
entries -> entry entries : ['$1' | '$2'].

entry -> directive : '$1'.
entry -> resource_record : '$1'.
entry -> nl : empty.

%% ============================================================================
%% Directives
%% ============================================================================

%% $ORIGIN - RFC 1035 §5.1
%% Changes the origin for relative domain names
directive -> '$origin' domain_name :
    {directive, origin, extract_value('$2')}.

%% $TTL - RFC 2308 §4
%% Sets default TTL for subsequent RRs
directive -> '$ttl' ttl_value :
    {directive, ttl, '$2'}.

%% $INCLUDE - RFC 1035 §5.1
%% Includes another zone file, optionally with a different origin
directive -> '$include' name :
    {directive, include, extract_token('$2')}.

directive -> '$include' name domain_name :
    {directive, include, extract_token('$2'), extract_value('$3')}.

%% $GENERATE - BIND extension (non-standard)
%% Used to generate multiple similar RRs from a template
%% WARNING: Not implemented - parsed but ignored
directive -> '$generate' rdata :
    {directive, generate, '$2'}.

%% ============================================================================
%% Resource Records - RFC 1035 §5.1
%% ============================================================================
%%
%% RR Format: <owner> [<TTL>] [<class>] <type> <RDATA>
%%
%% RFC 1035 allows flexible field ordering:
%% - Owner can be omitted (inherits from previous RR)
%% - TTL is optional (uses $TTL default or previous RR's TTL)
%% - Class is optional (defaults to IN)
%% - TTL and class can appear in either order
%%
%% The @ symbol represents the current $ORIGIN (RFC 1035 §5.1)

%% Full form: owner [ttl] [class] type rdata
resource_record -> owner_name ttl_value class_value rtype_value rdata :
    {rr, '$1', '$2', '$3', '$4', '$5'}.

resource_record -> owner_name ttl_value rtype_value rdata :
    {rr, '$1', '$2', undefined, '$3', '$4'}.

resource_record -> owner_name class_value rtype_value rdata :
    {rr, '$1', undefined, '$2', '$3', '$4'}.

resource_record -> owner_name rtype_value rdata :
    {rr, '$1', undefined, undefined, '$2', '$3'}.

%% TTL and class can be in either order (RFC 1035 allows this)
resource_record -> owner_name class_value ttl_value rtype_value rdata :
    {rr, '$1', '$3', '$2', '$4', '$5'}.

%% Owner name can be blank (inherits from previous RR - RFC 1035 §5.1)
resource_record -> ttl_value class_value rtype_value rdata :
    {rr, undefined, '$1', '$2', '$3', '$4'}.

resource_record -> ttl_value rtype_value rdata :
    {rr, undefined, '$1', undefined, '$2', '$3'}.

resource_record -> class_value rtype_value rdata :
    {rr, undefined, undefined, '$1', '$2', '$3'}.

resource_record -> rtype_value rdata :
    {rr, undefined, undefined, undefined, '$1', '$2'}.

%% ============================================================================
%% Record Fields
%% ============================================================================

owner_name -> domain_name : '$1'.
owner_name -> '@' : at_sign.

ttl_value -> int : extract_value('$1').
ttl_value -> time : extract_value('$1').

%% RFC 3597 - Generic CLASS syntax (e.g., CLASS32, CLASS1)
class_value -> class : extract_token('$1').
class_value -> generic_class : {generic_class, extract_token('$1')}.

%% RFC 3597 - Generic RR type syntax (e.g., TYPE99, TYPE65535)
rtype_value -> rtype : extract_token('$1').
rtype_value -> generic_type : {generic_type, extract_token('$1')}.

%% ============================================================================
%% Domain Names
%% ============================================================================

domain_name -> name : extract_token('$1').
domain_name -> name dot : append_dot(extract_token('$1')).
domain_name -> label : extract_token('$1').
domain_name -> label dot : append_dot(extract_token('$1')).
domain_name -> dot : ".".  % Root domain

%% ============================================================================
%% RDATA (Resource Data) - RFC 1035 §5.1
%% ============================================================================
%%
%% Parentheses allow RRs to span multiple lines (RFC 1035 §5.1)
%% This is commonly used for SOA records with readable formatting.
%% Newlines are ONLY allowed inside parentheses.

%% RDATA can be:
%% 1. Just elements (no parentheses)
%% 2. Elements followed by a parenthesized section with optional trailing elements
%% 3. Parenthesized section followed by optional trailing elements
rdata -> rdata_elements : '$1'.
rdata -> rdata_elements paren_section rdata_elements_maybe : '$1' ++ '$2' ++ '$3'.
rdata -> paren_section rdata_elements_maybe : '$1' ++ '$2'.

%% List of rdata elements (no newlines allowed here)
rdata_elements -> rdata_element : ['$1'].
rdata_elements -> rdata_element rdata_elements : ['$1' | '$2'].

%% Optional trailing elements after parentheses
rdata_elements_maybe -> rdata_elements : '$1'.
rdata_elements_maybe -> '$empty' : [].

%% Parenthesized section where newlines are allowed
paren_section -> lparen paren_content rparen : '$2'.

%% Content inside parentheses can include newlines
paren_content -> paren_item : flatten_paren(['$1']).
paren_content -> paren_item paren_content : flatten_paren(['$1' | '$2']).

%% Items inside parentheses
paren_item -> rdata_element : {element, '$1'}.
paren_item -> nl : ignore.

rdata_element -> domain_name : {domain, '$1'}.
rdata_element -> integer : {int, '$1'}.
rdata_element -> quoted_string : {string, '$1'}.
rdata_element -> ipv4 : {ipv4, extract_token('$1')}.
rdata_element -> ipv6 : {ipv6, extract_token('$1')}.
%% RFC 3597 - Generic RDATA format: \# length hexdata
%% The entire \# line is captured as a single token by the lexer
rdata_element -> rfc3597_data : {rfc3597, extract_token('$1')}.
%% Record type tokens can appear in RDATA (e.g., RRSIG type_covered field)
%% Treat them as strings/labels
rdata_element -> rtype : {domain, extract_token('$1')}.

%% ============================================================================
%% Basic Values
%% ============================================================================

integer -> int : extract_value('$1').
integer -> time : extract_value('$1').

quoted_string -> string : extract_token('$1').

%% ============================================================================
%% Helper Functions
%% ============================================================================

Erlang code.

%% Extract the value from a token tuple
extract_token({_Type, _Line, Value}) -> Value;
extract_token({_Type, _Line}) -> undefined;
extract_token(Value) when is_list(Value) -> Value.

extract_value({_Type, _Line, Value}) -> Value;
extract_value({_Type, _Line}) -> undefined;
extract_value(Value) when is_integer(Value) -> Value;
extract_value(Value) when is_list(Value) -> Value.

%% Append a dot to make a domain name fully qualified
append_dot(Name) when is_list(Name) ->
    Name ++ ".".

%% Flatten paren_content list to remove ignore markers and extract elements
flatten_paren(List) ->
    flatten_paren(List, []).

flatten_paren([], Acc) ->
    lists:reverse(Acc);
flatten_paren([ignore | Rest], Acc) ->
    flatten_paren(Rest, Acc);
flatten_paren([{element, Element} | Rest], Acc) ->
    flatten_paren(Rest, [Element | Acc]);
flatten_paren([List | Rest], Acc) when is_list(List) ->
    flatten_paren(Rest, lists:reverse(flatten_paren(List, [])) ++ Acc);
flatten_paren([Other | Rest], Acc) ->
    flatten_paren(Rest, [Other | Acc]).
