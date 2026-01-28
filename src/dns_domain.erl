-module(dns_domain).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
Domain name processing module providing operations for converting between
text representation, label lists, and DNS wire format.

This module provides strictly reversible domain name operations for use in DNS
message encoding and decoding.
""").

-export([split/1, join/1, join/2]).
-export([from_wire/1, from_wire/2]).
-export([to_wire/1, to_wire/3]).
-export([to_lower/1, to_upper/1]).
-export([are_equal/2, are_equal_labels/2]).
-export([escape_label/1, unescape_label/1]).

?DOC("Text representation of domain name: \"www.example.com\"").
-type dname() :: binary().

?DOC("Single label: \"www\"").
-type label() :: binary().

?DOC("List of labels").
-type labels() :: [label()].

?DOC("Wire format binary").
-type wire() :: binary().

?DOC("Compression map: maps label sequences to positions").
-type compmap() :: #{labels() => non_neg_integer()}.

-export_type([compmap/0]).

?DOC("Encode error types").
-type encode_error() ::
    {error, label_too_long, label()}
    | {error, name_too_long, dname()}.

?DOC("Decode error types").
-type decode_error() ::
    {error, truncated}
    | {error, invalid_label_length, non_neg_integer()}
    | {error, bad_pointer, non_neg_integer()}.

-export_type([dname/0, label/0, labels/0, wire/0, encode_error/0, decode_error/0]).

?DOC("""
Split domain name into labels.

Converts a domain name string into a list of labels. Handles escaped dots
and backslashes, removing escape sequences from the resulting labels.

Returns an empty list for empty names or root (single dot).

Raises `{invalid_dname, empty_label}` if the name contains contiguous dots.

## Examples:

```erlang
1> dns_domain:split(<<"www.example.com">>).
[<<"www">>, <<"example">>, <<"com">>]
2> dns_domain:split(<<"example.com.">>).
[<<"example">>, <<"com">>]
3> dns_domain:split(<<"test\\.label.com">>).
[<<"test.label">>, <<"com">>]
4> dns_domain:split(<<>>).
[]
5> dns_domain:split(<<"example..com">>).
** exception error: {invalid_dname, empty_label}
```
""").
-spec split(dname()) -> labels().
split(Name) when is_binary(Name) ->
    do_split(Name, <<>>).

-spec do_split(binary(), binary()) -> labels().
%% End of input - return empty list if no label accumulated, otherwise return label
do_split(<<>>, <<>>) ->
    [];
do_split(<<>>, Label) ->
    [Label];
do_split(<<$.>>, <<>>) ->
    [];
do_split(<<$.>>, Label) ->
    [Label];
%% Match 8 bytes at once when all are safe (common case - no dots, no backslashes)
do_split(<<A, B, C, D, E, F, G, H, Rest/binary>>, Label) when
    A =/= $.,
    A =/= $\\,
    B =/= $.,
    B =/= $\\,
    C =/= $.,
    C =/= $\\,
    D =/= $.,
    D =/= $\\,
    E =/= $.,
    E =/= $\\,
    F =/= $.,
    F =/= $\\,
    G =/= $.,
    G =/= $\\,
    H =/= $.,
    H =/= $\\
->
    do_split(Rest, <<Label/binary, A, B, C, D, E, F, G, H>>);
%% Match 4 bytes
do_split(<<A, B, C, D, Rest/binary>>, Label) when
    A =/= $.,
    A =/= $\\,
    B =/= $.,
    B =/= $\\,
    C =/= $.,
    C =/= $\\,
    D =/= $.,
    D =/= $\\
->
    do_split(Rest, <<Label/binary, A, B, C, D>>);
%% Check for empty label (contiguous dots) - illegal except for root
do_split(<<$., $., _/binary>>, _) ->
    error({invalid_dname, empty_label});
%% Match 2 bytes
do_split(<<A, B, Rest/binary>>, Label) when
    A =/= $., A =/= $\\, B =/= $., B =/= $\\
->
    do_split(Rest, <<Label/binary, A, B>>);
%% Unescaped dot - label separator
do_split(<<$., _/binary>>, Label) when 63 < byte_size(Label) ->
    error({label_too_long, Label});
do_split(<<$., Cs/binary>>, Label) ->
    [Label | do_split(Cs, <<>>)];
%% Escaped dot - literal dot in label
do_split(<<$\\, $., Cs/binary>>, Label) ->
    do_split(Cs, <<Label/binary, $.>>);
%% Escaped backslash - literal backslash in label
do_split(<<$\\, $\\, Cs/binary>>, Label) ->
    do_split(Cs, <<Label/binary, $\\>>);
%% Single byte fallback
do_split(<<C, Cs/binary>>, Label) ->
    do_split(Cs, <<Label/binary, C>>).

?DOC(#{equiv => join(Labels, subdomain)}).
-spec join(Labels :: labels()) -> dname().
join(Labels) ->
    join(Labels, subdomain).

?DOC("""
Join labels into domain name.

Converts a list of labels into a domain name string. Automatically escapes
dots and backslashes in labels as needed.

Returns an empty binary for an empty list.

Note that it does not automatically append a trailing dot at the end of the domain.

## Examples:

```erlang
1> dns_domain:join([<<"www">>, <<"example">>, <<"com">>], subdomain).
<<"www.example.com">>
2> dns_domain:join([<<"test.label">>, <<"com">>], subdomain).
<<"test\\.label.com">>
3> dns_domain:join([<<"test\\label">>, <<"com">>], subdomain).
<<"test\\\\label.com">>
4> dns_domain:join([], subdomain).
<<>>
5> dns_domain:join([], fqdn).
<<".">>
5> dns_domain:join([<<"example">>], fqdn).
<<"example.">>
```
""").
-spec join(Labels :: labels(), subdomain | fqdn) -> dname().
join([], subdomain) ->
    <<>>;
join([], fqdn) ->
    <<$.>>;
join([First | Rest], Type) ->
    %% Escape and build in single pass per label
    build_joined(Rest, escape_direct(First, <<>>), Type).

build_joined([], Acc, subdomain) ->
    Acc;
build_joined([], Acc, fqdn) ->
    <<Acc/binary, ".">>;
build_joined([Label | Rest], Acc, Type) ->
    build_joined(Rest, escape_direct(Label, <<Acc/binary, $.>>), Type).

%% Always iterates - no pre-check
escape_direct(<<>>, Acc) ->
    Acc;
escape_direct(<<$., Rest/binary>>, Acc) ->
    escape_direct(Rest, <<Acc/binary, "\\.">>);
escape_direct(<<$\\, Rest/binary>>, Acc) ->
    escape_direct(Rest, <<Acc/binary, "\\\\">>);
escape_direct(<<C, Rest/binary>>, Acc) ->
    escape_direct(Rest, <<Acc/binary, C>>).

?DOC("""
Escape special characters in a label.

Escapes dots (`.`) and backslashes (`\`) in a label by prefixing them with
backslashes. Returns the original label unchanged if no escaping is needed.

Use this when you need to include literal dots or backslashes in a label
that will be joined with other labels.

## Examples:

```erlang
1> dns_domain:escape_label(<<"test">>).
<<"test">>
2> dns_domain:escape_label(<<"test.label">>).
<<"test\\.label">>
3> dns_domain:escape_label(<<"test\\label">>).
<<"test\\\\label">>
4> dns_domain:escape_label(<<"test\\.label">>).
<<"test\\\\.label">>
```
""").
-spec escape_label(label()) -> label().
escape_label(Label) ->
    case needs_escape(Label) of
        false ->
            %% No copy needed - sub-binary reference
            Label;
        true ->
            do_escape(Label, <<>>)
    end.

%% Quick scan - avoids allocation if no escaping needed
needs_escape(<<>>) ->
    false;
needs_escape(<<$., _/binary>>) ->
    true;
needs_escape(<<$\\, _/binary>>) ->
    true;
needs_escape(<<_, Rest/binary>>) ->
    needs_escape(Rest).

do_escape(<<>>, Acc) ->
    Acc;
do_escape(<<$., Rest/binary>>, Acc) ->
    do_escape(Rest, <<Acc/binary, "\\.">>);
do_escape(<<$\\, Rest/binary>>, Acc) ->
    do_escape(Rest, <<Acc/binary, "\\\\">>);
do_escape(<<C, Rest/binary>>, Acc) ->
    do_escape(Rest, <<Acc/binary, C>>).

?DOC("""
Unescape a label by removing escape sequences.

Reverses the escaping performed by `escape_label/1`. Converts `\\.` back to `.`
and `\\\\` back to `\\`. Returns the original label unchanged if no unescaping
is needed.

Use this when parsing labels that may contain escaped characters.

## Examples:

```erlang
1> dns_domain:unescape_label(<<"test">>).
<<"test">>
2> dns_domain:unescape_label(<<"test\\.label">>).
<<"test.label">>
3> dns_domain:unescape_label(<<"test\\\\label">>).
<<"test\\label">>
4> dns_domain:unescape_label(<<"test\\\\.label">>).
<<"test\\.label">>
```
""").
-spec unescape_label(label()) -> label().
unescape_label(Label) ->
    case needs_unescape(Label) of
        false ->
            %% No copy needed - sub-binary reference
            Label;
        true ->
            do_unescape(Label, <<>>)
    end.

%% Quick scan - avoids allocation if no unescaping needed
needs_unescape(<<>>) ->
    false;
needs_unescape(<<$\\, _/binary>>) ->
    true;
needs_unescape(<<_, Rest/binary>>) ->
    needs_unescape(Rest).

do_unescape(<<>>, Acc) ->
    Acc;
do_unescape(<<$\\, $\\, Rest/binary>>, Acc) ->
    %% Escaped backslash: \\ -> \
    do_unescape(Rest, <<Acc/binary, $\\>>);
do_unescape(<<$\\, $., Rest/binary>>, Acc) ->
    %% Escaped dot: \. -> .
    do_unescape(Rest, <<Acc/binary, $.>>);
do_unescape(<<$\\, C, Rest/binary>>, Acc) ->
    %% Invalid escape sequence - treat backslash as literal
    %% This handles malformed input gracefully
    do_unescape(Rest, <<Acc/binary, $\\, C>>);
do_unescape(<<C, Rest/binary>>, Acc) ->
    do_unescape(Rest, <<Acc/binary, C>>).

?DOC("""
Convert domain name to wire format.

Converts a domain name string to DNS wire format binary. The wire format
consists of length-prefixed labels followed by a null byte terminator.

Raises `{label_too_long, Label}` if any label exceeds 63 bytes.
Raises `name_too_long` if the total encoded name exceeds 255 bytes.
Raises `{invalid_dname, empty_label}` if the name contains empty labels
(contiguous dots).

Returns `<<0>>` for empty names or root.

## Examples:

```erlang
1> dns_domain:to_wire(<<"www.example.com">>).
<<3,119,119,119,7,101,120,97,109,112,108,101,3,99,111,109,0>>
2> dns_domain:to_wire(<<"example.com">>).
<<7,101,120,97,109,112,108,101,3,99,111,109,0>>
3> dns_domain:to_wire(<<>>).
<<0>>
4> dns_domain:to_wire(<<"example..com">>).
** exception error: {invalid_dname, empty_label}
```
""").
-spec to_wire(dname()) -> wire().
to_wire(Name) ->
    Labels = do_split(Name, <<>>),
    LabelsBin = <<<<(byte_size(L)), L/binary>> || L <- Labels>>,
    254 < byte_size(LabelsBin) andalso error(name_too_long),
    <<LabelsBin/binary, 0>>.

?DOC("""
Convert domain name to wire format with compression.

Converts a domain name to wire format, using DNS name compression to reduce
message size. Maintains a compression map tracking previously encoded names
and emits compression pointers when a name (or suffix) has been seen before.

`CompMap` is the compression map mapping label sequences to their positions.
`Pos` is the current position in the message where encoding starts.
Returns `{Wire, NewCompMap}` where `Wire` is the encoded name and `NewCompMap`
is the updated compression map.

Use this when encoding DNS messages where multiple names may share suffixes
(e.g., `example.com` and `www.example.com`).

## Examples:

```erlang
1> CompMap = #{}, Pos = 0.
2> {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, <<"example.com">>).
{<<7,101,120,97,109,112,108,101,3,99,111,109,0>>, #{...}}
3> Pos2 = byte_size(Wire1).
4> {Wire2, _} = dns_domain:to_wire(CompMap1, Pos2, <<"www.example.com">>).
{<<3,119,119,119,192,0>>, #{...}}
%% Wire2 uses compression pointer (192,0) pointing to position 0
5> {Wire3, _} = dns_domain:to_wire(CompMap1, Pos2, <<"example.com">>).
{<<192,0>>, #{...}}
%% Wire3 is just a compression pointer since the name was seen before
```
""").
-spec to_wire(compmap(), non_neg_integer(), dname()) -> {wire(), compmap()}.
to_wire(CompMap, Pos, Name) when is_binary(Name) ->
    Labels = do_split(Name, <<>>),
    LowerLabels = do_split(to_lower_chunk(Name), <<>>),
    to_wire_labels_compressed(CompMap, Pos, Labels, LowerLabels, <<>>).

to_wire_labels_compressed(_, _, [], [], Acc) when 255 < byte_size(Acc) ->
    error(name_too_long);
to_wire_labels_compressed(CompMap, _Pos, [], [], Acc) ->
    {<<Acc/binary, 0>>, CompMap};
to_wire_labels_compressed(_, _, [L | _], [_ | _] = _, _) when 63 < byte_size(L) ->
    error({label_too_long, L});
to_wire_labels_compressed(CompMap, Pos, [L | Ls], [_ | LwrLs] = LwrLabels, Acc) ->
    case maps:get(LwrLabels, CompMap, undefined) of
        %% Compression pointer must point to prior occurrence
        Ptr when is_integer(Ptr), Ptr < Pos ->
            {<<Acc/binary, 3:2, Ptr:14>>, CompMap};
        _ ->
            NewCompMap =
                case Pos < (1 bsl 14) of
                    true -> CompMap#{LwrLabels => Pos};
                    false -> CompMap
                end,
            Len = byte_size(L),
            NewPos = Pos + 1 + Len,
            NewAcc = <<Acc/binary, Len, L/binary>>,
            to_wire_labels_compressed(NewCompMap, NewPos, Ls, LwrLs, NewAcc)
    end.

?DOC("""
Convert wire format to domain name.

Decodes a DNS wire format binary into a domain name string. Handles escaped
characters in labels automatically.

Returns `{Dname, Rest}` where `Dname` is the decoded domain name and `Rest`
is any remaining binary data after the name.

Raises `truncated` if the wire format is incomplete or malformed.
Raises `{invalid_label_length, Len}` if a label length byte exceeds 63.
Raises `{name_too_long, Size}` if the decoded name exceeds 255 bytes.
Raises `{too_many_labels, Count}` if the name contains more than 127 labels.

## Examples:

```erlang
1> Wire = <<3,119,119,119,7,101,120,97,109,112,108,101,3,99,111,109,0>>.
2> {Dname, Rest} = dns_domain:from_wire(Wire).
{<<"www.example.com">>, <<>>}
3> Wire2 = <<7,101,120,97,109,112,108,101,3,99,111,109,0,1,2,3>>.
4> {Dname2, Rest2} = dns_domain:from_wire(Wire2).
{<<"example.com">>, <<1,2,3>>}
5> Wire3 = <<0>>.
6> {Dname3, Rest3} = dns_domain:from_wire(Wire3).
{<<>>, <<>>}
```
""").
-spec from_wire(wire()) -> {dname(), wire()}.
from_wire(Bin) when is_binary(Bin) ->
    from_wire_first(Bin).

%% First label - no leading dot, escape inline
from_wire_first(<<>>) ->
    error(truncated);
from_wire_first(<<0, Rest/binary>>) ->
    {<<>>, Rest};
from_wire_first(<<Len, _/binary>>) when Len > 63 ->
    error({invalid_label_length, Len});
from_wire_first(<<Len, Rest/binary>>) when byte_size(Rest) < Len ->
    error(truncated);
from_wire_first(<<Len, Label:Len/binary, Rest/binary>>) ->
    Acc = escape_label_inline(Label, <<>>),
    from_wire_rest(Rest, Acc, 1).

from_wire_rest(_, Acc, _) when byte_size(Acc) > 255 ->
    error({name_too_long, byte_size(Acc)});
from_wire_rest(<<>>, _Acc, _) ->
    error(truncated);
from_wire_rest(<<0, Rest/binary>>, Acc, _) ->
    {Acc, Rest};
from_wire_rest(<<Len, _/binary>>, _Acc, _) when Len > 63 ->
    error({invalid_label_length, Len});
from_wire_rest(<<Len, Rest/binary>>, _Acc, _) when byte_size(Rest) < Len ->
    error(truncated);
from_wire_rest(<<Len, _:Len/binary, _/binary>>, _, 127) ->
    error({too_many_labels, 128});
from_wire_rest(<<Len, Label:Len/binary, Rest/binary>>, Acc, LabelCount) ->
    %% Add dot separator, then escape label directly into accumulator
    AccWithDot = <<Acc/binary, $.>>,
    AccEscaped = escape_label_inline(Label, AccWithDot),
    from_wire_rest(Rest, AccEscaped, LabelCount + 1).

%% Escape label inline, appending directly to accumulator
%% Optimized to process chunks of safe characters (8, 4, 2 bytes) when possible
%% VM optimizes binary pattern matching and guards efficiently
escape_label_inline(<<>>, Acc) ->
    Acc;
%% Match 8 bytes at once when all are safe (common case - no escaping needed)
escape_label_inline(<<A, B, C, D, E, F, G, H, Rest/binary>>, Acc) when
    A =/= $.,
    A =/= $\\,
    B =/= $.,
    B =/= $\\,
    C =/= $.,
    C =/= $\\,
    D =/= $.,
    D =/= $\\,
    E =/= $.,
    E =/= $\\,
    F =/= $.,
    F =/= $\\,
    G =/= $.,
    G =/= $\\,
    H =/= $.,
    H =/= $\\
->
    escape_label_inline(Rest, <<Acc/binary, A, B, C, D, E, F, G, H>>);
%% Match 4 bytes
escape_label_inline(<<A, B, C, D, Rest/binary>>, Acc) when
    A =/= $.,
    A =/= $\\,
    B =/= $.,
    B =/= $\\,
    C =/= $.,
    C =/= $\\,
    D =/= $.,
    D =/= $\\
->
    escape_label_inline(Rest, <<Acc/binary, A, B, C, D>>);
%% Match 2 bytes
escape_label_inline(<<A, B, Rest/binary>>, Acc) when
    A =/= $., A =/= $\\, B =/= $., B =/= $\\
->
    escape_label_inline(Rest, <<Acc/binary, A, B>>);
%% Single byte fallback
escape_label_inline(<<$., Rest/binary>>, Acc) ->
    escape_label_inline(Rest, <<Acc/binary, "\\.">>);
escape_label_inline(<<$\\, Rest/binary>>, Acc) ->
    escape_label_inline(Rest, <<Acc/binary, "\\\\">>);
escape_label_inline(<<C, Rest/binary>>, Acc) ->
    escape_label_inline(Rest, <<Acc/binary, C>>).

?DOC("""
Convert wire format to domain name with compression support.

Decodes a DNS wire format binary that may contain compression pointers.
Compression pointers allow names to reference earlier parts of the message
to reduce size.

`MsgBin` is the complete message binary needed to resolve compression pointers.
`DataBin` is the binary data starting at the name to decode.

Returns `{Dname, Rest}` where `Dname` is the decoded domain name and `Rest`
is any remaining binary data after the name.

Raises the same errors as `from_wire/1`, plus `{bad_pointer, Pos}` if a
compression pointer is invalid or points outside the message.

## Examples:

```erlang
1> MsgBin = <<7,101,120,97,109,112,108,101,3,99,111,109,0,3,119,119,119,192,0>>.
%% First name at position 0: "example.com"
%% Second name at position 13: "www.example.com" (uses compression pointer)
2> {Dname1, Rest1} = dns_domain:from_wire(MsgBin, MsgBin).
{<<"example.com">>, <<3,119,119,119,192,0>>}
3> {Dname2, Rest2} = dns_domain:from_wire(MsgBin, Rest1).
{<<"www.example.com">>, <<>>}
%% Resolved compression pointer to decode "www.example.com"
```
""").
-spec from_wire(MsgBin :: wire(), DataBin :: wire()) -> {dname(), wire()}.
from_wire(MsgBin, DataBin) when is_binary(MsgBin), is_binary(DataBin) ->
    from_wire_first_compressed(MsgBin, DataBin, 0, 0).

%% First label - matches structure of from_wire_first
from_wire_first_compressed(_MsgBin, _Acc, _Count, TotalSize) when 255 < TotalSize ->
    error({name_too_long, TotalSize});
from_wire_first_compressed(_MsgBin, <<>>, _Count, _TotalSize) ->
    error(truncated);
from_wire_first_compressed(_MsgBin, <<0, Rest/binary>>, _Count, _TotalSize) ->
    {<<>>, Rest};
from_wire_first_compressed(MsgBin, <<3:2, Ptr:14, Rest/binary>>, Count, TotalSize) ->
    %% Compression pointer as first label
    NewCount = Count + 2,
    case NewCount > byte_size(MsgBin) of
        true ->
            error(decode_loop);
        false ->
            case MsgBin of
                <<_:Ptr/binary, PtrDataBin/binary>> ->
                    {PtrName, _} = from_wire_first_compressed(
                        MsgBin, PtrDataBin, NewCount, 2 + TotalSize
                    ),
                    {PtrName, Rest};
                _ ->
                    error({bad_pointer, Ptr})
            end
    end;
from_wire_first_compressed(_MsgBin, <<Len, _/binary>>, _Count, _TotalSize) when 63 < Len ->
    error({invalid_label_length, Len});
from_wire_first_compressed(_MsgBin, <<Len, Rest/binary>>, _Count, _TotalSize) when
    byte_size(Rest) < Len
->
    error(truncated);
from_wire_first_compressed(MsgBin, <<Len, Label:Len/binary, Rest/binary>>, Count, TotalSize) ->
    Acc = escape_label_inline(Label, <<>>),
    from_wire_rest_compressed(MsgBin, Rest, Acc, Count, 1, 1 + Len + TotalSize).

%% Rest labels - matches structure of from_wire_rest
from_wire_rest_compressed(_MsgBin, _, _Acc, _Count, _LabelCount, TotalSize) when 255 < TotalSize ->
    error({name_too_long, TotalSize});
from_wire_rest_compressed(_MsgBin, <<>>, _Acc, _Count, _LabelCount, _TotalSize) ->
    error(truncated);
from_wire_rest_compressed(_MsgBin, <<0, Rest/binary>>, Acc, _Count, _LabelCount, _TotalSize) ->
    {Acc, Rest};
from_wire_rest_compressed(
    MsgBin, <<3:2, Ptr:14, Rest/binary>>, Acc, Count, _LabelCount, TotalSize
) ->
    case MsgBin of
        <<_:Ptr/binary, PtrDataBin/binary>> ->
            {PtrName, _} = from_wire_first_compressed(
                MsgBin, PtrDataBin, 2 + Count, 2 + TotalSize
            ),
            {<<Acc/binary, $., PtrName/binary>>, Rest};
        _ ->
            error({bad_pointer, Ptr})
    end;
from_wire_rest_compressed(_MsgBin, <<Len, _/binary>>, _Acc, _Count, _LabelCount, _TotalSize) when
    Len > 63
->
    error({invalid_label_length, Len});
from_wire_rest_compressed(_MsgBin, <<Len, Rest/binary>>, _Acc, _Count, _LabelCount, _TotalSize) when
    byte_size(Rest) < Len
->
    error(truncated);
from_wire_rest_compressed(_MsgBin, <<Len, _:Len/binary, _/binary>>, _Acc, _Count, 127, _) ->
    error({too_many_labels, 128});
from_wire_rest_compressed(
    MsgBin,
    <<Len, Label:Len/binary, Rest/binary>>,
    Acc,
    Count,
    LabelCount,
    TotalSize
) ->
    %% Add dot separator, then escape label directly into accumulator
    AccWithDot = <<Acc/binary, $.>>,
    AccEscaped = escape_label_inline(Label, AccWithDot),
    from_wire_rest_compressed(MsgBin, Rest, AccEscaped, Count, 1 + LabelCount, 1 + Len + TotalSize).

-define(UP(X), (upper_byte(X)):8).
?DOC("""
Returns provided name with case-insensitive characters in uppercase.
""").
-spec to_upper(dname()) -> dname().
to_upper(Data) when is_binary(Data) ->
    to_upper_chunk(Data).

-spec to_upper_chunk(dname()) -> dname().
to_upper_chunk(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G), ?UP(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
to_upper_chunk(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
to_upper_chunk(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F)>> || <<A, B, C, D, E, F>> <= Data>>;
to_upper_chunk(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E)>> || <<A, B, C, D, E>> <= Data>>;
to_upper_chunk(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D)>> || <<A, B, C, D>> <= Data>>;
to_upper_chunk(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C)>> || <<A, B, C>> <= Data>>;
to_upper_chunk(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?UP(A), ?UP(B)>> || <<A, B>> <= Data>>;
to_upper_chunk(Data) ->
    <<<<?UP(N)>> || <<N>> <= Data>>.

-define(LOW(X), (lower_byte(X)):8).
?DOC("""
Returns provided name with case-insensitive characters in lowercase.
""").
-spec to_lower(dname()) -> dname().
to_lower(Data) when is_binary(Data) ->
    to_lower_chunk(Data).

-spec to_lower_chunk(dname()) -> dname().
to_lower_chunk(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G), ?LOW(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
to_lower_chunk(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
to_lower_chunk(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F)>> || <<A, B, C, D, E, F>> <= Data>>;
to_lower_chunk(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E)>> || <<A, B, C, D, E>> <= Data>>;
to_lower_chunk(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D)>> || <<A, B, C, D>> <= Data>>;
to_lower_chunk(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C)>> || <<A, B, C>> <= Data>>;
to_lower_chunk(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?LOW(A), ?LOW(B)>> || <<A, B>> <= Data>>;
to_lower_chunk(Data) ->
    <<<<?LOW(N)>> || <<N>> <= Data>>.

lower_byte(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104,
            105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
            122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
            139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
            156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
            173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
            190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
            207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
            224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
            241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
    ).

upper_byte(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
            81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131,
            132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
            149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
            166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
            183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
            217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            251, 252, 253, 254, 255}
    ).

%% ============================================================================
%% Comparison Functions
%% ============================================================================

?DOC("""
Compare two domain names case-insensitively.

Returns `true` if the names are equal, `false` otherwise.
""").
-spec are_equal(dname(), dname()) -> boolean().
are_equal(Name, Name) ->
    true;
are_equal(NameA, NameB) ->
    to_lower(NameA) =:= to_lower(NameB).

?DOC("""
Compare two label lists case-insensitively.

Returns `true` if the label lists are equal, `false` otherwise.
""").
-spec are_equal_labels(labels(), labels()) -> boolean().
are_equal_labels(LabelsA, LabelsB) when is_list(LabelsA), is_list(LabelsB) ->
    do_are_equal_labels(LabelsA, LabelsB).

-spec do_are_equal_labels(labels(), labels()) -> boolean().
do_are_equal_labels([], []) ->
    true;
do_are_equal_labels([LA | LabelsA], [LA | LabelsB]) ->
    do_are_equal_labels(LabelsA, LabelsB);
do_are_equal_labels([LA | LabelsA], [LB | LabelsB]) ->
    to_lower(LA) =:= to_lower(LB) andalso do_are_equal_labels(LabelsA, LabelsB);
do_are_equal_labels([], [_ | _]) ->
    false;
do_are_equal_labels([_ | _], []) ->
    false.
