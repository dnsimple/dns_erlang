-module(dns_domain).
-moduledoc """
Domain name processing module providing operations for converting between
text representation, label lists, and DNS wire format.

This module provides strictly reversible domain name operations for use in DNS
message encoding and decoding.
""".

-export([new_compmap/0]).
-export([split/1, join/1, join/2]).
-export([from_wire/1, from_wire/2]).
-export([to_wire/1, to_wire/3]).
-export([to_lower/1, to_upper/1]).
-export([are_equal/2, are_equal_labels/2]).
-export([escape_label/1, unescape_label/1]).

-doc ~'Text representation of domain name: "www.example.com".'.
-type dname() :: binary().

-doc ~'Single label: "www".'.
-type label() :: binary().

-doc "List of labels.".
-type labels() :: [label()].

-doc "Wire format binary.".
-type wire() :: binary().

-doc """
Compression map: opaque state threaded through a run of `to_wire/3` calls.

Obtain one from `new_compmap/0`, thread it through `to_wire/3`. Its lifetime is one DNS message,
offsets in it are relative to the start of the message being built.
""".
-opaque compmap() :: #{dname() | labels() => non_neg_integer()}.

-export_type([compmap/0]).

-doc "Encode error types.".
-type encode_error() ::
    {error, label_too_long, label()}
    | {error, name_too_long, dname()}.

-doc "Decode error types.".
-type decode_error() ::
    {error, truncated}
    | {error, invalid_label_length, non_neg_integer()}
    | {error, bad_pointer, non_neg_integer()}.

-export_type([dname/0, label/0, labels/0, wire/0, encode_error/0, decode_error/0]).

-doc """
Split domain name into labels.

Converts a domain name string into a list of labels. Handles escaped dots
and backslashes, removing escape sequences from the resulting labels.

Returns an empty list for empty names or root (single dot).

Raises `{invalid_dname, empty_label}` if the name contains contiguous dots.

## Examples:

```erlang
1> dns_domain:split(~"www.example.com").
[~"www", ~"example", ~"com"]
2> dns_domain:split(~"example.com.").
[~"example", ~"com"]
3> dns_domain:split(~"test\.label.com").
[~"test.label", ~"com"]
4> dns_domain:split(<<>>).
[]
5> dns_domain:split(~"example..com").
** exception error: {invalid_dname, empty_label}
```
""".
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

-doc #{equiv => join(Labels, subdomain)}.
-spec join(Labels :: labels()) -> dname().
join(Labels) ->
    join(Labels, subdomain).

-doc """
Join labels into domain name.

Converts a list of labels into a domain name string. Automatically escapes
dots and backslashes in labels as needed.

Returns an empty binary for an empty list.

Note that it does not automatically append a trailing dot at the end of the domain.

## Examples:

```erlang
1> dns_domain:join([~"www", ~"example", ~"com"], subdomain).
~"www.example.com"
2> dns_domain:join([~"test.label", ~"com"], subdomain).
~"test\\.label.com"
3> dns_domain:join([~"test\\label", ~"com"], subdomain).
~"test\\\\label.com"
4> dns_domain:join([], subdomain).
<<>>
5> dns_domain:join([], fqdn).
~"."
5> dns_domain:join([~"example"], fqdn).
~"example."
```
""".
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

-doc """
Escape special characters in a label.

Escapes dots (`.`) and backslashes (`\`) in a label by prefixing them with
backslashes. Returns the original label unchanged if no escaping is needed.

Use this when you need to include literal dots or backslashes in a label
that will be joined with other labels.

## Examples:

```erlang
1> dns_domain:escape_label(~"test").
~"test"
2> dns_domain:escape_label(~"test.label").
~"test\\.label"
3> dns_domain:escape_label(~"test\\label").
~"test\\\\label"
4> dns_domain:escape_label(~"test\\.label").
~"test\\\\.label"
```
""".
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

-doc """
Unescape a label by removing escape sequences.

Reverses the escaping performed by `escape_label/1`. Converts `\\.` back to `.`
and `\\\\` back to `\\`. Returns the original label unchanged if no unescaping
is needed.

Use this when parsing labels that may contain escaped characters.

## Examples:

```erlang
1> dns_domain:unescape_label(~"test").
~"test"
2> dns_domain:unescape_label(~"test\\.label").
~"test.label"
3> dns_domain:unescape_label(~"test\\\\label").
~"test\\label"
4> dns_domain:unescape_label(~"test\\\\.label").
~"test\\.label"
```
""".
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

-doc "Returns an empty compression map, for the first `to_wire/3` call of a message.".
-spec new_compmap() -> compmap().
new_compmap() ->
    #{}.

-doc """
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
1> dns_domain:to_wire(~"www.example.com").
<<3,119,119,119,7,101,120,97,109,112,108,101,3,99,111,109,0>>
2> dns_domain:to_wire(~"example.com").
<<7,101,120,97,109,112,108,101,3,99,111,109,0>>
3> dns_domain:to_wire(~"").
<<0>>
4> dns_domain:to_wire(~"example..com").
** exception error: {invalid_dname, empty_label}
```
""".
-spec to_wire(dname()) -> wire().
to_wire(Name) ->
    Labels = do_split(Name, <<>>),
    LabelsBin = <<<<(byte_size(L)), L/binary>> || L <- Labels>>,
    254 < byte_size(LabelsBin) andalso error(name_too_long),
    <<LabelsBin/binary, 0>>.

-doc """
Convert domain name to wire format with compression.

Converts a domain name to wire format, using DNS name compression to reduce
message size. Maintains a compression map tracking previously encoded names
and emits compression pointers when a name (or suffix) has been seen before.

`CompMap` is the compression map mapping name suffixes to their positions.
`Pos` is the current position in the message where encoding starts.
Returns `{Wire, NewCompMap}` where `Wire` is the encoded name and `NewCompMap`
is the updated compression map.

Use this when encoding DNS messages where multiple names may share suffixes
(e.g., `example.com` and `www.example.com`).

## Examples:

```erlang
1> CompMap = dns_domain:new_compmap(), Pos = 0.
2> {Wire1, CompMap1} = dns_domain:to_wire(CompMap, Pos, ~"example.com").
{<<7,101,120,97,109,112,108,101,3,99,111,109,0>>, #{...}}
3> Pos2 = byte_size(Wire1).
4> {Wire2, _} = dns_domain:to_wire(CompMap1, Pos2, ~"www.example.com").
{<<3,119,119,119,192,0>>, #{...}}
%% Wire2 uses compression pointer (192,0) pointing to position 0
5> {Wire3, _} = dns_domain:to_wire(CompMap1, Pos2, ~"example.com").
{<<192,0>>, #{...}}
%% Wire3 is just a compression pointer since the name was seen before
```
""".
-spec to_wire(compmap(), non_neg_integer(), dname()) -> {wire(), compmap()}.
to_wire(CompMap, Pos, Name) when is_binary(Name) ->
    Key = memo_key(Name),
    maybe
        miss ?= memo(CompMap, Pos, Key),
        %% An escaped name keeps its untrimmed spelling: do_split/2 resolves its escapes.
        case classify(Name) of
            escaped -> to_wire_escaped(CompMap, Pos, Name);
            false -> to_wire_lc_write(CompMap, Pos, Key, <<>>, remember(Pos, Key, []));
            true -> to_wire_mc(CompMap, Pos, Key, to_lower_chunk(Key, <<>>), <<>>, [])
        end
    end.

%% Stored keys never carry the terminating dot, so a name is keyed on its trimmed spelling. That is
%% also the name to encode: the trim is skipped only when the final dot may be escaped, and such a
%% name always has a backslash, so it goes down the escaped path instead.
memo_key(Name) ->
    Sz = byte_size(Name),
    case Name of
        %% `foo\.` is the single label `foo.`, so that final dot is not a terminator.
        <<_:(Sz - 2)/binary, $\\, $.>> ->
            Name;
        <<Trimmed:(Sz - 1)/binary, $.>> ->
            Trimmed;
        _ ->
            Name
    end.

%% Answering here skips preparation entirely, which is the usual shape of a response:
%% every RR of an rrset repeats its owner name.
memo(CompMap, _Pos, <<>>) ->
    %% "" and "." both reduce to the root, which is never a stored key
    {<<0>>, CompMap};
memo(CompMap, Pos, Key) ->
    case CompMap of
        #{Key := Ptr} when is_integer(Ptr), Ptr < Pos -> {<<3:2, Ptr:14>>, CompMap};
        _ -> miss
    end.

%% All-lowercase: the remaining name is both the wire source and the key.
to_wire_lc(CompMap, Pos, Rest, Acc, Pending) ->
    case CompMap of
        #{Rest := Ptr} when is_integer(Ptr), Ptr < Pos ->
            {<<Acc/binary, 3:2, Ptr:14>>, merge_pending(CompMap, Pending)};
        _ ->
            to_wire_lc_write(CompMap, Pos, Rest, Acc, remember(Pos, Rest, Pending))
    end.

to_wire_lc_write(CompMap, Pos, Rest, Acc, Pending) ->
    case dot_at(Rest, 0) of
        nomatch ->
            {to_wire_last_label(Acc, Rest), merge_pending(CompMap, Pending)};
        Len ->
            63 < Len andalso error({label_too_long, binary:part(Rest, 0, Len)}),
            Skip = Len + 1,
            <<_:Skip/binary, Rest1/binary>> = Rest,
            no_empty(Rest1),
            %% The label goes straight from Rest into the accumulator, never built on its own.
            to_wire_lc(CompMap, Pos + Skip, Rest1, <<Acc/binary, Len, Rest:Len/binary>>, Pending)
    end.

%% Mixed case (0x20-randomised names): LRest is the lowered name at the same offset as Rest, and
%% only LRest is ever used as a key.
to_wire_mc(CompMap, Pos, Rest, LRest, Acc, Pending) ->
    case CompMap of
        #{LRest := Ptr} when is_integer(Ptr), Ptr < Pos ->
            {<<Acc/binary, 3:2, Ptr:14>>, merge_pending(CompMap, Pending)};
        _ ->
            to_wire_mc_write(CompMap, Pos, Rest, LRest, Acc, remember(Pos, LRest, Pending))
    end.

to_wire_mc_write(CompMap, Pos, Rest, LRest, Acc, Pending) ->
    case dot_at(Rest, 0) of
        nomatch ->
            {to_wire_last_label(Acc, Rest), merge_pending(CompMap, Pending)};
        Len ->
            63 < Len andalso error({label_too_long, binary:part(Rest, 0, Len)}),
            Skip = Len + 1,
            <<_:Skip/binary, Rest1/binary>> = Rest,
            no_empty(Rest1),
            <<_:Skip/binary, LRest1/binary>> = LRest,
            to_wire_mc(
                CompMap,
                Pos + Skip,
                Rest1,
                LRest1,
                <<Acc/binary, Len, Rest:Len/binary>>,
                Pending
            )
    end.

to_wire_last_label(Acc, L) ->
    Len = byte_size(L),
    63 < Len andalso error({label_too_long, L}),
    Acc1 = <<Acc/binary, Len, L/binary>>,
    255 < byte_size(Acc1) andalso error(name_too_long),
    <<Acc1/binary, 0>>.

%% An empty label is legal only at the very start of a name (the ".foo" quirk), never here.
no_empty(<<>>) ->
    error({invalid_dname, empty_label});
no_empty(<<$., _/binary>>) ->
    error({invalid_dname, empty_label});
no_empty(_) ->
    ok.

%% Escaped names, keyed conservatively. Joining labels with "." is injective only while no label
%% contains a "." itself: `a\.b.example.com` would otherwise share a key with the four-label
%% `a.b.example.com` and could be handed a pointer to the wrong label sequence. So a suffix keeps
%% the list-of-labels key whenever one of its labels carries a "." or a "\", and takes the joined
%% binary otherwise. The two key spaces never compare equal, so they cannot collide, while the
%% unambiguous tail of an escaped name still shares keys with ordinary names.
to_wire_escaped(CompMap, Pos, Name) ->
    Labels = do_split(Name, <<>>),
    Lower =
        case has_upper(Name) of
            false -> Labels;
            true -> [to_lower_chunk(L, <<>>) || L <- Labels]
        end,
    to_wire_esc(CompMap, Pos, Labels, Lower, 0, last_special(Lower, 0, -1), <<>>, []).

to_wire_esc(CompMap, _Pos, [], [], _Idx, _Last, Acc, Pending) ->
    255 < byte_size(Acc) andalso error(name_too_long),
    {<<Acc/binary, 0>>, merge_pending(CompMap, Pending)};
to_wire_esc(CompMap, Pos, [L | Ls], [_ | LwrLs] = Lwr, Idx, Last, Acc, Pending) ->
    Key =
        case Last < Idx of
            true -> join_dots(Lwr);
            false -> Lwr
        end,
    case CompMap of
        #{Key := Ptr} when is_integer(Ptr), Ptr < Pos ->
            {<<Acc/binary, 3:2, Ptr:14>>, merge_pending(CompMap, Pending)};
        _ ->
            Len = byte_size(L),
            63 < Len andalso error({label_too_long, L}),
            to_wire_esc(
                CompMap,
                Pos + 1 + Len,
                Ls,
                LwrLs,
                Idx + 1,
                Last,
                <<Acc/binary, Len, L/binary>>,
                remember(Pos, Key, Pending)
            )
    end.

%% Index of the last label whose joined spelling would be ambiguous, or -1.
last_special([], _Idx, Last) ->
    Last;
last_special([L | Ls], Idx, Last) ->
    case has_special(L) of
        false -> last_special(Ls, Idx + 1, Last);
        true -> last_special(Ls, Idx + 1, Idx)
    end.

join_dots([L]) ->
    L;
join_dots([L | Ls]) ->
    Rest = join_dots(Ls),
    <<L/binary, $., Rest/binary>>.

%% Compression pointers carry a 14-bit offset; nothing beyond that is storable.
remember(Pos, Key, Pending) when Pos < (1 bsl 14) ->
    [{Key, Pos} | Pending];
remember(_Pos, _Key, Pending) ->
    Pending.

%% Suffix keys of the name being encoded can never be looked up while encoding that same name
%% (suffixes strictly shrink), so this is observably identical while avoiding one map copy per label
merge_pending(CompMap, []) ->
    CompMap;
merge_pending(CompMap, [{K, P}]) ->
    CompMap#{K => P};
merge_pending(CompMap, [{K1, P1}, {K2, P2}]) ->
    CompMap#{K1 => P1, K2 => P2};
merge_pending(CompMap, [{K1, P1}, {K2, P2}, {K3, P3}]) ->
    CompMap#{K1 => P1, K2 => P2, K3 => P3};
merge_pending(CompMap, Pending) ->
    maps:merge(CompMap, maps:from_list(Pending)).

%% 56-bit (7-byte) and 32-bit SWAR constants — stay within BEAM small integer range
-define(ONES56, 16#01010101010101).
-define(HIGHS56, 16#80808080808080).
-define(ONES32, 16#01010101).
-define(HIGHS32, 16#80808080).
-define(DOTS56, (?ONES56 * $.)).
-define(BSLS56, (?ONES56 * $\\)).
-define(DOTS32, (?ONES32 * $.)).
-define(BSLS32, (?ONES32 * $\\)).

%% Flag word for "does W contain byte C", C given pre-multiplied by ones: the zero-byte half of the
%% CLEAN56 test, kept separate so the matching lane can be located and not just detected.
-define(HASBYTE56(W, C),
    (((((W) bxor (C)) - ?ONES56) band bnot ((W) bxor (C))) band ?HIGHS56)
).

%% Guard-legal test that a word contains neither '.' nor '\': W bxor (C * ones) has a zero byte iff
%% W contains byte C, and (V - ones) band (bnot V) band highs =/= 0 iff V has a zero byte (exact, no
%% false positives).
-define(CLEAN56(W),
    (0 =:=
        ((((((W) bxor ?DOTS56) - ?ONES56) band bnot ((W) bxor ?DOTS56)) bor
            ((((W) bxor ?BSLS56) - ?ONES56) band bnot ((W) bxor ?BSLS56))) band ?HIGHS56))
).
-define(CLEAN32(W),
    (0 =:=
        ((((((W) bxor ?DOTS32) - ?ONES32) band bnot ((W) bxor ?DOTS32)) bor
            ((((W) bxor ?BSLS32) - ?ONES32) band bnot ((W) bxor ?BSLS32))) band ?HIGHS32))
).

-doc """
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
{~"www.example.com", <<>>}
3> Wire2 = <<7,101,120,97,109,112,108,101,3,99,111,109,0,1,2,3>>.
4> {Dname2, Rest2} = dns_domain:from_wire(Wire2).
{~"example.com", <<1,2,3>>}
5> Wire3 = <<0>>.
6> {Dname3, Rest3} = dns_domain:from_wire(Wire3).
{<<>>, <<>>}
```
""".
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
    Acc = escape_label_chunk(Label, <<>>),
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
    AccEscaped = escape_label_chunk(Label, <<Acc/binary, $.>>),
    from_wire_rest(Rest, AccEscaped, LabelCount + 1).

%% Escape a label, appending directly into the accumulator. SWAR optimised.
escape_label_chunk(<<W:56/unsigned-little, Rest/binary>>, Acc) when ?CLEAN56(W) ->
    escape_label_chunk(Rest, <<Acc/binary, W:56/unsigned-little>>);
escape_label_chunk(<<W:32/unsigned-little, Rest/binary>>, Acc) when ?CLEAN32(W) ->
    escape_label_chunk(Rest, <<Acc/binary, W:32/unsigned-little>>);
escape_label_chunk(<<$., Rest/binary>>, Acc) ->
    escape_label_chunk(Rest, <<Acc/binary, "\\.">>);
escape_label_chunk(<<$\\, Rest/binary>>, Acc) ->
    escape_label_chunk(Rest, <<Acc/binary, "\\\\">>);
escape_label_chunk(<<C, Rest/binary>>, Acc) ->
    escape_label_chunk(Rest, <<Acc/binary, C>>);
escape_label_chunk(<<>>, Acc) ->
    Acc.

-doc """
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
{~"example.com", <<3,119,119,119,192,0>>}
3> {Dname2, Rest2} = dns_domain:from_wire(MsgBin, Rest1).
{~"www.example.com", <<>>}
%% Resolved compression pointer to decode "www.example.com"
```
""".
-spec from_wire(MsgBin :: wire(), DataBin :: wire()) -> {dname(), wire()}.
from_wire(MsgBin, DataBin) when is_binary(MsgBin), is_binary(DataBin) ->
    from_wire_first_compressed(MsgBin, DataBin, <<>>, 0, 0, none).

%% Compressed decode threads the accumulator through pointer jumps: a
%% pointer target's labels are appended straight into the same accumulator
%% (a rest-position jump appends the '.' separator first) instead of
%% decoding the target into its own binary and copying that into the
%% accumulator. "First" position means the next label is appended without a
%% separator: the start of the name, or right after a followed pointer.
%% SavedRest is the Rest captured at the first pointer followed — the
%% remainder from_wire/2 must return. Behavior quirks are preserved
%% exactly: the label counter restarts on every pointer segment,
%% decode_loop is checked only for pointers in first position
%% (pointer-to-pointer chains; any label in between grows TotalSize, which
%% is bounded), and a pointer to a terminating zero byte yields a
%% trailing-dot name.
from_wire_first_compressed(_MsgBin, _DataBin, _Acc, _Count, TotalSize, _SavedRest) when
    255 < TotalSize
->
    error({name_too_long, TotalSize});
from_wire_first_compressed(_MsgBin, <<>>, _Acc, _Count, _TotalSize, _SavedRest) ->
    error(truncated);
from_wire_first_compressed(_MsgBin, <<0, Rest/binary>>, Acc, _Count, _TotalSize, SavedRest) ->
    {Acc, keep_first(SavedRest, Rest)};
from_wire_first_compressed(
    MsgBin, <<3:2, Ptr:14, Rest/binary>>, Acc, Count, TotalSize, SavedRest
) ->
    NewCount = Count + 2,
    case NewCount > byte_size(MsgBin) of
        true ->
            error(decode_loop);
        false ->
            case MsgBin of
                <<_:Ptr/binary, PtrDataBin/binary>> ->
                    from_wire_first_compressed(
                        MsgBin,
                        PtrDataBin,
                        Acc,
                        NewCount,
                        2 + TotalSize,
                        keep_first(SavedRest, Rest)
                    );
                _ ->
                    error({bad_pointer, Ptr})
            end
    end;
from_wire_first_compressed(_MsgBin, <<Len, _/binary>>, _Acc, _Count, _TotalSize, _SavedRest) when
    63 < Len
->
    error({invalid_label_length, Len});
from_wire_first_compressed(_MsgBin, <<Len, Rest/binary>>, _Acc, _Count, _TotalSize, _SavedRest) when
    byte_size(Rest) < Len
->
    error(truncated);
from_wire_first_compressed(
    MsgBin, <<Len, Label:Len/binary, Rest/binary>>, Acc, Count, TotalSize, SavedRest
) ->
    NewAcc = escape_label_chunk(Label, Acc),
    from_wire_rest_compressed(MsgBin, Rest, NewAcc, Count, 1, 1 + Len + TotalSize, SavedRest).

%% Rest labels - matches structure of from_wire_rest
from_wire_rest_compressed(_MsgBin, _, _Acc, _Count, _LabelCount, TotalSize, _SavedRest) when
    255 < TotalSize
->
    error({name_too_long, TotalSize});
from_wire_rest_compressed(_MsgBin, <<>>, _Acc, _Count, _LabelCount, _TotalSize, _SavedRest) ->
    error(truncated);
from_wire_rest_compressed(
    _MsgBin, <<0, Rest/binary>>, Acc, _Count, _LabelCount, _TotalSize, SavedRest
) ->
    {Acc, keep_first(SavedRest, Rest)};
from_wire_rest_compressed(
    MsgBin, <<3:2, Ptr:14, Rest/binary>>, Acc, Count, _LabelCount, TotalSize, SavedRest
) ->
    case MsgBin of
        <<_:Ptr/binary, PtrDataBin/binary>> ->
            from_wire_first_compressed(
                MsgBin,
                PtrDataBin,
                <<Acc/binary, $.>>,
                2 + Count,
                2 + TotalSize,
                keep_first(SavedRest, Rest)
            );
        _ ->
            error({bad_pointer, Ptr})
    end;
from_wire_rest_compressed(
    _MsgBin, <<Len, _/binary>>, _Acc, _Count, _LabelCount, _TotalSize, _SavedRest
) when
    Len > 63
->
    error({invalid_label_length, Len});
from_wire_rest_compressed(
    _MsgBin, <<Len, Rest/binary>>, _Acc, _Count, _LabelCount, _TotalSize, _SavedRest
) when
    byte_size(Rest) < Len
->
    error(truncated);
from_wire_rest_compressed(
    _MsgBin, <<Len, _:Len/binary, _/binary>>, _Acc, _Count, 127, _, _SavedRest
) ->
    error({too_many_labels, 128});
from_wire_rest_compressed(
    MsgBin, <<Len, Label:Len/binary, Rest/binary>>, Acc, Count, LabelCount, TotalSize, SavedRest
) ->
    %% Add dot separator, then escape label directly into accumulator
    AccEscaped = escape_label_chunk(Label, <<Acc/binary, $.>>),
    from_wire_rest_compressed(
        MsgBin, Rest, AccEscaped, Count, 1 + LabelCount, 1 + Len + TotalSize, SavedRest
    ).

%% The remainder returned by from_wire/2 is the Rest at the first pointer
%% followed; later pointer sites don't change it.
keep_first(none, Rest) -> Rest;
keep_first(Saved, _Rest) -> Saved.

-doc """
Returns provided name with case-insensitive characters in uppercase.
""".
-spec to_upper(dname()) -> dname().
to_upper(Data) when is_binary(Data) ->
    to_upper_chunk(Data, <<>>).

-compile(
    {inline, [
        lower_word56/1,
        upper_word56/1,
        lower_byte/1,
        upper_byte/1,
        are_equal_ci/2,
        has_upper_word/1,
        memo/3,
        memo_key/1,
        classify/1,
        lowest_byte/1,
        no_empty/1,
        remember/3,
        keep_first/2
    ]}
).

%% Bitwise SWAR case conversion for 7 packed bytes.
%% Carry-safe: even for bytes >= 128, (0x80 | b) - 91 >= 37, so no borrow
%% propagates between byte lanes. An AsciiMask suppresses false-positive range
%% hits on bytes 0xC1-0xDA (or 0xE1-0xFA for upper) that would otherwise
%% corrupt non-ASCII input.
-spec lower_word56(non_neg_integer()) -> non_neg_integer().
lower_word56(W) ->
    AsciiMask = (W band ?HIGHS56) bxor ?HIGHS56,
    GeA = ((W bor ?HIGHS56) - (?ONES56 * $A)) band ?HIGHS56,
    GeZ1 = ((W bor ?HIGHS56) - (?ONES56 * ($Z + 1))) band ?HIGHS56,
    W bxor (((GeA bxor GeZ1) band AsciiMask) bsr 2).

-spec upper_word56(non_neg_integer()) -> non_neg_integer().
upper_word56(W) ->
    AsciiMask = (W band ?HIGHS56) bxor ?HIGHS56,
    GeA = ((W bor ?HIGHS56) - (?ONES56 * $a)) band ?HIGHS56,
    GeZ1 = ((W bor ?HIGHS56) - (?ONES56 * ($z + 1))) band ?HIGHS56,
    W bxor (((GeA bxor GeZ1) band AsciiMask) bsr 2).

%% SWAR scan for any byte in [$A, $Z], 7 bytes at a time.
%% Offset of the first "." in Bin, or nomatch. Returns an immediate, allocates nothing, and never
%% has to build the label it skipped over.
-spec dot_at(binary(), non_neg_integer()) -> nomatch | non_neg_integer().
dot_at(<<W:56/unsigned-little, Rest/binary>>, N) ->
    case ?HASBYTE56(W, ?DOTS56) of
        0 -> dot_at(Rest, N + 7);
        Z -> N + lowest_byte(Z band -Z)
    end;
dot_at(<<$., _/binary>>, N) ->
    N;
dot_at(<<_, Rest/binary>>, N) ->
    dot_at(Rest, N + 1);
dot_at(<<>>, _N) ->
    nomatch.

%% Byte index of the single flagged lane. The lowest flagged byte is the first match, because
%% borrows only ever propagate towards higher bytes.
-spec lowest_byte(non_neg_integer()) -> 0..6.
lowest_byte(16#80) -> 0;
lowest_byte(16#8000) -> 1;
lowest_byte(16#800000) -> 2;
lowest_byte(16#80000000) -> 3;
lowest_byte(16#8000000000) -> 4;
lowest_byte(16#800000000000) -> 5;
lowest_byte(16#80000000000000) -> 6.

%% Which of the three encode paths a name takes, in one pass: `escaped` as soon as a backslash
%% appears, otherwise whether any byte is upper case.
-spec classify(dname()) -> escaped | boolean().
classify(Name) ->
    classify(Name, false).

classify(<<W:56/unsigned-little, Rest/binary>>, Up) ->
    case ?HASBYTE56(W, ?BSLS56) of
        0 -> classify(Rest, Up orelse has_upper_word(W));
        _ -> escaped
    end;
classify(<<$\\, _/binary>>, _Up) ->
    escaped;
classify(<<C, Rest/binary>>, Up) ->
    classify(Rest, Up orelse ($A =< C andalso C =< $Z));
classify(<<>>, Up) ->
    Up.

%% Does the label carry a byte that would make its joined spelling ambiguous?
-spec has_special(binary()) -> boolean().
has_special(<<W:56/unsigned-little, Rest/binary>>) ->
    (not ?CLEAN56(W)) orelse has_special(Rest);
has_special(<<$., _/binary>>) ->
    true;
has_special(<<$\\, _/binary>>) ->
    true;
has_special(<<_, Rest/binary>>) ->
    has_special(Rest);
has_special(<<>>) ->
    false.

-spec has_upper(binary()) -> boolean().
has_upper(<<W:56/unsigned-little, Rest/binary>>) ->
    has_upper_word(W) orelse has_upper(Rest);
has_upper(<<C, Rest/binary>>) ->
    ($A =< C andalso C =< $Z) orelse has_upper(Rest);
has_upper(<<>>) ->
    false.

-spec has_upper_word(non_neg_integer()) -> boolean().
has_upper_word(W) ->
    AsciiMask = (W band ?HIGHS56) bxor ?HIGHS56,
    GeA = ((W bor ?HIGHS56) - (?ONES56 * $A)) band ?HIGHS56,
    GeZ1 = ((W bor ?HIGHS56) - (?ONES56 * ($Z + 1))) band ?HIGHS56,
    (GeA band (bnot GeZ1) band AsciiMask) =/= 0.

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

-spec to_upper_chunk(dname(), binary()) -> dname().
to_upper_chunk(<<W:56/unsigned-little, Rest/binary>>, Acc) ->
    to_upper_chunk(Rest, <<Acc/binary, (upper_word56(W)):56/unsigned-little>>);
to_upper_chunk(<<B, Rest/binary>>, Acc) ->
    to_upper_chunk(Rest, <<Acc/binary, (upper_byte(B))>>);
to_upper_chunk(<<>>, Acc) ->
    Acc.

-doc """
Returns provided name with case-insensitive characters in lowercase.
""".
-spec to_lower(dname()) -> dname().
to_lower(Data) when is_binary(Data) ->
    to_lower_chunk(Data, <<>>).

-spec to_lower_chunk(dname(), binary()) -> dname().
to_lower_chunk(<<W:56/unsigned-little, Rest/binary>>, Acc) ->
    to_lower_chunk(Rest, <<Acc/binary, (lower_word56(W)):56/unsigned-little>>);
to_lower_chunk(<<B, Rest/binary>>, Acc) ->
    to_lower_chunk(Rest, <<Acc/binary, (lower_byte(B))>>);
to_lower_chunk(<<>>, Acc) ->
    Acc.

%% ============================================================================
%% Comparison Functions
%% ============================================================================

-doc """
Compare two domain names case-insensitively.

Returns `true` if the names are equal, `false` otherwise.
""".
-spec are_equal(dname(), dname()) -> boolean().
are_equal(NameA, NameB) when is_binary(NameA) andalso is_binary(NameB) ->
    byte_size(NameA) =:= byte_size(NameB) andalso
        (NameA =:= NameB orelse are_equal_ci(NameA, NameB)).

-doc """
Compare two label lists case-insensitively.

Returns `true` if the label lists are equal, `false` otherwise.
""".
-spec are_equal_labels(labels(), labels()) -> boolean().
are_equal_labels(LabelsA, LabelsB) when is_list(LabelsA), is_list(LabelsB) ->
    do_are_equal_labels(LabelsA, LabelsB).

-spec do_are_equal_labels(labels(), labels()) -> boolean().
do_are_equal_labels([], []) ->
    true;
do_are_equal_labels([], [_ | _]) ->
    false;
do_are_equal_labels([_ | _], []) ->
    false;
do_are_equal_labels([LA | LabelsA], [LB | LabelsB]) ->
    byte_size(LA) =:= byte_size(LB) andalso
        (LA =:= LB orelse are_equal_ci(LA, LB)) andalso
        do_are_equal_labels(LabelsA, LabelsB).

%% Word-at-a-time case-insensitive comparison — no intermediate binary allocated.
%% Short-circuits on first mismatched word.
-spec are_equal_ci(binary(), binary()) -> boolean().
are_equal_ci(<<W0:56/unsigned-little, R1/binary>>, <<W0:56/unsigned-little, R2/binary>>) ->
    are_equal_ci(R1, R2);
are_equal_ci(<<W1:56/unsigned-little, R1/binary>>, <<W2:56/unsigned-little, R2/binary>>) ->
    lower_word56(W1) =:= lower_word56(W2) andalso are_equal_ci(R1, R2);
are_equal_ci(<<B1, R1/binary>>, <<B2, R2/binary>>) ->
    lower_byte(B1) =:= lower_byte(B2) andalso are_equal_ci(R1, R2);
are_equal_ci(<<>>, <<>>) ->
    true.
