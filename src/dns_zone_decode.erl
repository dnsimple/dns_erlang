-module(dns_zone_decode).
-moduledoc false.

%% Reads zone files (RFC 1035 §5) straight from binaries. An entry is a line, or the
%% lines a pair of parentheses joins, and is split into fields: words, and quoted
%% strings without their quotes. A field keeps its escapes until the reader of what
%% it holds decodes them, as a name, a string and a number each read them their own
%% way: RDATA is read field by field, as the type of the record has it, so a salt
%% of digits is read as hex, and a name keeps an escaped dot.

-include_lib("dns_erlang/include/dns.hrl").

-export([parse_file/2, parse_string/2, format_error/1]).

%% calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
-define(UNIX_EPOCH_GREGORIAN_SECONDS, 62_167_219_200).
-define(IS_DIGIT(C), ($0 =< C andalso C =< $9)).
-define(IS_UINT(Bits, X), (is_integer(X) andalso 0 =< X andalso X < (1 bsl (Bits)))).
-define(MAX_RDLENGTH, 16#FFFF).
%% The classes an address is written in, as dns_encode has them
-define(IS_IN_OR_NONE(Class), ((Class) =:= ?DNS_CLASS_IN orelse (Class) =:= ?DNS_CLASS_NONE)).
%% A field a reader cannot read, or an entry a zone file cannot hold
-define(FAIL(Reason), erlang:error({?MODULE, Reason})).
%% No field holds a larger number, and reading digits past it, one at a time, would
%% take time quadratic in their count
-define(MAX_NUMBER, 16#FFFFFFFFFFFFFFFF).
%% Below it, ten times a number and a digit is still a small integer, so digits are
%% added without comparing the sum with ?MAX_NUMBER, a bignum
-define(SMALL_NUMBER, 16#80000000000000).

%% SWAR checks of 7 octets at a time, taken as one 56-bit word so that every value
%% stays a small integer. Each check first requires all 7 octets to be ASCII,
%% which lets ?NO_ZERO_OCTET leave out the (bnot V) term of Mycroft's test: the
%% XOR of two ASCII octets is below 128, so subtracting 1 sets an octet's high bit
%% only where it is zero, or where a zero octet below borrowed from it. Such a
%% borrow can flag an octet that is not zero, but only next to one that is, and the
%% callers then read those octets one at a time.
-define(ONES7, 16#01010101010101).
-define(HIGHS7, 16#80808080808080).
-define(ASCII7(W), ((W) band ?HIGHS7 =:= 0)).
-define(NO_ZERO_OCTET(V), (((V) - ?ONES7) band ?HIGHS7 =:= 0)).
-define(NO_OCTET(W, C), ?NO_ZERO_OCTET((W) bxor (?ONES7 * (C)))).
%% 7 octets of a word: from $* up, which leaves out the blanks, the line end, the
%% quote and the parentheses, and neither ; nor \. Adding 16#56 to an octet below
%% 128 sets its high bit iff it is $* (16#2A) or above, and carries into no other.
-define(WORD7(W),
    (?ASCII7(W) andalso ((W) + 16#56565656565656) band ?HIGHS7 =:= ?HIGHS7 andalso
        ?NO_OCTET(W, $;) andalso ?NO_OCTET(W, $\\))
).
%% 7 octets of a quoted string: no quote, backslash or line end
-define(QUOTED7(W),
    (?ASCII7(W) andalso ?NO_OCTET(W, $") andalso ?NO_OCTET(W, $\\) andalso ?NO_OCTET(W, $\n))
).
%% 7 octets of a comment: no line end
-define(COMMENT7(W), (?ASCII7(W) andalso ?NO_OCTET(W, $\n))).
%% 7 octets of text without escapes: no backslash
-define(PLAIN7(W), (?ASCII7(W) andalso ?NO_OCTET(W, $\\))).
%% The high bits of the octets of 7 that are dots. A borrow can also flag an octet
%% next to a dot, which then reads one octet at a time.
-define(DOTS7(W), ((((W) bxor (?ONES7 * $.)) - ?ONES7) band ?HIGHS7)).
%% 7 octets of a name without escapes or an empty label: no backslash, and no dot
%% next to another
-define(NAME7(W), (?PLAIN7(W) andalso ?DOTS7(W) band (?DOTS7(W) bsr 8) =:= 0)).
%% The octets that end a word, other than the end of the source
-define(WORD_END(C),
    (C =:= $\s orelse C =:= $\t orelse C =:= $\r orelse C =:= $\n orelse C =:= $; orelse
        C =:= $( orelse C =:= $) orelse C =:= $")
).

%% RFC1876§3: the size and precisions a LOC record has when they are left out, in cm
-define(LOC_DEFAULT_SIZE, 100).
-define(LOC_DEFAULT_HORIZ, 1000000).
-define(LOC_DEFAULT_VERT, 1000).
%% How deep files may include files. A file that includes itself, at any remove,
%% stops here, where it recursed until the process ran out of memory.
-define(MAX_INCLUDE_DEPTH, 16).
%% The types whose RDATA has a presentation format read here; the others are read
%% only in RFC 3597's generic form
-define(READABLE_TYPES, [
    ?DNS_TYPE_A,
    ?DNS_TYPE_AAAA,
    ?DNS_TYPE_AFSDB,
    ?DNS_TYPE_AMTRELAY,
    ?DNS_TYPE_BRID,
    ?DNS_TYPE_CAA,
    ?DNS_TYPE_CDNSKEY,
    ?DNS_TYPE_CDS,
    ?DNS_TYPE_CERT,
    ?DNS_TYPE_CNAME,
    ?DNS_TYPE_CSYNC,
    ?DNS_TYPE_DHCID,
    ?DNS_TYPE_DLV,
    ?DNS_TYPE_DNAME,
    ?DNS_TYPE_DNSKEY,
    ?DNS_TYPE_DS,
    ?DNS_TYPE_DSYNC,
    ?DNS_TYPE_EUI48,
    ?DNS_TYPE_EUI64,
    ?DNS_TYPE_HHIT,
    ?DNS_TYPE_HINFO,
    ?DNS_TYPE_HIP,
    ?DNS_TYPE_HTTPS,
    ?DNS_TYPE_IPSECKEY,
    ?DNS_TYPE_KEY,
    ?DNS_TYPE_KX,
    ?DNS_TYPE_L32,
    ?DNS_TYPE_L64,
    ?DNS_TYPE_LOC,
    ?DNS_TYPE_LP,
    ?DNS_TYPE_MB,
    ?DNS_TYPE_MG,
    ?DNS_TYPE_MINFO,
    ?DNS_TYPE_MR,
    ?DNS_TYPE_MX,
    ?DNS_TYPE_NAPTR,
    ?DNS_TYPE_NID,
    ?DNS_TYPE_NS,
    ?DNS_TYPE_NSEC,
    ?DNS_TYPE_NSEC3,
    ?DNS_TYPE_NSEC3PARAM,
    ?DNS_TYPE_NXT,
    ?DNS_TYPE_OPENPGPKEY,
    ?DNS_TYPE_PTR,
    ?DNS_TYPE_PX,
    ?DNS_TYPE_RESINFO,
    ?DNS_TYPE_RP,
    ?DNS_TYPE_RRSIG,
    ?DNS_TYPE_RT,
    ?DNS_TYPE_SIG,
    ?DNS_TYPE_SMIMEA,
    ?DNS_TYPE_SOA,
    ?DNS_TYPE_SPF,
    ?DNS_TYPE_SRV,
    ?DNS_TYPE_SSHFP,
    ?DNS_TYPE_SVCB,
    ?DNS_TYPE_TLSA,
    ?DNS_TYPE_TXT,
    ?DNS_TYPE_URI,
    ?DNS_TYPE_WALLET,
    ?DNS_TYPE_ZONEMD
]).

-record(ctx, {
    origin = <<>> :: dns:dname(),
    default_ttl = 0 :: dns:ttl(),
    default_class = ?DNS_CLASS_IN :: dns:class(),
    base_dir = "" :: file:filename_all(),
    filename = undefined :: file:filename_all() | undefined,
    %% How many files include this one
    include_depth = 0 :: non_neg_integer(),
    source = <<>> :: binary()
}).
-type ctx() :: #ctx{}.
%% The text of the last owner read from a name, the origin it was read under, and
%% the name it gave, which a record has been accepted with
-type owner_memo() :: {binary(), dns:dname(), dns:dname()} | undefined.

%% A word, as its binary alone, or a quoted string without its quotes, as
%% {quoted, Text}, either as written, escapes included. Most fields are words, and
%% a tuple around each would be most of what a field allocates.
-type field() :: binary() | {quoted, binary()}.
%% The fields of an entry, the line of its first field, which is 0 while there is
%% none, and where and on which line the entry after it starts
-type fields_result() ::
    {ok, [field()], non_neg_integer(), non_neg_integer(), pos_integer()}
    | {error, term(), pos_integer()}.
%% A record's TTL and class, if given, its type, as a number and as written, and
%% its RDATA's fields
-type header() ::
    {dns:ttl() | undefined, dns:class() | undefined, dns:type(), binary(), [field()]}.
-type entry() ::
    {rrs, [dns:rr()], ctx()}
    | {origin, ctx()}
    | {ctx, ctx()}
    | {error, dns_zone:error_detail()}.

%% ============================================================================
%% API
%% ============================================================================

-spec parse_file(file:filename(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
parse_file(Filename, Options) ->
    case read_file(Filename) of
        {ok, Bin} ->
            parse(Bin, Options#{base_dir => filename:dirname(Filename), filename => Filename});
        {error, Reason} ->
            {error, file_error(Filename, Reason)}
    end.

%% Read in this process: file:read_file/1 reads in the file server, which then keeps
%% the zone's text referenced until it next collects its garbage.
-spec read_file(file:name_all()) -> {ok, binary()} | {error, term()}.
read_file(Filename) ->
    file:read_file(Filename, [raw]).

-spec parse_string(binary() | string(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
parse_string(Data, Options) when is_binary(Data) ->
    parse(Data, Options);
parse_string(Data, Options) when is_list(Data) ->
    case chars_to_binary(Data) of
        {ok, Bin} ->
            parse(Bin, Options);
        {error, Read} ->
            Line = 1 + length(binary:matches(Read, ~"\n")),
            Location =
                case Options of
                    #{filename := File} -> #{line => Line, file => filename(File)};
                    _ -> #{line => Line}
                end,
            {error, #{
                type => lexer,
                message => ~"Lexical error: not a character",
                details => {lexer_error, not_a_character},
                location => Location
            }}
    end.

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

%% ============================================================================
%% Entries
%% ============================================================================

%% A list of characters up to 255 is a string of octets, as it was before
%% binaries were read; one with characters past 255 is read as UTF-8. Otherwise,
%% what reads before the first element that is not a character.
-spec chars_to_binary(string()) -> {ok, binary()} | {error, binary()}.
chars_to_binary(Data) ->
    try
        {ok, iolist_to_binary(Data)}
    catch
        error:badarg ->
            try unicode:characters_to_binary(Data) of
                Bin when is_binary(Bin) -> {ok, Bin};
                {_, Read, _} -> {error, Read}
            catch
                error:badarg -> {error, <<>>}
            end
    end.

-spec parse(binary(), dns_zone:parse_options()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
parse(Bin, Options) ->
    parse(Bin, Options, 0).

-spec parse(binary(), dns_zone:parse_options(), non_neg_integer()) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
parse(Bin, Options, IncludeDepth) ->
    Origin = maps:get(origin, Options, <<>>),
    Ctx = #ctx{
        origin = Origin,
        default_ttl = maps:get(default_ttl, Options, 0),
        default_class = maps:get(default_class, Options, ?DNS_CLASS_IN),
        base_dir = filename:flatten(maps:get(base_dir, Options, "")),
        filename = filename(maps:get(filename, Options, undefined)),
        include_depth = IncludeDepth,
        source = Bin
    },
    with_binary_heap(byte_size(Bin), fun() ->
        entries(Bin, 0, 1, Ctx, dns_domain:to_lower(Origin), undefined, [])
    end).

%% A file name of the options as an error location gives it: parse_options() takes
%% the atoms and deep lists of file:name_all(), which are made flat
-spec filename(file:name_all() | undefined) -> file:filename_all() | undefined.
filename(undefined) ->
    undefined;
filename(Name) ->
    filename:flatten(Name).

%% The source is referenced from the process heap while it is read, and counts
%% towards the process's binary heap. With the default minimum, a large source
%% overflows it each time records are promoted to the old heap, and the garbage
%% collector then sweeps the whole heap. Twice the source's size, for as long as
%% it is read, keeps it off.
-spec with_binary_heap(non_neg_integer(), fun(() -> Result)) -> Result.
with_binary_heap(Size, Fun) ->
    Words = 2 * Size div erlang:system_info(wordsize),
    case erlang:process_info(self(), min_bin_vheap_size) of
        {min_bin_vheap_size, Current} when Current < Words ->
            Previous = erlang:process_flag(min_bin_vheap_size, Words),
            try
                Fun()
            after
                erlang:process_flag(min_bin_vheap_size, Previous)
            end;
        _ ->
            Fun()
    end.

%% Each entry is read as its fields are cut out of the source, a directive or a
%% record. A record goes on the list without a tuple around it. The owner of the
%% last record, which a record without one takes, and the owner memo change from
%% record to record, and go from one to the next as arguments rather than in the
%% state, which would be copied for each.
-spec entries(
    binary(), non_neg_integer(), pos_integer(), ctx(), dns:dname(), owner_memo(), [dns:rr()]
) ->
    {ok, [dns:rr()]} | {error, dns_zone:error_detail()}.
entries(Bin, Pos, _Line, _Ctx, _Owner, _Memo, Acc) when Pos >= byte_size(Bin) ->
    {ok, lists:reverse(Acc)};
entries(Bin, Pos, Line, Ctx, Owner, Memo, Acc) ->
    case entry_fields(Bin, Pos, Line) of
        {ok, [], _Start, Next, NextLine} ->
            entries(Bin, Next, NextLine, Ctx, Owner, Memo, Acc);
        {ok, [First | Args] = Fields, Start, Next, NextLine} ->
            case directive_name(First) of
                Name when is_binary(Name) ->
                    case directive_entry(Name, Args, Start, Ctx) of
                        {rrs, RRs, Ctx1} ->
                            entries(
                                Bin, Next, NextLine, Ctx1, Owner, Memo, lists:reverse(RRs, Acc)
                            );
                        {ctx, Ctx1} ->
                            entries(Bin, Next, NextLine, Ctx1, Owner, Memo, Acc);
                        {origin, #ctx{origin = Origin} = Ctx1} ->
                            Owner1 = dns_domain:to_lower(Origin),
                            entries(Bin, Next, NextLine, Ctx1, Owner1, Memo, Acc);
                        {error, _} = Error ->
                            Error
                    end;
                false ->
                    Blank = binary:at(Bin, Pos) =:= $\s orelse binary:at(Bin, Pos) =:= $\t,
                    try record(Blank, Fields, Ctx, Owner, Memo) of
                        {#dns_rr{name = Owner1} = RR, Memo1} ->
                            entries(Bin, Next, NextLine, Ctx, Owner1, Memo1, [RR | Acc])
                    catch
                        error:{?MODULE, Reason} -> {error, record_error(Reason, Start, Ctx)}
                    end
            end;
        {error, unclosed_parenthesis = Reason, _End} ->
            Message = <<"Parse error: ", (reason_text(Reason))/binary>>,
            {error, error_detail(parser, Message, undefined, {parser_error, Reason}, Line, Ctx)};
        {error, unterminated_string = Reason, ErrorLine} ->
            Message = <<"Lexical error: ", (reason_text(Reason))/binary>>,
            {error, error_detail(lexer, Message, undefined, {lexer_error, Reason}, ErrorLine, Ctx)};
        {error, Reason, ErrorLine} ->
            Message = <<"Parse error: ", (reason_text(Reason))/binary>>,
            {error,
                error_detail(parser, Message, undefined, {parser_error, Reason}, ErrorLine, Ctx)}
    end.

%% The name of a directive, a word that starts with $, told by its first octet
-compile({inline, [directive_name/1]}).
-spec directive_name(field()) -> binary() | false.
directive_name(Word) when is_binary(Word) ->
    case binary:first(Word) of
        $$ -> Word;
        _ -> false
    end;
directive_name({quoted, _}) ->
    false.

-spec directive_entry(binary(), [field()], pos_integer(), ctx()) -> entry().
directive_entry(Name, Args, Line, Ctx) ->
    try
        directive(dns_domain:to_upper(Name), Args, Line, Ctx)
    catch
        error:{?MODULE, Reason} ->
            Message = <<"Parse error: ", (reason_text(Reason))/binary>>,
            {error, error_detail(parser, Message, undefined, {parser_error, Reason}, Line, Ctx)}
    end.

-spec record_error(dynamic(), pos_integer(), ctx()) -> dns_zone:error_detail().
record_error({rdata_error, Message, Suggestion, Details}, Line, Ctx) ->
    error_detail(semantic, Message, Suggestion, Details, Line, Ctx);
record_error(Reason, Line, Ctx) ->
    Message = <<"Parse error: ", (reason_text(Reason))/binary>>,
    error_detail(parser, Message, undefined, {parser_error, Reason}, Line, Ctx).

%% RFC1035§5.1 directives, and RFC2308§4's $TTL. BIND's $GENERATE is accepted and
%% generates nothing. After $ORIGIN, the origin is the owner of a record that gives
%% none, lowercased as owners are.
-spec directive(binary(), [field()], pos_integer(), ctx()) -> entry().
directive(~"$ORIGIN", [Name], _Line, Ctx) ->
    {origin, Ctx#ctx{origin = fqdn(name(Name, Ctx))}};
directive(~"$TTL", [Field], _Line, Ctx) ->
    %% RFC2181§8
    TTL = ttl(Field),
    TTL =< 16#7FFFFFFF orelse ?FAIL({out_of_range, ~"TTL", TTL}),
    {ctx, Ctx#ctx{default_ttl = TTL}};
directive(~"$INCLUDE", [File], Line, Ctx) ->
    include(text(File), Ctx#ctx.origin, Line, Ctx);
directive(~"$INCLUDE", [File, Origin], Line, Ctx) ->
    include(text(File), fqdn(name(Origin, Ctx)), Line, Ctx);
directive(~"$GENERATE", _Args, _Line, Ctx) ->
    {ctx, Ctx};
directive(Name, Args, _Line, _Ctx) ->
    ?FAIL({bad_directive, Name, length(Args)}).

%% RFC1035§5.1: the origin of the parent file is not changed by the included file.
%% A file that cannot be read is an error on the line of the $INCLUDE. An error
%% within the file gives its line there and the kind of error, but nothing the
%% file holds, neither the text of the line nor the field or number the error is
%% about: a zone can include any file, which need not be one to show. An $INCLUDE
%% in a file included ?MAX_INCLUDE_DEPTH deep is an error.
-spec include(binary(), dns:dname(), pos_integer(), ctx()) -> entry().
include(File, Origin, Line, #ctx{base_dir = BaseDir, include_depth = Depth} = Ctx) ->
    Depth < ?MAX_INCLUDE_DEPTH orelse ?FAIL(include_too_deep),
    Path =
        case BaseDir of
            "" -> File;
            <<>> -> File;
            _ -> filename:join(BaseDir, File)
        end,
    case read_file(Path) of
        {ok, Bin} ->
            Options = #{
                origin => Origin,
                default_ttl => Ctx#ctx.default_ttl,
                default_class => Ctx#ctx.default_class,
                base_dir => filename:dirname(Path),
                filename => Path
            },
            case parse(Bin, Options, Depth + 1) of
                {ok, RRs} -> {rrs, RRs, Ctx};
                {error, Error} -> {error, included_error(Error)}
            end;
        {error, Reason} ->
            #{message := Message} = file_error(Path, Reason),
            {error, error_detail(file, Message, undefined, {file_error, Reason}, Line, Ctx)}
    end.

%% An error within an included file, with its type, location and suggestion, and
%% the kind of its reason in place of the reason, which holds what it is about.
%% The message of a record that does not fit names only its type, and that of a
%% file that cannot be read only why.
-spec included_error(dns_zone:error_detail()) -> dns_zone:error_detail().
included_error(#{type := Type} = Error) ->
    Without = maps:remove(context, Error),
    case Error of
        #{details := {file_error, _}} ->
            Without;
        #{details := {invalid_record, Mnemonic, _Texts}} ->
            Without#{details => {invalid_record, Mnemonic, []}};
        #{details := {Stage, Reason}} ->
            Kind = reason_kind(Reason),
            Message = <<
                (type_text(Type))/binary, " in an included file: ", (atom_to_binary(Kind))/binary
            >>,
            Without#{message => Message, details => {Stage, Kind}};
        _ ->
            Without#{message => <<(type_text(Type))/binary, " in an included file">>}
    end.

%% The atom a reason is, or is tagged with
-spec reason_kind(term()) -> atom().
reason_kind(Reason) when is_atom(Reason) ->
    Reason;
reason_kind(Reason) when is_tuple(Reason), tuple_size(Reason) > 0 ->
    case element(1, Reason) of
        Kind when is_atom(Kind) -> Kind;
        _ -> unknown
    end;
reason_kind(_Reason) ->
    unknown.

-spec type_text(dns_zone:error_type()) -> binary().
type_text(file) -> ~"File error";
type_text(lexer) -> ~"Lexical error";
type_text(parser) -> ~"Parse error";
type_text(semantic) -> ~"Invalid record".

%% RFC1035§5.1: an owner, or none for the owner of the previous record, then
%% [<TTL>] [<class>] <type> <RDATA>, TTL and class in either order. Owner names are
%% lowercased; the names in RDATA keep their case. A line that starts with a blank
%% has no owner, unless it only reads as a record with its first field taken for
%% one, as the grammar this parser replaced took it.
-spec record(boolean(), [field(), ...], ctx(), dns:dname(), owner_memo()) ->
    {dns:rr(), owner_memo()}.
record(true, Fields, Ctx, LastOwner, Memo) ->
    try
        {rr(LastOwner, header(Fields, undefined, undefined), Ctx, Memo), Memo}
    catch
        error:{?MODULE, _} = Error:Stack ->
            case owner_record(Fields, Ctx, LastOwner, Memo) of
                {ok, RR} -> {RR, Memo};
                error -> erlang:raise(error, Error, Stack)
            end
    end;
record(false, Fields, Ctx, LastOwner, Memo) ->
    {Owner, Header, Memo1} = owner_and_header(Fields, Ctx, LastOwner, Memo),
    {rr(Owner, Header, Ctx, Memo), Memo1}.

-spec owner_record([field(), ...], ctx(), dns:dname(), owner_memo()) -> {ok, dns:rr()} | error.
owner_record(Fields, Ctx, LastOwner, Memo) ->
    try
        {Owner, Rest, _Memo} = owner(Fields, Ctx, LastOwner, Memo),
        Rest =/= Fields orelse ?FAIL(no_owner),
        {ok, rr(Owner, header(Rest, undefined, undefined), Ctx, Memo)}
    catch
        error:{?MODULE, _} -> error
    end.

%% The memo is that of the records before this one, whose owner was accepted
-spec rr(dns:dname(), header(), ctx(), owner_memo()) -> dns:rr().
rr(Owner, {TTL, Class, Type, Mnemonic, RDataFields}, Ctx, Memo) ->
    RDataFields =:= [] andalso ?FAIL({no_rdata, Mnemonic}),
    RR = #dns_rr{
        name = Owner,
        type = Type,
        class = default(Class, Ctx#ctx.default_class),
        ttl = default(TTL, Ctx#ctx.default_ttl),
        data = rdata(Type, Mnemonic, RDataFields, Ctx)
    },
    fits(RR, Memo) orelse rdata_fail(Mnemonic, RDataFields, does_not_fit),
    RR.

%% dns_check:rr/1, which encodes the RDATA to see that it fits. For the types most
%% zones are made of, and those of DNSSEC, the same is told without writing them:
%% the fields dns_check:fits/1 checks, and what the encoder refuses on top, in any
%% class but where it says. That is an address of the wrong shape or in a class
%% other than IN or NONE, a name dns_domain:to_wire/1 refuses, told without writing
%% it, a DNSKEY whose key is not a binary, an NSEC3 opt-out that is not a boolean,
%% and RDATA past 65535 octets, which an NSEC's or an NSEC3's cannot reach. Other
%% types are left to dns_check:rr/1. The owner of the memo was accepted with a
%% record already.
-spec fits(dns:rr(), owner_memo()) -> boolean().
fits(#dns_rr{name = Owner, type = Type, class = Class, ttl = TTL, data = Data} = RR, Memo) ->
    case Data of
        #dns_rrdata_a{ip = IP} ->
            header_fits(Type, Class, TTL) andalso ?IS_IN_OR_NONE(Class) andalso
                inet:is_ipv4_address(IP) andalso owner_fits(Owner, Memo);
        #dns_rrdata_aaaa{ip = IP} ->
            header_fits(Type, Class, TTL) andalso ?IS_IN_OR_NONE(Class) andalso
                inet:is_ipv6_address(IP) andalso owner_fits(Owner, Memo);
        #dns_rrdata_ns{dname = Name} ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso dname_fits(Name);
        #dns_rrdata_cname{dname = Name} ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso dname_fits(Name);
        #dns_rrdata_ptr{dname = Name} ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso dname_fits(Name);
        #dns_rrdata_mx{preference = Preference, exchange = Name} ->
            header_fits(Type, Class, TTL) andalso ?IS_UINT(16, Preference) andalso
                owner_fits(Owner, Memo) andalso dname_fits(Name);
        #dns_rrdata_ds{keytag = KeyTag, alg = Alg, digest_type = DigestType, digest = Digest} when
            is_binary(Digest)
        ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso
                ?IS_UINT(16, KeyTag) andalso ?IS_UINT(8, Alg) andalso
                ?IS_UINT(8, DigestType) andalso 4 + byte_size(Digest) =< ?MAX_RDLENGTH;
        #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = Alg, public_key = Key} when
            is_binary(Key)
        ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso
                ?IS_UINT(16, Flags) andalso ?IS_UINT(8, Protocol) andalso ?IS_UINT(8, Alg) andalso
                4 + byte_size(Key) =< ?MAX_RDLENGTH;
        #dns_rrdata_rrsig{signers_name = Signer, signature = Signature} = RRSIG when
            is_binary(Signer), is_binary(Signature)
        ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso
                rrsig_fields_fit(RRSIG) andalso
                case dname_size(Signer) of
                    false -> false;
                    Size -> 18 + Size + byte_size(Signature) =< ?MAX_RDLENGTH
                end;
        #dns_rrdata_nsec{next_dname = Next, types = Types} when is_binary(Next), is_list(Types) ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso
                dname_fits(Next) andalso types_fit(Types);
        #dns_rrdata_nsec3{
            hash_alg = HashAlg,
            opt_out = OptOut,
            iterations = Iterations,
            salt = Salt,
            hash = Hash,
            types = Types
        } when is_binary(Salt), is_binary(Hash), is_list(Types) ->
            header_fits(Type, Class, TTL) andalso owner_fits(Owner, Memo) andalso
                ?IS_UINT(8, HashAlg) andalso is_boolean(OptOut) andalso
                ?IS_UINT(16, Iterations) andalso byte_size(Salt) =< 255 andalso
                byte_size(Hash) =< 255 andalso types_fit(Types);
        _ ->
            dns_check:rr(RR)
    end.

-spec rrsig_fields_fit(dns:rrdata()) -> boolean().
rrsig_fields_fit(#dns_rrdata_rrsig{
    type_covered = TypeCovered,
    alg = Alg,
    labels = Labels,
    original_ttl = OriginalTTL,
    expiration = Expiration,
    inception = Inception,
    keytag = KeyTag
}) ->
    ?IS_UINT(16, TypeCovered) andalso ?IS_UINT(8, Alg) andalso ?IS_UINT(8, Labels) andalso
        ?IS_UINT(32, OriginalTTL) andalso ?IS_UINT(32, Expiration) andalso
        ?IS_UINT(32, Inception) andalso ?IS_UINT(16, KeyTag).

-spec types_fit([dns:type()]) -> boolean().
types_fit(Types) ->
    lists:all(fun(Type) -> ?IS_UINT(16, Type) end, Types).

-spec owner_fits(dns:dname(), owner_memo()) -> boolean().
owner_fits(Owner, {_, _, Owner}) -> true;
owner_fits(Owner, _Memo) -> dname_fits(Owner).

-spec header_fits(dns:type(), dns:class(), dns:ttl()) -> boolean().
header_fits(Type, Class, TTL) ->
    ?IS_UINT(16, Type) andalso ?IS_UINT(16, Class) andalso ?IS_UINT(31, TTL).

-spec dname_fits(binary()) -> boolean().
dname_fits(Name) ->
    is_integer(dname_size(Name)).

%% The octets dns_domain:to_wire/1 writes a name in, or false where it refuses the
%% name, told the way it splits the name: no empty label but a first one, labels of
%% up to 63 octets, and up to 254 octets of labels and their lengths before the
%% root's. A name with an escape is given to it.
-spec dname_size(binary()) -> pos_integer() | false.
dname_size(Name) ->
    case labels_size(Name, 0, 0) of
        escaped ->
            try dns_domain:to_wire(Name) of
                Wire -> byte_size(Wire)
            catch
                error:_ -> false
            end;
        Size when is_integer(Size), Size =< 254 ->
            Size + 1;
        _ ->
            false
    end.

%% The octets of the labels read so far and their lengths, Size, and of the label
%% being read, Label
-spec labels_size(binary(), non_neg_integer(), non_neg_integer()) ->
    non_neg_integer() | false | escaped.
labels_size(<<W:56, Rest/binary>>, Label, Size) when ?PLAIN7(W) andalso ?DOTS7(W) =:= 0 ->
    labels_size(Rest, Label + 7, Size);
labels_size(<<$., $., _/binary>>, _Label, _Size) ->
    false;
labels_size(<<$.>>, 0, Size) ->
    Size;
labels_size(<<$., Rest/binary>>, Label, Size) when Label =< 63 ->
    labels_size(Rest, 0, Size + 1 + Label);
labels_size(<<$\\, _/binary>>, _Label, _Size) ->
    escaped;
labels_size(<<C, Rest/binary>>, Label, Size) when C =/= $. ->
    labels_size(Rest, Label + 1, Size);
labels_size(<<>>, 0, Size) ->
    Size;
labels_size(<<>>, Label, Size) when Label =< 63 ->
    Size + 1 + Label;
labels_size(_, _Label, _Size) ->
    false.

-spec default(Value | undefined, Value) -> Value.
default(undefined, Default) -> Default;
default(Value, _Default) -> Value.

%% The owner is the first field, as the grammar this parser replaced read it,
%% unless that field is a TTL, a class or a type, which leave the owner of the
%% previous record. A type is an owner when a class follows it, or a TTL and a
%% class. The words are told apart as that grammar's lexer told them, which took
%% only uppercase mnemonics.
-spec owner([field(), ...], ctx(), dns:dname(), owner_memo()) ->
    {dns:dname(), [field()], owner_memo()}.
owner([~"@" | Fields], #ctx{origin = Origin}, _LastOwner, Memo) ->
    {dns_domain:to_lower(Origin), Fields, Memo};
owner([Word | Rest] = Fields, Ctx, LastOwner, Memo) when is_binary(Word) ->
    case word_kind(Word) of
        name ->
            owner_name(Word, Rest, Ctx, Memo);
        type ->
            case [word_kind(Next) || Next <- lists:sublist(Rest, 2), is_binary(Next)] of
                [class | _] -> {dns_domain:to_lower(name(Word, Ctx)), Rest, Memo};
                [ttl, class] -> {dns_domain:to_lower(name(Word, Ctx)), Rest, Memo};
                _ -> {LastOwner, Fields, Memo}
            end;
        _ ->
            {LastOwner, Fields, Memo}
    end;
owner([{quoted, Text} | _], _Ctx, _LastOwner, _Memo) ->
    ?FAIL({quoted_owner, Text}).

%% Zone files often spell the same owner line after line. Spelled as the memo's,
%% under the same origin, it is the memo's name, the same binary, rather than read,
%% copied and lowercased again.
-spec owner_name(binary(), [field()], ctx(), owner_memo()) ->
    {dns:dname(), [field()], owner_memo()}.
owner_name(Text, Rest, #ctx{origin = Origin}, {Text, Origin, Owner} = Memo) ->
    {Owner, Rest, Memo};
owner_name(Text, Rest, #ctx{origin = Origin} = Ctx, _Memo) ->
    Owner = dns_domain:to_lower(name(Text, Ctx)),
    {Owner, Rest, {Text, Origin, Owner}}.

%% RFC1035§5.1: a line that does not start with a blank starts with its owner. Where
%% the reading above takes its first field for a TTL, a class or a type and the
%% rest does not read as a record's start, the first field is read as the owner,
%% so that the 1 of a reverse zone, which the writer writes before its TTL, is
%% an owner.
-spec owner_and_header([field(), ...], ctx(), dns:dname(), owner_memo()) ->
    {dns:dname(), header(), owner_memo()}.
owner_and_header([First | Rest] = Fields, Ctx, LastOwner, Memo0) ->
    case owner(Fields, Ctx, LastOwner, Memo0) of
        {Owner, Fields, Memo} ->
            try
                {Owner, header(Fields, undefined, undefined), Memo}
            catch
                error:{?MODULE, _} = Error:Stack ->
                    try
                        Header = header(Rest, undefined, undefined),
                        {dns_domain:to_lower(name(First, Ctx)), Header, Memo}
                    catch
                        error:{?MODULE, _} -> erlang:raise(error, Error, Stack)
                    end
            end;
        {Owner, Remaining, Memo} ->
            {Owner, header(Remaining, undefined, undefined), Memo}
    end.

%% Told by the first octet, which binary:first/1 reads without starting a match:
%% a class or a type is spelled in uppercase, as that lexer took them, and most
%% owners are not
-spec word_kind(binary()) -> ttl | class | type | generic_type | name.
word_kind(Word) ->
    case binary:first(Word) of
        C when ?IS_DIGIT(C) ->
            case lexer_ttl(Word) of
                true -> ttl;
                false -> name
            end;
        C when $A =< C, C =< $Z ->
            uppercase_word_kind(Word);
        _ ->
            name
    end.

-spec uppercase_word_kind(binary()) -> class | type | generic_type | name.
uppercase_word_kind(Word) ->
    case Word of
        ~"IN" ->
            class;
        ~"CH" ->
            class;
        ~"HS" ->
            class;
        ~"CS" ->
            class;
        <<"CLASS", Digits/binary>> when Digits =/= <<>> ->
            case digits(Digits) of
                true -> class;
                false -> name
            end;
        <<"TYPE", Digits/binary>> when Digits =/= <<>> ->
            case digits(Digits) of
                true -> generic_type;
                false -> lexer_type(Word)
            end;
        _ ->
            lexer_type(Word)
    end.

%% Digits, alone or each run followed by lowercase units
-spec lexer_ttl(binary()) -> boolean().
lexer_ttl(<<C, Rest/binary>>) when ?IS_DIGIT(C) ->
    lexer_ttl(Rest);
lexer_ttl(<<U, Rest/binary>>) when U =:= $y; U =:= $w; U =:= $d; U =:= $h; U =:= $m; U =:= $s ->
    lexer_ttl(Rest);
lexer_ttl(<<>>) ->
    true;
lexer_ttl(_) ->
    false.

-spec lexer_type(binary()) -> type | name.
lexer_type(Word) when byte_size(Word) =< 10 ->
    case Word of
        ~"A" -> type;
        ~"AAAA" -> type;
        ~"AFSDB" -> type;
        ~"ALIAS" -> type;
        ~"AMTRELAY" -> type;
        ~"BRID" -> type;
        ~"CAA" -> type;
        ~"CDNSKEY" -> type;
        ~"CDS" -> type;
        ~"CERT" -> type;
        ~"CNAME" -> type;
        ~"CSYNC" -> type;
        ~"DHCID" -> type;
        ~"DLV" -> type;
        ~"DNAME" -> type;
        ~"DNSKEY" -> type;
        ~"DS" -> type;
        ~"DSYNC" -> type;
        ~"EUI48" -> type;
        ~"EUI64" -> type;
        ~"HHIT" -> type;
        ~"HINFO" -> type;
        ~"HIP" -> type;
        ~"HTTPS" -> type;
        ~"IPSECKEY" -> type;
        ~"KEY" -> type;
        ~"KX" -> type;
        ~"L32" -> type;
        ~"L64" -> type;
        ~"LOC" -> type;
        ~"LP" -> type;
        ~"MB" -> type;
        ~"MG" -> type;
        ~"MINFO" -> type;
        ~"MR" -> type;
        ~"MX" -> type;
        ~"NAPTR" -> type;
        ~"NID" -> type;
        ~"NS" -> type;
        ~"NSEC" -> type;
        ~"NSEC3" -> type;
        ~"NSEC3PARAM" -> type;
        ~"NXT" -> type;
        ~"OPENPGPKEY" -> type;
        ~"PTR" -> type;
        ~"PX" -> type;
        ~"RESINFO" -> type;
        ~"RP" -> type;
        ~"RRSIG" -> type;
        ~"RT" -> type;
        ~"SIG" -> type;
        ~"SMIMEA" -> type;
        ~"SOA" -> type;
        ~"SPF" -> type;
        ~"SRV" -> type;
        ~"SSHFP" -> type;
        ~"SVCB" -> type;
        ~"TLSA" -> type;
        ~"TXT" -> type;
        ~"URI" -> type;
        ~"WALLET" -> type;
        ~"ZONEMD" -> type;
        _ -> name
    end;
lexer_type(_Word) ->
    name.

%% A record's TTL and class, in either order, then its type, each word told as it
%% is read: a TTL by its first octet, IN by equality, and a type by its number,
%% with no tuple to say which it was. A word that is no type or class as written
%% is tried in uppercase.
-spec header([field()], dns:ttl() | undefined, dns:class() | undefined) -> header().
header([Word | Rest], TTL, Class) when is_binary(Word) ->
    case binary:first(Word) of
        C when ?IS_DIGIT(C) ->
            case ttl_value(Word) of
                Value when is_integer(Value), TTL =:= undefined -> header(Rest, Value, Class);
                _ -> ?FAIL({unexpected_field, Word})
            end;
        _ when Word =:= ~"IN", Class =:= undefined ->
            header(Rest, TTL, ?DNS_CLASS_IN);
        _ ->
            case type_or_class(Word) of
                Type when is_integer(Type) ->
                    {TTL, Class, Type, Word, Rest};
                {class, Value} when Class =:= undefined ->
                    header(Rest, TTL, Value);
                unknown ->
                    Upper = dns_domain:to_upper(Word),
                    case type_or_class(Upper) of
                        Type when is_integer(Type) -> {TTL, Class, Type, Upper, Rest};
                        {class, Value} when Class =:= undefined -> header(Rest, TTL, Value);
                        _ -> ?FAIL({unexpected_field, Word})
                    end;
                _ ->
                    ?FAIL({unexpected_field, Word})
            end
    end;
header([{quoted, Text} | _], _TTL, _Class) ->
    ?FAIL({unexpected_field, Text});
header([], _TTL, _Class) ->
    ?FAIL(no_type).

%% A type first, as a record has one and seldom a class other than IN; no class is
%% spelled as a type
-spec type_or_class(binary()) -> dns:type() | {class, dns:class()} | unknown.
type_or_class(Word) ->
    case type_number(Word) of
        undefined ->
            case class_number(Word) of
                undefined -> unknown;
                Class -> {class, Class}
            end;
        Type ->
            Type
    end.

%% RFC3597§5: CLASSnnn for any class
-spec class_number(binary()) -> dns:class() | undefined.
class_number(~"IN") -> ?DNS_CLASS_IN;
class_number(~"CH") -> ?DNS_CLASS_CH;
class_number(~"HS") -> ?DNS_CLASS_HS;
class_number(~"CS") -> ?DNS_CLASS_CS;
class_number(<<"CLASS", Number/binary>> = Mnemonic) -> generic_number(Number, ~"class", Mnemonic);
class_number(_) -> undefined.

%% RFC3597§5: TYPEnnn for any type. ALIAS, PowerDNS's, is read as a CNAME. The
%% types most zones are made of are told by equality, which starts no match, as
%% dns_names:name_type/1 and a TYPE prefix do.
-spec type_number(binary()) -> dns:type() | undefined.
type_number(Mnemonic) when Mnemonic =:= ~"A" -> ?DNS_TYPE_A;
type_number(Mnemonic) when Mnemonic =:= ~"NS" -> ?DNS_TYPE_NS;
type_number(Mnemonic) when Mnemonic =:= ~"AAAA" -> ?DNS_TYPE_AAAA;
type_number(Mnemonic) when Mnemonic =:= ~"CNAME" -> ?DNS_TYPE_CNAME;
type_number(Mnemonic) when Mnemonic =:= ~"MX" -> ?DNS_TYPE_MX;
type_number(Mnemonic) when Mnemonic =:= ~"TXT" -> ?DNS_TYPE_TXT;
type_number(Mnemonic) when Mnemonic =:= ~"DS" -> ?DNS_TYPE_DS;
type_number(Mnemonic) when Mnemonic =:= ~"RRSIG" -> ?DNS_TYPE_RRSIG;
type_number(Mnemonic) when Mnemonic =:= ~"NSEC" -> ?DNS_TYPE_NSEC;
type_number(Mnemonic) ->
    case dns_names:name_type(Mnemonic) of
        undefined -> other_type_number(Mnemonic);
        Type -> Type
    end.

-spec other_type_number(binary()) -> dns:type() | undefined.
other_type_number(~"ALIAS") ->
    ?DNS_TYPE_CNAME;
other_type_number(<<"TYPE", Number/binary>> = Mnemonic) ->
    generic_number(Number, ~"type", Mnemonic);
other_type_number(_Mnemonic) ->
    undefined.

%% The number of TYPEnnn or CLASSnnn, undefined if it is not digits, and refused
%% past 16 bits, where the parser read TYPE65536 as A and CLASS65536 as IN
-spec generic_number(binary(), binary(), binary()) -> dns:uint16() | undefined.
generic_number(Number, What, Mnemonic) ->
    case digits(Number) of
        true ->
            case number(Number) of
                N when is_integer(N), N =< 16#FFFF -> N;
                _ -> ?FAIL({out_of_range, What, Mnemonic})
            end;
        false ->
            undefined
    end.

%% ============================================================================
%% Splitting entries into fields
%% ============================================================================

%% The fields of the entry at Pos, and where the entry after it starts. Lines with
%% no fields, blank or with only a comment, are entries of no fields.
%%
%% The scanner reads the source the way OTP's json module does. Each function
%% matches the octets ahead and passes the rest on in a tail call, so the compiler
%% keeps one match context throughout and nothing is allocated for each octet,
%% while Pos follows where that rest starts in the source, to cut fields out of it
%% with binary_part/3. The rest is never kept or returned: as a binary of its own
%% it would hold the whole source, and count it towards the process heap.
-spec entry_fields(binary(), non_neg_integer(), pos_integer()) -> fields_result().
entry_fields(Bin, Pos, Line) ->
    <<_:Pos/binary, Rest/binary>> = Bin,
    fields(Rest, Bin, Pos, Line, 0, 0, []).

%% RFC1035§5.1: a semicolon starts a comment, which ends with the line, and
%% parentheses group fields across lines. First is the line of the first field,
%% 0 until there is one.
-spec fields(
    binary(),
    binary(),
    non_neg_integer(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    [field()]
) -> fields_result().
fields(<<C, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) when
    C =:= $\s; C =:= $\t; C =:= $\r
->
    fields(Rest, Bin, Pos + 1, Line, Depth, First, Acc);
fields(<<$\n, _/binary>>, _Bin, Pos, Line, 0, First, Acc) ->
    {ok, lists:reverse(Acc), First, Pos + 1, Line + 1};
fields(<<$\n, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    fields(Rest, Bin, Pos + 1, Line + 1, Depth, First, Acc);
fields(<<$;, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    comment(Rest, Bin, Pos + 1, Line, Depth, First, Acc);
fields(<<$(, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    fields(Rest, Bin, Pos + 1, Line, Depth + 1, First, Acc);
fields(<<$), _/binary>>, _Bin, _Pos, Line, 0, _First, _Acc) ->
    {error, unbalanced_parenthesis, Line};
fields(<<$), Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    fields(Rest, Bin, Pos + 1, Line, Depth - 1, First, Acc);
fields(<<$", Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    quoted(Rest, Bin, Pos + 1, Pos + 1, Line, Line, Depth, First, Acc);
fields(<<>>, _Bin, Pos, Line, 0, First, Acc) ->
    {ok, lists:reverse(Acc), First, Pos, Line};
fields(<<>>, _Bin, _Pos, Line, _Depth, _First, _Acc) ->
    {error, unclosed_parenthesis, Line};
fields(Rest, Bin, Pos, Line, Depth, First, Acc) ->
    word(Rest, Bin, Pos, Pos, first_line(First, Line), Line, Depth, Acc).

%% A comment ends at the end of its line, which then ends the entry as it would
%% without the comment
-spec comment(
    binary(),
    binary(),
    non_neg_integer(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    [field()]
) -> fields_result().
comment(<<W:56, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) when ?COMMENT7(W) ->
    comment(Rest, Bin, Pos + 7, Line, Depth, First, Acc);
comment(<<$\n, _/binary>>, _Bin, Pos, Line, 0, First, Acc) ->
    {ok, lists:reverse(Acc), First, Pos + 1, Line + 1};
comment(<<$\n, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    fields(Rest, Bin, Pos + 1, Line + 1, Depth, First, Acc);
comment(<<_, Rest/binary>>, Bin, Pos, Line, Depth, First, Acc) ->
    comment(Rest, Bin, Pos + 1, Line, Depth, First, Acc);
comment(<<>>, Bin, Pos, Line, Depth, First, Acc) ->
    fields(<<>>, Bin, Pos, Line, Depth, First, Acc).

%% A word ends at a blank, a parenthesis, a semicolon, a quote or the end of the
%% line, and a backslash escapes the octet after it. Start is where the word
%% starts, and First the line of the entry's first field, this word's if it is the
%% first, which escaped line ends do not move, as they move Line.
-spec word(
    binary(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    pos_integer(),
    pos_integer(),
    non_neg_integer(),
    [field()]
) -> fields_result().
word(<<W:56, Rest/binary>>, Bin, Start, Pos, First, Line, Depth, Acc) when ?WORD7(W) ->
    word(Rest, Bin, Start, Pos + 7, First, Line, Depth, Acc);
word(<<$\\, $\n, Rest/binary>>, Bin, Start, Pos, First, Line, Depth, Acc) ->
    word(Rest, Bin, Start, Pos + 2, First, Line + 1, Depth, Acc);
word(<<$\\, _, Rest/binary>>, Bin, Start, Pos, First, Line, Depth, Acc) ->
    word(Rest, Bin, Start, Pos + 2, First, Line, Depth, Acc);
word(<<$\\>>, Bin, Start, Pos, First, Line, Depth, Acc) ->
    Word = binary_part(Bin, Start, Pos + 1 - Start),
    fields(<<>>, Bin, Pos + 1, Line, Depth, First, [Word | Acc]);
word(<<C, Rest/binary>>, Bin, Start, Pos, First, Line, Depth, Acc) when not ?WORD_END(C) ->
    word(Rest, Bin, Start, Pos + 1, First, Line, Depth, Acc);
word(Rest, Bin, Start, Pos, First, Line, Depth, Acc) ->
    Word = binary_part(Bin, Start, Pos - Start),
    fields(Rest, Bin, Pos, Line, Depth, First, [Word | Acc]).

%% A quoted string ends at the next quote a backslash does not escape, and may
%% span lines. Start is where its text starts, after the quote, and StartLine the
%% line of the quote, which an unterminated string is reported on.
-spec quoted(
    binary(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    pos_integer(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    [field()]
) -> fields_result().
quoted(<<W:56, Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) when
    ?QUOTED7(W)
->
    quoted(Rest, Bin, Start, Pos + 7, StartLine, Line, Depth, First, Acc);
quoted(<<$", Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) ->
    Text = binary_part(Bin, Start, Pos - Start),
    fields(Rest, Bin, Pos + 1, Line, Depth, first_line(First, StartLine), [{quoted, Text} | Acc]);
quoted(<<$\n, Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) ->
    quoted(Rest, Bin, Start, Pos + 1, StartLine, Line + 1, Depth, First, Acc);
quoted(<<$\\, $\n, Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) ->
    quoted(Rest, Bin, Start, Pos + 2, StartLine, Line + 1, Depth, First, Acc);
quoted(<<$\\, _, Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) ->
    quoted(Rest, Bin, Start, Pos + 2, StartLine, Line, Depth, First, Acc);
quoted(<<C, Rest/binary>>, Bin, Start, Pos, StartLine, Line, Depth, First, Acc) when C =/= $\\ ->
    quoted(Rest, Bin, Start, Pos + 1, StartLine, Line, Depth, First, Acc);
quoted(_, _Bin, _Start, _Pos, StartLine, _Line, _Depth, _First, _Acc) ->
    {error, unterminated_string, StartLine}.

%% The line of an entry's first field: that of the field just read, if there was
%% none before it
-compile({inline, [first_line/2]}).
-spec first_line(non_neg_integer(), pos_integer()) -> pos_integer().
first_line(0, Line) -> Line;
first_line(First, _Line) -> First.

%% ============================================================================
%% RDATA
%% ============================================================================

%% RFC3597§5: \# and the length and hex of the RDATA stand for the RDATA of any
%% type, which is then kept as those octets
-spec rdata(dns:type(), binary(), [field(), ...], ctx()) -> dns:rrdata().
rdata(Type, Mnemonic, Fields, Ctx) ->
    try
        case Fields of
            [~"\\#" | Generic] -> generic(Generic);
            _ -> rdata(Type, Fields, Ctx)
        end
    catch
        error:{?MODULE, Reason} -> rdata_fail(Mnemonic, Fields, Reason)
    end.

-spec rdata_fail(binary(), [field()], term()) -> no_return().
rdata_fail(Mnemonic, Fields, does_not_fit) ->
    Message = <<"Invalid ", Mnemonic/binary, " record: a value does not fit its field">>,
    Texts = [field_text(Field) || Field <- Fields],
    ?FAIL({rdata_error, Message, undefined, {invalid_record, Mnemonic, Texts}});
rdata_fail(Mnemonic, Fields, Reason) ->
    {ShapeMessage, Suggestion} = rdata_error_message(Mnemonic, Fields),
    Message =
        case Reason of
            malformed -> ShapeMessage;
            _ -> <<"Invalid ", Mnemonic/binary, " record: ", (reason_text(Reason))/binary>>
        end,
    ?FAIL({rdata_error, Message, Suggestion, {semantic_error, Reason}}).

-spec generic([field()]) -> binary().
generic([Length | Hex]) ->
    Size = uint(Length),
    Data = hex(Hex),
    byte_size(Data) =:= Size orelse ?FAIL({rfc3597_length_mismatch, Size, byte_size(Data)}),
    Data;
generic([]) ->
    ?FAIL(rfc3597_no_length).

-spec rdata(dns:type(), [field(), ...], ctx()) -> dns:rrdata().
rdata(?DNS_TYPE_A, [IP], _Ctx) ->
    #dns_rrdata_a{ip = ipv4(IP)};
rdata(?DNS_TYPE_AAAA, [IP], _Ctx) ->
    #dns_rrdata_aaaa{ip = ipv6(IP)};
rdata(?DNS_TYPE_NS, [Name], Ctx) ->
    #dns_rrdata_ns{dname = name(Name, Ctx)};
rdata(?DNS_TYPE_CNAME, [Name], Ctx) ->
    #dns_rrdata_cname{dname = name(Name, Ctx)};
rdata(?DNS_TYPE_PTR, [Name], Ctx) ->
    #dns_rrdata_ptr{dname = name(Name, Ctx)};
rdata(?DNS_TYPE_DNAME, [Name], Ctx) ->
    #dns_rrdata_dname{dname = name(Name, Ctx)};
rdata(?DNS_TYPE_MB, [Name], Ctx) ->
    #dns_rrdata_mb{madname = name(Name, Ctx)};
rdata(?DNS_TYPE_MG, [Name], Ctx) ->
    #dns_rrdata_mg{madname = name(Name, Ctx)};
rdata(?DNS_TYPE_MR, [Name], Ctx) ->
    #dns_rrdata_mr{newname = name(Name, Ctx)};
rdata(?DNS_TYPE_MX, [Pref, Name], Ctx) ->
    #dns_rrdata_mx{preference = uint(Pref), exchange = name(Name, Ctx)};
rdata(?DNS_TYPE_KX, [Pref, Name], Ctx) ->
    #dns_rrdata_kx{preference = uint(Pref), exchange = name(Name, Ctx)};
rdata(?DNS_TYPE_RT, [Pref, Name], Ctx) ->
    #dns_rrdata_rt{preference = uint(Pref), host = name(Name, Ctx)};
rdata(?DNS_TYPE_AFSDB, [Subtype, Name], Ctx) ->
    #dns_rrdata_afsdb{subtype = uint(Subtype), hostname = name(Name, Ctx)};
rdata(?DNS_TYPE_LP, [Pref, Name], Ctx) ->
    #dns_rrdata_lp{preference = uint(Pref), fqdn = name(Name, Ctx)};
rdata(?DNS_TYPE_PX, [Pref, Map822, MapX400], Ctx) ->
    #dns_rrdata_px{
        preference = uint(Pref), map822 = name(Map822, Ctx), mapx400 = name(MapX400, Ctx)
    };
rdata(?DNS_TYPE_RP, [Mbox, Txt], Ctx) ->
    #dns_rrdata_rp{mbox = name(Mbox, Ctx), txt = name(Txt, Ctx)};
rdata(?DNS_TYPE_MINFO, [RMailbx, EMailbx], Ctx) ->
    #dns_rrdata_minfo{rmailbx = name(RMailbx, Ctx), emailbx = name(EMailbx, Ctx)};
rdata(?DNS_TYPE_SOA, [MName, RName, Serial, Refresh, Retry, Expire, Minimum], Ctx) ->
    #dns_rrdata_soa{
        mname = name(MName, Ctx),
        rname = name(RName, Ctx),
        serial = uint(Serial),
        refresh = ttl(Refresh),
        retry = ttl(Retry),
        expire = ttl(Expire),
        minimum = ttl(Minimum)
    };
rdata(?DNS_TYPE_SRV, [Priority, Weight, Port, Target], Ctx) ->
    #dns_rrdata_srv{
        priority = uint(Priority),
        weight = uint(Weight),
        port = uint(Port),
        target = name(Target, Ctx)
    };
rdata(?DNS_TYPE_TXT, Strings, _Ctx) ->
    #dns_rrdata_txt{txt = [text(String) || String <- Strings]};
rdata(?DNS_TYPE_SPF, Strings, _Ctx) ->
    #dns_rrdata_spf{spf = [text(String) || String <- Strings]};
rdata(?DNS_TYPE_RESINFO, Strings, _Ctx) ->
    #dns_rrdata_resinfo{data = [text(String) || String <- Strings]};
rdata(?DNS_TYPE_WALLET, Strings, _Ctx) ->
    #dns_rrdata_wallet{data = [text(String) || String <- Strings]};
rdata(?DNS_TYPE_HINFO, [CPU, OS], _Ctx) ->
    #dns_rrdata_hinfo{cpu = text(CPU), os = text(OS)};
rdata(?DNS_TYPE_CAA, [Flags, Tag, Value], _Ctx) ->
    #dns_rrdata_caa{flags = uint(Flags), tag = text(Tag), value = text(Value)};
rdata(?DNS_TYPE_NAPTR, [Order, Pref, Flags, Services, Regexp, Replacement], Ctx) ->
    #dns_rrdata_naptr{
        order = uint(Order),
        preference = uint(Pref),
        flags = text(Flags),
        services = text(Services),
        regexp = text(Regexp),
        replacement = name(Replacement, Ctx)
    };
%% RFC4255§3.2, RFC6698§2.2, RFC8162§2, RFC8976§2.3, RFC4034§5.3: the hex may be
%% split by blanks, and its pieces join
rdata(?DNS_TYPE_SSHFP, [Alg, FPType | [_ | _] = FP], _Ctx) ->
    #dns_rrdata_sshfp{alg = uint(Alg), fp_type = uint(FPType), fp = hex(FP)};
rdata(?DNS_TYPE_TLSA, [Usage, Selector, MatchingType | [_ | _] = Cert], _Ctx) ->
    #dns_rrdata_tlsa{
        usage = uint(Usage),
        selector = uint(Selector),
        matching_type = uint(MatchingType),
        certificate = hex(Cert)
    };
rdata(?DNS_TYPE_SMIMEA, [Usage, Selector, MatchingType | [_ | _] = Cert], _Ctx) ->
    #dns_rrdata_smimea{
        usage = uint(Usage),
        selector = uint(Selector),
        matching_type = uint(MatchingType),
        certificate = hex(Cert)
    };
rdata(?DNS_TYPE_ZONEMD, [Serial, Scheme, Alg | [_ | _] = Hash], _Ctx) ->
    #dns_rrdata_zonemd{
        serial = uint(Serial), scheme = uint(Scheme), algorithm = uint(Alg), hash = hex(Hash)
    };
rdata(?DNS_TYPE_DS, [KeyTag, Alg, DigestType | [_ | _] = Digest], _Ctx) ->
    #dns_rrdata_ds{
        keytag = uint(KeyTag), alg = alg(Alg), digest_type = uint(DigestType), digest = hex(Digest)
    };
rdata(?DNS_TYPE_CDS, [KeyTag, Alg, DigestType | [_ | _] = Digest], _Ctx) ->
    #dns_rrdata_cds{
        keytag = uint(KeyTag), alg = alg(Alg), digest_type = uint(DigestType), digest = hex(Digest)
    };
rdata(?DNS_TYPE_DLV, [KeyTag, Alg, DigestType | [_ | _] = Digest], _Ctx) ->
    #dns_rrdata_dlv{
        keytag = uint(KeyTag), alg = alg(Alg), digest_type = uint(DigestType), digest = hex(Digest)
    };
%% RFC4034§2.2, RFC4398§2.2, RFC4701§3.2, RFC7929§2.3, RFC9886§5: base64 may be
%% split by blanks, and its pieces join
rdata(?DNS_TYPE_DNSKEY, [Flags, Protocol, Alg | [_ | _] = Key], _Ctx) ->
    {F, P, A, PublicKey} = {uint(Flags), uint(Protocol), alg(Alg), base64(Key)},
    #dns_rrdata_dnskey{
        flags = F,
        protocol = P,
        alg = A,
        public_key = PublicKey,
        keytag = keytag(F, P, A, PublicKey)
    };
rdata(?DNS_TYPE_CDNSKEY, [Flags, Protocol, Alg | [_ | _] = Key], _Ctx) ->
    {F, P, A, PublicKey} = {uint(Flags), uint(Protocol), alg(Alg), base64(Key)},
    #dns_rrdata_cdnskey{
        flags = F,
        protocol = P,
        alg = A,
        public_key = PublicKey,
        keytag = keytag(F, P, A, PublicKey)
    };
rdata(?DNS_TYPE_CERT, [Type, KeyTag, Alg | [_ | _] = Cert], _Ctx) ->
    #dns_rrdata_cert{type = uint(Type), keytag = uint(KeyTag), alg = alg(Alg), cert = base64(Cert)};
rdata(?DNS_TYPE_DHCID, Data, _Ctx) ->
    #dns_rrdata_dhcid{data = base64(Data)};
rdata(?DNS_TYPE_OPENPGPKEY, Data, _Ctx) ->
    #dns_rrdata_openpgpkey{data = base64(Data)};
rdata(?DNS_TYPE_HHIT, Data, _Ctx) ->
    #dns_rrdata_hhit{data = base64(Data)};
rdata(?DNS_TYPE_BRID, Data, _Ctx) ->
    #dns_rrdata_brid{data = base64(Data)};
%% RFC2535§7.1: the key is left out when the flags say there is none
rdata(?DNS_TYPE_KEY, [Flags, Protocol, Alg | Key], _Ctx) ->
    F = uint(Flags),
    F =< 16#FFFF orelse ?FAIL({out_of_range, flags, F}),
    #dns_rrdata_key{
        type = (F bsr 14) band 16#3,
        xt = (F bsr 12) band 16#1,
        name_type = (F bsr 8) band 16#3,
        sig = F band 16#F,
        protocol = uint(Protocol),
        alg = alg(Alg),
        public_key = base64(Key)
    };
rdata(?DNS_TYPE_RRSIG, [_, _, _, _, _, _, _, _ | [_ | _]] = Fields, Ctx) ->
    rrsig(Fields, Ctx);
rdata(?DNS_TYPE_SIG, [_, _, _, _, _, _, _, _ | [_ | _]] = Fields, Ctx) ->
    dns_encode:rrsig_to_sig(rrsig(Fields, Ctx));
rdata(?DNS_TYPE_NSEC, [Next | Types], Ctx) ->
    #dns_rrdata_nsec{next_dname = name(Next, Ctx), types = types(Types)};
rdata(?DNS_TYPE_NXT, [Next | Types], Ctx) ->
    #dns_rrdata_nxt{dname = name(Next, Ctx), types = types(Types)};
%% RFC5155§3.3: "-" for no salt, and the hash in base32hex
rdata(?DNS_TYPE_NSEC3, [HashAlg, Flags, Iterations, Salt, Hash | Types], _Ctx) ->
    F = uint(Flags),
    F =< 16#FF orelse ?FAIL({out_of_range, flags, F}),
    #dns_rrdata_nsec3{
        hash_alg = uint(HashAlg),
        opt_out = F band 16#01 =:= 1,
        iterations = uint(Iterations),
        salt = salt(Salt),
        hash = base32hex(Hash),
        types = types(Types)
    };
rdata(?DNS_TYPE_NSEC3PARAM, [HashAlg, Flags, Iterations, Salt], _Ctx) ->
    #dns_rrdata_nsec3param{
        hash_alg = uint(HashAlg),
        flags = uint(Flags),
        iterations = uint(Iterations),
        salt = salt(Salt)
    };
rdata(?DNS_TYPE_CSYNC, [Serial, Flags | Types], _Ctx) ->
    #dns_rrdata_csync{soa_serial = uint(Serial), flags = uint(Flags), types = types(Types)};
rdata(?DNS_TYPE_DSYNC, [Type, Scheme, Port, Target], Ctx) ->
    #dns_rrdata_dsync{
        rrtype = type(Type), scheme = uint(Scheme), port = uint(Port), target = name(Target, Ctx)
    };
rdata(?DNS_TYPE_URI, [Priority, Weight, Target], _Ctx) ->
    #dns_rrdata_uri{priority = uint(Priority), weight = uint(Weight), target = uri(Target)};
rdata(?DNS_TYPE_EUI48, [Address], _Ctx) ->
    #dns_rrdata_eui48{address = eui(Address, 6)};
rdata(?DNS_TYPE_EUI64, [Address], _Ctx) ->
    #dns_rrdata_eui64{address = eui(Address, 8)};
%% RFC6742§2.1-2.3
rdata(?DNS_TYPE_NID, [Pref, NodeID], _Ctx) ->
    #dns_rrdata_nid{preference = uint(Pref), node_id = ilnp64(NodeID)};
rdata(?DNS_TYPE_L64, [Pref, Locator], _Ctx) ->
    #dns_rrdata_l64{preference = uint(Pref), locator64 = ilnp64(Locator)};
rdata(?DNS_TYPE_L32, [Pref, Locator], _Ctx) ->
    #dns_rrdata_l32{preference = uint(Pref), locator32 = ipv4(Locator)};
%% RFC8777§4.3.1: the relay is "." for relay type 0, an address for types 1 and 2,
%% and a name for type 3
rdata(?DNS_TYPE_AMTRELAY, [Precedence, D, RelayType, Relay], Ctx) ->
    Type = uint(RelayType),
    #dns_rrdata_amtrelay{
        precedence = uint(Precedence),
        discovery_optional = discovery_optional(D),
        relay_type = Type,
        relay = gateway(Type, Relay, Ctx)
    };
%% RFC4025§3.1: precedence, gateway type, algorithm, gateway, as AMTRELAY's relay,
%% and the key in base64, which may be left out
rdata(?DNS_TYPE_IPSECKEY, [Precedence, GatewayType, Alg, Gateway | Key], Ctx) ->
    #dns_rrdata_ipseckey{
        precedence = uint(Precedence),
        alg = uint(Alg),
        gateway = gateway(uint(GatewayType), Gateway, Ctx),
        public_key = base64(Key)
    };
%% RFC8005§6: the HIT in hex and the key in base64, each one word
rdata(?DNS_TYPE_HIP, [Alg, HIT, Key | Servers], Ctx) ->
    #dns_rrdata_hip{
        alg = uint(Alg),
        hit = hex([HIT]),
        public_key = base64([Key]),
        rendezvous_servers = [name(Server, Ctx) || Server <- Servers]
    };
rdata(?DNS_TYPE_LOC, Fields, _Ctx) ->
    loc(Fields);
rdata(?DNS_TYPE_SVCB, [Priority, Target | Params], Ctx) ->
    #dns_rrdata_svcb{
        svc_priority = uint(Priority), target_name = name(Target, Ctx), svc_params = svcb(Params)
    };
rdata(?DNS_TYPE_HTTPS, [Priority, Target | Params], Ctx) ->
    #dns_rrdata_https{
        svc_priority = uint(Priority), target_name = name(Target, Ctx), svc_params = svcb(Params)
    };
rdata(Type, _Fields, _Ctx) ->
    case lists:member(Type, ?READABLE_TYPES) of
        true -> ?FAIL(malformed);
        false -> ?FAIL(unsupported_type)
    end.

%% RFC4034§3.2: the RRSIG fields, SIG's too (RFC2535§7.2)
-spec rrsig([field()], ctx()) -> dns:rrdata_rrsig().
rrsig([Covered, Alg, Labels, OriginalTTL, Expiration, Inception, KeyTag, Signer | Sig], Ctx) ->
    #dns_rrdata_rrsig{
        type_covered = type(Covered),
        alg = alg(Alg),
        labels = uint(Labels),
        original_ttl = ttl(OriginalTTL),
        expiration = rrsig_time(Expiration),
        inception = rrsig_time(Inception),
        keytag = uint(KeyTag),
        signers_name = name(Signer, Ctx),
        signature = base64(Sig)
    }.

%% RFC4034§3.2: a signature time is written either as seconds since the epoch or
%% as a UTC date YYYYMMDDHHmmSS. The date is always 14 digits and a 32-bit number
%% never more than 10, which tells them apart. RFC4034§3.1.5: the wire field holds
%% the seconds modulo 2^32, compared with serial number arithmetic, so a date
%% after 2106 wraps as it does in BIND. BIND also takes second 60, a leap second,
%% as the first second of the next minute; calendar refuses it, so the seconds of
%% the day are added up here.
-spec rrsig_time(field()) -> dns:uint32().
rrsig_time(Field) ->
    case uint(Field) of
        Seconds when Seconds =< 16#FFFFFFFF ->
            Seconds;
        Date when 10_000_000_000_000 =< Date, Date < 100_000_000_000_000 ->
            Year = Date div 10_000_000_000,
            YMD = {Year, Date div 100_000_000 rem 100, Date div 1_000_000 rem 100},
            {H, M, S} = {Date div 10_000 rem 100, Date div 100 rem 100, Date rem 100},
            case
                1970 =< Year andalso calendar:valid_date(YMD) andalso H < 24 andalso
                    M < 60 andalso S =< 60
            of
                true ->
                    Days = calendar:date_to_gregorian_days(YMD),
                    Gregorian = Days * 86400 + H * 3600 + M * 60 + S,
                    (Gregorian - ?UNIX_EPOCH_GREGORIAN_SECONDS) rem (1 bsl 32);
                false ->
                    ?FAIL({bad_time, Date})
            end;
        Time ->
            ?FAIL({bad_time, Time})
    end.

%% RFC1876§3: d1 [m1 [s1]] N|S d2 [m2 [s2]] E|W alt[m] [siz[m] [hp[m] [vp[m]]]].
%% The six integers the zone writer writes are read too.
-spec loc([field()]) -> dns:rrdata().
loc([_, _, _, _, _, _] = Fields) ->
    case [signed_integer(Text) || Text <- Fields, is_binary(Text)] of
        [Lat, Lon, Alt, Size, Horiz, Vert] when
            is_integer(Lat),
            is_integer(Lon),
            is_integer(Alt),
            is_integer(Size),
            is_integer(Horiz),
            is_integer(Vert)
        ->
            #dns_rrdata_loc{
                lat = Lat, lon = Lon, alt = Alt, size = Size, horiz = Horiz, vert = Vert
            };
        _ ->
            loc_rfc1876([text(Field) || Field <- Fields])
    end;
loc(Fields) ->
    loc_rfc1876([text(Field) || Field <- Fields]).

-spec loc_rfc1876([binary()]) -> dns:rrdata().
loc_rfc1876(Words) ->
    {Lat, Rest1} = loc_coordinate(Words, [], {~"N", ~"S", 90}),
    {Lon, Rest2} = loc_coordinate(Rest1, [], {~"E", ~"W", 180}),
    case Rest2 of
        [Alt | Precisions] ->
            {Size, Horiz, Vert} = loc_precisions(Precisions),
            #dns_rrdata_loc{
                lat = Lat, lon = Lon, alt = loc_cm(Alt), size = Size, horiz = Horiz, vert = Vert
            };
        [] ->
            ?FAIL(malformed)
    end.

%% Degrees, and minutes and seconds if given, to thousandths of a second of arc,
%% negative to the south and the west
-spec loc_coordinate([binary()], [binary()], {binary(), binary(), 90 | 180}) ->
    {integer(), [binary()]}.
loc_coordinate([Word | Rest], Parts, {Positive, Negative, MaxDegrees} = Axis) when Parts =/= [] ->
    case dns_domain:to_upper(Word) of
        Positive ->
            {loc_angle(lists:reverse(Parts), MaxDegrees), Rest};
        Negative ->
            {-loc_angle(lists:reverse(Parts), MaxDegrees), Rest};
        _ ->
            case Parts of
                [_, _, _] -> ?FAIL(malformed);
                _ -> loc_coordinate(Rest, [Word | Parts], Axis)
            end
    end;
loc_coordinate([Word | Rest], [], Axis) ->
    loc_coordinate(Rest, [Word], Axis);
loc_coordinate([], _Parts, _Axis) ->
    ?FAIL(malformed).

%% RFC1876§3: whole degrees, up to 90 of latitude and 180 of longitude, whole
%% minutes below 60, and seconds below 60 with at most three decimals
-spec loc_angle([binary()], 90 | 180) -> non_neg_integer().
loc_angle([Degrees | MinutesSeconds] = Parts, MaxDegrees) ->
    {Minutes, Seconds} =
        case MinutesSeconds of
            [] -> {0, 0};
            [M] -> {decimal(M, 0), 0};
            [M, S] -> {decimal(M, 0), decimal(S, 3)}
        end,
    Angle = decimal(Degrees, 0) * 3600000 + Minutes * 60000 + Seconds,
    case Minutes < 60 andalso Seconds < 60000 andalso Angle =< MaxDegrees * 3600000 of
        true -> Angle;
        false -> ?FAIL({bad_coordinate, iolist_to_binary(lists:join(~" ", Parts))})
    end.

-spec loc_precisions([binary()]) -> {integer(), integer(), integer()}.
loc_precisions([]) ->
    {?LOC_DEFAULT_SIZE, ?LOC_DEFAULT_HORIZ, ?LOC_DEFAULT_VERT};
loc_precisions([Size]) ->
    {loc_cm(Size), ?LOC_DEFAULT_HORIZ, ?LOC_DEFAULT_VERT};
loc_precisions([Size, Horiz]) ->
    {loc_cm(Size), loc_cm(Horiz), ?LOC_DEFAULT_VERT};
loc_precisions([Size, Horiz, Vert]) ->
    {loc_cm(Size), loc_cm(Horiz), loc_cm(Vert)};
loc_precisions(_) ->
    ?FAIL(malformed).

%% Metres, with an "m" or without, to centimetres
-spec loc_cm(binary()) -> integer().
loc_cm(Word) ->
    Size = byte_size(Word) - 1,
    case Word of
        <<Number:Size/binary, M>> when M =:= $m; M =:= $M -> signed_decimal(Number, 2);
        _ -> signed_decimal(Word, 2)
    end.

-spec signed_decimal(binary(), non_neg_integer()) -> integer().
signed_decimal(<<$-, Number/binary>>, Scale) -> -decimal(Number, Scale);
signed_decimal(Number, Scale) -> decimal(Number, Scale).

%% A decimal number with at most Scale decimals, in units of 10^-Scale, as BIND
%% reads the numbers of a LOC record
-spec decimal(binary(), non_neg_integer()) -> non_neg_integer().
decimal(Text, Scale) ->
    {Int, Frac} =
        case binary:split(Text, ~".") of
            [I] -> {I, <<>>};
            [I, F] -> {I, F}
        end,
    Padding = Scale - byte_size(Frac),
    case Padding >= 0 andalso digits(Int) andalso (Frac =:= <<>> orelse digits(Frac)) of
        true ->
            case number(<<Int/binary, Frac/binary, (binary:copy(~"0", Padding))/binary>>) of
                error -> ?FAIL({not_a_number, Text});
                Number -> Number
            end;
        false ->
            ?FAIL({bad_decimal, Text, Scale})
    end.

-spec digits(binary()) -> boolean().
digits(<<>>) -> false;
digits(Text) -> all_digits(Text).

-spec all_digits(binary()) -> boolean().
all_digits(<<C, Rest/binary>>) when ?IS_DIGIT(C) -> all_digits(Rest);
all_digits(<<>>) -> true;
all_digits(_) -> false.

%% Digits as a number, or error when there are none, or more than ?MAX_NUMBER holds
-spec number(binary()) -> non_neg_integer() | error.
number(<<>>) -> error;
number(Text) -> number(Text, 0).

-spec number(binary(), non_neg_integer()) -> non_neg_integer() | error.
number(<<C, Rest/binary>>, Acc) when ?IS_DIGIT(C) andalso Acc < ?SMALL_NUMBER ->
    number(Rest, Acc * 10 + (C - $0));
number(<<C, Rest/binary>>, Acc) when ?IS_DIGIT(C) ->
    case Acc * 10 + (C - $0) of
        Number when Number =< ?MAX_NUMBER -> number(Rest, Number);
        _ -> error
    end;
number(<<>>, Acc) ->
    Acc;
number(_, _Acc) ->
    error.

-spec signed_integer(binary()) -> integer() | error.
signed_integer(<<$-, C, _/binary>> = Text) when ?IS_DIGIT(C) -> to_integer(Text);
signed_integer(<<C, _/binary>> = Text) when ?IS_DIGIT(C) -> to_integer(Text);
signed_integer(_) -> error.

-spec to_integer(binary()) -> integer() | error.
to_integer(Text) ->
    try
        binary_to_integer(Text)
    catch
        error:badarg -> error
    end.

%% ============================================================================
%% Fields
%% ============================================================================

%% RFC1035§5.1: a domain name, relative to the origin unless it ends with a dot,
%% and "@" for the origin itself. The name is as dns_erlang keeps it: \X stands
%% for X and \DDD for the octet DDD, which are kept as they are, but for a dot or
%% a backslash, kept escaped as dns_erlang keeps them within a label. A name
%% without escapes is copied once, alone or with the origin after it, and its
%% first and last octets are read with binary:first/1 and binary:last/1, which
%% start no match.
-spec name(field(), ctx()) -> dns:dname().
name(Text, #ctx{origin = Origin}) when Text =:= ~"@" ->
    case Origin =:= <<>> of
        true -> ~".";
        false -> fqdn(Origin)
    end;
name(Text, #ctx{origin = Origin}) when is_binary(Text) ->
    case binary:first(Text) =:= $. of
        true when Text =:= ~"." ->
            ~".";
        true ->
            ?FAIL({empty_label, Text});
        false ->
            case plain_name(Text, $.) of
                plain ->
                    case binary:last(Text) =:= $. orelse Origin =:= <<>> of
                        true -> binary:copy(Text);
                        false -> under_origin(Text, Origin)
                    end;
                escaped ->
                    case escaped_name(Text, Text, <<>>, 0) of
                        {Name, Absolute} when Absolute; Origin =:= <<>> -> Name;
                        {Name, false} -> under_origin(Name, Origin)
                    end;
                empty_label ->
                    ?FAIL({empty_label, Text})
            end
    end;
name({quoted, Text}, _Ctx) ->
    ?FAIL({quoted_name, Text}).

%% A relative name under an origin that is not empty, as a new binary
-spec under_origin(binary(), dns:dname()) -> dns:dname().
under_origin(Name, Origin) when Origin =:= ~"." ->
    <<Name/binary, $.>>;
under_origin(Name, Origin) ->
    <<Name/binary, $., Origin/binary>>.

%% Whether a name has no escapes, and no empty label either. Previous is the octet
%% before, which a dot must not follow a dot across 7 octets read at once either.
-spec plain_name(binary(), byte()) -> plain | escaped | empty_label.
plain_name(<<W:56, Rest/binary>>, Previous) when
    ?NAME7(W) andalso not (Previous =:= $. andalso W bsr 48 =:= $.)
->
    plain_name(Rest, W band 16#FF);
plain_name(<<$\\, _/binary>>, _Previous) ->
    escaped;
plain_name(<<$., _/binary>>, $.) ->
    empty_label;
plain_name(<<C, Rest/binary>>, _Previous) ->
    plain_name(Rest, C);
plain_name(<<>>, _Previous) ->
    plain.

-spec escaped_name(binary(), binary(), binary(), non_neg_integer()) -> {binary(), boolean()}.
escaped_name(<<$\\, A, B, C, Rest/binary>>, Text, Acc, Len) when
    ?IS_DIGIT(A), ?IS_DIGIT(B), ?IS_DIGIT(C)
->
    case (A - $0) * 100 + (B - $0) * 10 + (C - $0) of
        Octet when Octet =< 255 -> escaped_name(Rest, Text, label_octet(Octet, Acc), Len + 1);
        _ -> ?FAIL({bad_escape, Text})
    end;
escaped_name(<<$\\, D, _/binary>>, Text, _Acc, _Len) when ?IS_DIGIT(D) ->
    ?FAIL({bad_escape, Text});
escaped_name(<<$\\, C, Rest/binary>>, Text, Acc, Len) ->
    escaped_name(Rest, Text, label_octet(C, Acc), Len + 1);
escaped_name(<<$\\>>, Text, _Acc, _Len) ->
    ?FAIL({bad_escape, Text});
escaped_name(<<$.>>, _Text, Acc, Len) when Len > 0 ->
    {<<Acc/binary, $.>>, true};
escaped_name(<<$., Rest/binary>>, Text, Acc, Len) when Len > 0 ->
    escaped_name(Rest, Text, <<Acc/binary, $.>>, 0);
escaped_name(<<$., _/binary>>, Text, _Acc, 0) ->
    ?FAIL({empty_label, Text});
escaped_name(<<C, Rest/binary>>, Text, Acc, Len) ->
    escaped_name(Rest, Text, <<Acc/binary, C>>, Len + 1);
escaped_name(<<>>, _Text, Acc, _Len) ->
    {Acc, false}.

-spec label_octet(byte(), binary()) -> binary().
label_octet($., Acc) -> <<Acc/binary, "\\.">>;
label_octet($\\, Acc) -> <<Acc/binary, "\\\\">>;
label_octet(Octet, Acc) -> <<Acc/binary, Octet>>.

-spec fqdn(dns:dname()) -> dns:dname().
fqdn(<<>>) ->
    ~".";
fqdn(Name) ->
    case binary:last(Name) of
        $. -> Name;
        _ -> <<Name/binary, $.>>
    end.

%% RFC1035§5.1: a <character-string>, quoted or not. \DDD is the octet DDD and \X
%% is X; \xHH is the octet HH, and \n, \t and \r a newline, a tab and a carriage
%% return, as the parser always read them.
-spec text(field()) -> binary().
text(Field) ->
    Text = field_text(Field),
    case plain_text(Text) of
        true -> binary:copy(Text);
        false -> unescape(Text, <<>>)
    end.

%% The same text, to be decoded at once rather than kept: without escapes it is the
%% field's own binary, part of the source, which what it decodes to does not hold
-spec raw_text(field()) -> binary().
raw_text(Field) ->
    Text = field_text(Field),
    case plain_text(Text) of
        true -> Text;
        false -> unescape(Text, <<>>)
    end.

%% A field's text, a word's or a quoted string's, as written
-spec field_text(field()) -> binary().
field_text({quoted, Text}) -> Text;
field_text(Text) -> Text.

%% The raw texts of fields one after another, as hex or base64 RDATA is split
-spec joined_text([field()]) -> binary().
joined_text([Field]) ->
    raw_text(Field);
joined_text(Fields) ->
    iolist_to_binary([raw_text(Field) || Field <- Fields]).

-spec plain_text(binary()) -> boolean().
plain_text(<<W:56, Rest/binary>>) when ?PLAIN7(W) -> plain_text(Rest);
plain_text(<<$\\, _/binary>>) -> false;
plain_text(<<_, Rest/binary>>) -> plain_text(Rest);
plain_text(<<>>) -> true.

%% RFC1035§5.1, as RFC9460 Appendix A reads an SvcParam's value: \DDD is the octet
%% DDD and \X is X
-spec char_string(binary()) -> binary().
char_string(Text) ->
    case plain_text(Text) of
        true -> binary:copy(Text);
        false -> char_string(Text, Text, <<>>)
    end.

-spec char_string(binary(), binary(), binary()) -> binary().
char_string(<<$\\, A, B, C, Rest/binary>>, Text, Acc) when
    ?IS_DIGIT(A), ?IS_DIGIT(B), ?IS_DIGIT(C)
->
    case (A - $0) * 100 + (B - $0) * 10 + (C - $0) of
        Octet when Octet =< 255 -> char_string(Rest, Text, <<Acc/binary, Octet>>);
        _ -> ?FAIL({bad_string_escape, Text})
    end;
char_string(<<$\\, D, _/binary>>, Text, _Acc) when ?IS_DIGIT(D) ->
    ?FAIL({bad_string_escape, Text});
char_string(<<$\\, C, Rest/binary>>, Text, Acc) ->
    char_string(Rest, Text, <<Acc/binary, C>>);
char_string(<<$\\>>, Text, _Acc) ->
    ?FAIL({bad_string_escape, Text});
char_string(<<C, Rest/binary>>, Text, Acc) ->
    char_string(Rest, Text, <<Acc/binary, C>>);
char_string(<<>>, _Text, Acc) ->
    Acc.

-spec unescape(binary(), binary()) -> binary().
unescape(<<$\\, A, B, C, Rest/binary>>, Acc) when ?IS_DIGIT(A), ?IS_DIGIT(B), ?IS_DIGIT(C) ->
    case (A - $0) * 100 + (B - $0) * 10 + (C - $0) of
        Octet when Octet =< 255 -> unescape(Rest, <<Acc/binary, Octet>>);
        _ -> unescape(<<A, B, C, Rest/binary>>, <<Acc/binary, $\\>>)
    end;
unescape(<<$\\, $x, H1, H2, Rest/binary>>, Acc) ->
    case {hex_digit(H1), hex_digit(H2)} of
        {V1, V2} when is_integer(V1), is_integer(V2) ->
            unescape(Rest, <<Acc/binary, (V1 * 16 + V2)>>);
        _ ->
            unescape(<<H1, H2, Rest/binary>>, <<Acc/binary, "\\x">>)
    end;
unescape(<<$\\, $n, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, $\n>>);
unescape(<<$\\, $t, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, $\t>>);
unescape(<<$\\, $r, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, $\r>>);
unescape(<<$\\, C, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, C>>);
unescape(<<C, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, C>>);
unescape(<<>>, Acc) ->
    Acc.

-spec hex_digit(byte()) -> 0..15 | error.
hex_digit(C) when ?IS_DIGIT(C) -> C - $0;
hex_digit(C) when $a =< C, C =< $f -> C - $a + 10;
hex_digit(C) when $A =< C, C =< $F -> C - $A + 10;
hex_digit(_) -> error.

%% A number, written as a TTL may be, 1h for 3600, as the parser read numbers
-spec uint(field()) -> non_neg_integer().
uint(Text) when is_binary(Text) ->
    case ttl_value(Text) of
        error -> ?FAIL({not_a_number, Text});
        Number -> Number
    end;
uint({quoted, Text}) ->
    ?FAIL({not_a_number, Text}).

%% RFC4034§2.2, §3.2, §5.3: an algorithm number, or its mnemonic
-spec alg(field()) -> dns:uint8().
alg(<<C, _/binary>> = Field) when ?IS_DIGIT(C) ->
    uint(Field);
alg(Text) when is_binary(Text) ->
    case dns_names:name_alg(dns_domain:to_upper(Text)) of
        undefined -> ?FAIL({unknown_algorithm, Text});
        Alg -> Alg
    end;
alg({quoted, Text}) ->
    ?FAIL({unknown_algorithm, Text}).

-spec ttl(field()) -> non_neg_integer().
ttl(Text) when is_binary(Text) ->
    case ttl_value(Text) of
        error -> ?FAIL({bad_ttl, Text});
        TTL -> TTL
    end;
ttl({quoted, Text}) ->
    ?FAIL({bad_ttl, Text}).

%% RFC2308§4, as BIND reads it: seconds, or numbers each followed by a unit, which
%% add up, as 1h30m, in either case: w, d, h, m and s, and y for 365 days
-spec ttl_value(binary()) -> non_neg_integer() | error.
ttl_value(Text) ->
    ttl_value(Text, none, 0, false).

-spec ttl_value(binary(), non_neg_integer() | none, non_neg_integer(), boolean()) ->
    non_neg_integer() | error.
ttl_value(<<C, Rest/binary>>, none, Total, Units) when ?IS_DIGIT(C) ->
    ttl_value(Rest, C - $0, Total, Units);
ttl_value(<<C, Rest/binary>>, Pending, Total, Units) when
    ?IS_DIGIT(C) andalso is_integer(Pending) andalso Pending < ?SMALL_NUMBER
->
    ttl_value(Rest, Pending * 10 + (C - $0), Total, Units);
ttl_value(<<C, Rest/binary>>, Pending, Total, Units) when
    ?IS_DIGIT(C) andalso is_integer(Pending)
->
    case Pending * 10 + (C - $0) of
        Number when Number =< ?MAX_NUMBER -> ttl_value(Rest, Number, Total, Units);
        _ -> error
    end;
ttl_value(<<Unit, Rest/binary>>, Pending, Total, _Units) when is_integer(Pending) ->
    case ttl_unit(Unit) of
        error ->
            error;
        Seconds ->
            case Total + Pending * Seconds of
                Sum when Sum =< ?MAX_NUMBER -> ttl_value(Rest, none, Sum, true);
                _ -> error
            end
    end;
ttl_value(<<>>, Pending, 0, false) when is_integer(Pending) ->
    Pending;
ttl_value(<<>>, none, Total, true) ->
    Total;
ttl_value(_, _, _, _) ->
    error.

-spec ttl_unit(byte()) -> pos_integer() | error.
ttl_unit(Unit) when Unit =:= $s; Unit =:= $S -> 1;
ttl_unit(Unit) when Unit =:= $m; Unit =:= $M -> 60;
ttl_unit(Unit) when Unit =:= $h; Unit =:= $H -> 3600;
ttl_unit(Unit) when Unit =:= $d; Unit =:= $D -> 86400;
ttl_unit(Unit) when Unit =:= $w; Unit =:= $W -> 604800;
ttl_unit(Unit) when Unit =:= $y; Unit =:= $Y -> 31536000;
ttl_unit(_) -> error.

%% RFC3597§5: a type's mnemonic, or TYPEnnn
-spec type(field()) -> dns:type().
type(Text) when is_binary(Text) ->
    case type_number(Text) of
        undefined ->
            case type_number(dns_domain:to_upper(Text)) of
                undefined -> ?FAIL({unknown_type, Text});
                Type -> Type
            end;
        Type ->
            Type
    end;
type({quoted, Text}) ->
    ?FAIL({unknown_type, Text}).

-spec types([field()]) -> [dns:type()].
types(Fields) ->
    [type(Field) || Field <- Fields].

%% RFC1035§3.4.1: four decimal octets, with no leading zeros, which would read as
%% octal elsewhere
-spec ipv4(field()) -> inet:ip4_address().
ipv4(Text) when is_binary(Text) ->
    case ipv4_octet(Text, 0, 0, 0, 0) of
        error -> ?FAIL({bad_ipv4, Text});
        IP -> IP
    end;
ipv4({quoted, Text}) ->
    ?FAIL({bad_ipv4, Text}).

%% The next octet, after Count of them, A, B and C as far as they are read
-spec ipv4_octet(binary(), 0..3, byte(), byte(), byte()) -> inet:ip4_address() | error.
ipv4_octet(<<D1, D2, D3, Rest/binary>>, Count, A, B, C) when
    $1 =< D1,
    D1 =< $2,
    ?IS_DIGIT(D2),
    ?IS_DIGIT(D3),
    (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0) =< 255
->
    ipv4_dot(Rest, Count, A, B, C, (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0));
ipv4_octet(<<D1, D2, Rest/binary>>, Count, A, B, C) when $1 =< D1, D1 =< $9, ?IS_DIGIT(D2) ->
    ipv4_dot(Rest, Count, A, B, C, (D1 - $0) * 10 + (D2 - $0));
ipv4_octet(<<D, Rest/binary>>, Count, A, B, C) when ?IS_DIGIT(D) ->
    ipv4_dot(Rest, Count, A, B, C, D - $0);
ipv4_octet(_Rest, _Count, _A, _B, _C) ->
    error.

%% A dot after each of the first three octets, and nothing after the fourth
-spec ipv4_dot(binary(), 0..3, byte(), byte(), byte(), byte()) -> inet:ip4_address() | error.
ipv4_dot(<<$., Rest/binary>>, 0, _A, _B, _C, Octet) ->
    ipv4_octet(Rest, 1, Octet, 0, 0);
ipv4_dot(<<$., Rest/binary>>, 1, A, _B, _C, Octet) ->
    ipv4_octet(Rest, 2, A, Octet, 0);
ipv4_dot(<<$., Rest/binary>>, 2, A, B, _C, Octet) ->
    ipv4_octet(Rest, 3, A, B, Octet);
ipv4_dot(<<>>, 3, A, B, C, Octet) ->
    {A, B, C, Octet};
ipv4_dot(_Rest, _Count, _A, _B, _C, _Octet) ->
    error.

%% An IPv6 address, without the "%" and zone index that inet would take and drop,
%% which have no place in a zone file. An address ending in an IPv4 address is read
%% by inet, as before, and the others the way inet reads them.
-spec ipv6(field()) -> inet:ip6_address().
ipv6(Text) when is_binary(Text) ->
    case ipv6_address(Text) of
        error -> ?FAIL({bad_ipv6, Text});
        ipv4_tail -> inet_ipv6(Text);
        IP -> IP
    end;
ipv6({quoted, Text}) ->
    ?FAIL({bad_ipv6, Text}).

-spec inet_ipv6(binary()) -> inet:ip6_address().
inet_ipv6(Text) ->
    case binary:match(Text, ~"%") of
        nomatch ->
            case inet:parse_ipv6strict_address(binary_to_list(Text)) of
                {ok, IP} -> IP;
                {error, _} -> ?FAIL({bad_ipv6, Text})
            end;
        _ ->
            ?FAIL({bad_ipv6, Text})
    end.

%% inet:parse_ipv6strict_address/1 on the binary: groups of 1 to 4 hex digits,
%% and one "::" for the zero groups the others leave out. ipv4_tail where a group
%% is followed by a dot.
-spec ipv6_address(binary()) -> inet:ip6_address() | ipv4_tail | error.
ipv6_address(~"::") ->
    {0, 0, 0, 0, 0, 0, 0, 0};
ipv6_address(<<"::", Rest/binary>>) ->
    ipv6_group(Rest, after_gap, [], [], 0, 0, 0);
ipv6_address(Text) ->
    ipv6_group(Text, before_gap, [], [], 0, 0, 0).

%% Before and After are the groups before and after the "::", last first, and Count
%% how many there are of both
-spec ipv6_group(
    binary(),
    before_gap | after_gap,
    [0..16#FFFF],
    [0..16#FFFF],
    non_neg_integer(),
    non_neg_integer(),
    0..16#FFFF
) -> inet:ip6_address() | ipv4_tail | error.
ipv6_group(<<C, Rest/binary>>, Gap, Before, After, Count, Digits, Value) when
    Digits < 4 andalso ?IS_DIGIT(C)
->
    ipv6_group(Rest, Gap, Before, After, Count, Digits + 1, Value * 16 + C - $0);
ipv6_group(<<C, Rest/binary>>, Gap, Before, After, Count, Digits, Value) when
    Digits < 4 andalso $a =< C andalso C =< $f
->
    ipv6_group(Rest, Gap, Before, After, Count, Digits + 1, Value * 16 + C - $a + 10);
ipv6_group(<<C, Rest/binary>>, Gap, Before, After, Count, Digits, Value) when
    Digits < 4 andalso $A =< C andalso C =< $F
->
    ipv6_group(Rest, Gap, Before, After, Count, Digits + 1, Value * 16 + C - $A + 10);
ipv6_group(_Rest, _Gap, _Before, _After, _Count, 0, _Value) ->
    error;
ipv6_group(Rest, before_gap, Before, [], Count, _Digits, Value) ->
    ipv6_before_gap(Rest, [Value | Before], Count + 1);
ipv6_group(Rest, after_gap, Before, After, Count, _Digits, Value) ->
    ipv6_after_gap(Rest, Before, [Value | After], Count + 1).

-spec ipv6_before_gap(binary(), [0..16#FFFF], pos_integer()) ->
    inet:ip6_address() | ipv4_tail | error.
ipv6_before_gap(<<>>, [H, G, F, E, D, C, B, A], 8) ->
    {A, B, C, D, E, F, G, H};
ipv6_before_gap(~"::", Before, Count) when Count =< 7 ->
    ipv6_zeros(Before, [], Count);
ipv6_before_gap(<<"::", Rest/binary>>, Before, Count) when Count =< 6 ->
    ipv6_group(Rest, after_gap, Before, [], Count, 0, 0);
ipv6_before_gap(<<$:, Rest/binary>>, Before, Count) when Count =< 7 ->
    ipv6_group(Rest, before_gap, Before, [], Count, 0, 0);
ipv6_before_gap(<<$., _/binary>>, _Before, _Count) ->
    ipv4_tail;
ipv6_before_gap(_Rest, _Before, _Count) ->
    error.

-spec ipv6_after_gap(binary(), [0..16#FFFF], [0..16#FFFF], pos_integer()) ->
    inet:ip6_address() | ipv4_tail | error.
ipv6_after_gap(<<>>, Before, After, Count) when Count =< 7 ->
    ipv6_zeros(Before, After, Count);
ipv6_after_gap(<<$:, Rest/binary>>, Before, After, Count) when Count =< 6 ->
    ipv6_group(Rest, after_gap, Before, After, Count, 0, 0);
ipv6_after_gap(<<$., _/binary>>, _Before, _After, _Count) ->
    ipv4_tail;
ipv6_after_gap(_Rest, _Before, _After, _Count) ->
    error.

-spec ipv6_zeros([0..16#FFFF], [0..16#FFFF], non_neg_integer()) -> inet:ip6_address().
ipv6_zeros(Before, After, Count) ->
    [A, B, C, D, E, F, G, H] = lists:reverse(
        Before, lists:duplicate(8 - Count, 0) ++ lists:reverse(After)
    ),
    {A, B, C, D, E, F, G, H}.

-spec hex([field()]) -> binary().
hex(Fields) ->
    decode_hex(joined_text(Fields)).

-spec decode_hex(binary()) -> binary().
decode_hex(Hex) ->
    try
        binary:decode_hex(Hex)
    catch
        error:badarg -> ?FAIL({bad_hex, Hex})
    end.

-spec base64([field()]) -> binary().
base64(Fields) ->
    Base64 = joined_text(Fields),
    try
        base64:decode(Base64)
    catch
        error:_ -> ?FAIL({bad_base64, Base64})
    end.

%% RFC5155§3.3: "-" for no salt
-spec salt(field()) -> binary().
salt(Field) ->
    case raw_text(Field) of
        ~"-" -> <<>>;
        Hex -> decode_hex(Hex)
    end.

%% RFC4648§7, without padding, as RFC5155§3.3 writes the next hashed owner name;
%% padding is read too, as the zone writer wrote it
-spec base32hex(field()) -> binary().
base32hex(Field) ->
    Text = raw_text(Field),
    Digits = trim_trailing(Text, $=),
    try <<<<(base32hex_digit(C)):5>> || <<C>> <= Digits>> of
        Bits ->
            Size = bit_size(Bits) div 8,
            Spare = bit_size(Bits) rem 8,
            case Bits of
                <<Hash:Size/binary, 0:Spare>> when Spare < 5 -> Hash;
                _ -> ?FAIL({bad_base32hex, Text})
            end
    catch
        error:badarg -> ?FAIL({bad_base32hex, Text})
    end.

-spec base32hex_digit(byte()) -> 0..31.
base32hex_digit(C) when ?IS_DIGIT(C) -> C - $0;
base32hex_digit(C) when $A =< C, C =< $V -> C - $A + 10;
base32hex_digit(C) when $a =< C, C =< $v -> C - $a + 10;
base32hex_digit(_) -> erlang:error(badarg).

%% RFC7553§4.4: the target is a URI, kept as it is written
-spec uri(field()) -> binary().
uri(Field) ->
    Target = text(Field),
    try uri_string:normalize(Target) of
        {error, _, _} -> ?FAIL({bad_uri, Target});
        _ -> Target
    catch
        error:_ -> ?FAIL({bad_uri, Target})
    end.

%% RFC7043§3, §4: six or eight octets in hex, separated by hyphens; colons are
%% read too, as are the hex digits alone, as the zone writer writes them
-spec eui(field(), 6 | 8) -> binary().
eui(Field, Size) ->
    Text = raw_text(Field),
    case decode_hex(<<<<C>> || <<C>> <= Text, C =/= $-, C =/= $:>>) of
        <<_:Size/binary>> = Address -> Address;
        _ -> ?FAIL({bad_eui, Text})
    end.

%% RFC6742§2.1, §2.3: a NodeID or Locator64 is four colon-separated groups of one
%% to four hex digits, as in an AAAA record, but never with the "::" shorthand
-spec ilnp64(field()) -> <<_:64>>.
ilnp64(Text) when is_binary(Text) ->
    case binary:split(Text, ~":", [global]) of
        [_, _, _, _] = Groups ->
            iolist_to_binary([ilnp64_group(Group, Text) || Group <- Groups]);
        _ ->
            ?FAIL({bad_ilnp64, Text})
    end;
ilnp64({quoted, Text}) ->
    ?FAIL({bad_ilnp64, Text}).

-spec ilnp64_group(binary(), binary()) -> <<_:16>>.
ilnp64_group(Group, Text) when 1 =< byte_size(Group), byte_size(Group) =< 4 ->
    case decode_hex(<<(binary:copy(~"0", 4 - byte_size(Group)))/binary, Group/binary>>) of
        <<_:16>> = Bin -> Bin;
        _ -> ?FAIL({bad_ilnp64, Text})
    end;
ilnp64_group(_Group, Text) ->
    ?FAIL({bad_ilnp64, Text}).

-spec discovery_optional(field()) -> boolean().
discovery_optional(~"0") -> false;
discovery_optional(~"1") -> true;
discovery_optional(Field) -> ?FAIL({bad_discovery_optional, field_text(Field)}).

%% RFC4025§3.1, RFC8777§4.3.1: the gateway or relay of each type
-spec gateway(non_neg_integer(), field(), ctx()) -> <<>> | inet:ip_address() | dns:dname().
gateway(0, ~".", _Ctx) -> <<>>;
gateway(1, Field, _Ctx) -> ipv4(Field);
gateway(2, Field, _Ctx) -> ipv6(Field);
gateway(3, Field, Ctx) -> name(Field, Ctx);
gateway(Type, Field, _Ctx) -> ?FAIL({bad_gateway, Type, field_text(Field)}).

%% RFC9460§2.1: key=value, or a key alone, each value a <character-string>, which
%% follows the "=" quoted, key="a value", as a field of its own
-spec svcb([field()]) -> dns:svcb_svc_params().
svcb(Fields) ->
    case dns_svcb_params:from_zone(svcb_params(Fields)) of
        {ok, Params} -> Params;
        {error, Reason} -> ?FAIL(Reason)
    end.

-spec svcb_params([field()]) -> [{binary(), binary() | none}].
svcb_params([Text | Rest]) when is_binary(Text) ->
    case {binary:split(Text, ~"="), Rest} of
        {[Key], _} ->
            [{Key, none} | svcb_params(Rest)];
        {[Key, <<>>], [{quoted, Value} | Rest1]} ->
            [{Key, char_string(Value)} | svcb_params(Rest1)];
        {[Key, Value], _} ->
            [{Key, char_string(Value)} | svcb_params(Rest)]
    end;
svcb_params([{quoted, Text} | _]) ->
    ?FAIL({invalid_svcparam_format, Text});
svcb_params([]) ->
    [].

%% RFC4034 Appendix B
-spec keytag(non_neg_integer(), non_neg_integer(), non_neg_integer(), binary()) -> dns:uint16().
keytag(Flags, Protocol, Alg, PublicKey) ->
    Sum = keytag_sum(<<Flags:16, Protocol:8, Alg:8, PublicKey/binary>>, 0),
    ((Sum band 16#FFFF) + (Sum bsr 16)) band 16#FFFF.

-spec keytag_sum(binary(), non_neg_integer()) -> non_neg_integer().
keytag_sum(<<Word:16, Rest/binary>>, Acc) -> keytag_sum(Rest, Acc + Word);
keytag_sum(<<Octet:8>>, Acc) -> Acc + (Octet bsl 8);
keytag_sum(<<>>, Acc) -> Acc.

%% ============================================================================
%% Errors
%% ============================================================================

-spec error_detail(
    dns_zone:error_type(), binary(), binary() | undefined, term(), pos_integer(), ctx()
) -> dns_zone:error_detail().
error_detail(Type, Message, Suggestion, Details, Line, #ctx{filename = File, source = Source}) ->
    Location =
        case File of
            undefined -> #{line => Line};
            _ -> #{line => Line, file => File}
        end,
    Error = #{
        type => Type, message => Message, details => copy_binaries(Details), location => Location
    },
    WithContext =
        case source_line(Source, Line) of
            undefined -> Error;
            Context -> Error#{context => Context}
        end,
    case Suggestion of
        undefined -> WithContext;
        _ -> WithContext#{suggestion => Suggestion}
    end.

%% The texts in an error's details are fields, cut out of the source without a
%% copy, and each would keep the whole source for as long as the error is kept.
%% They are copied, as the text of the line is.
-spec copy_binaries(dynamic()) -> dynamic().
copy_binaries(Bin) when is_binary(Bin) ->
    binary:copy(Bin);
copy_binaries([Head | Tail]) ->
    [copy_binaries(Head) | copy_binaries(Tail)];
copy_binaries(Tuple) when is_tuple(Tuple) ->
    list_to_tuple(copy_binaries(tuple_to_list(Tuple)));
copy_binaries(Map) when is_map(Map) ->
    maps:from_list(copy_binaries(maps:to_list(Map)));
copy_binaries(Term) ->
    Term.

-spec source_line(binary(), pos_integer()) -> binary() | undefined.
source_line(Source, 1) ->
    Line =
        case binary:match(Source, ~"\n") of
            nomatch -> Source;
            {Pos, _} -> binary:part(Source, 0, Pos)
        end,
    binary:copy(trim_trailing(Line, $\r));
source_line(Source, Line) ->
    case binary:match(Source, ~"\n") of
        nomatch -> undefined;
        {Pos, _} -> source_line(binary:part(Source, Pos + 1, byte_size(Source) - Pos - 1), Line - 1)
    end.

%% The binary without the octets it ends with that are the one given
-spec trim_trailing(binary(), byte()) -> binary().
trim_trailing(Bin, Octet) ->
    case Bin of
        <<Rest:(byte_size(Bin) - 1)/binary, Octet>> -> trim_trailing(Rest, Octet);
        _ -> Bin
    end.

-spec file_error(file:filename_all(), term()) -> dns_zone:error_detail().
file_error(Filename, Reason) ->
    #{
        type => file,
        message => iolist_to_binary(io_lib:format("Failed to read file: ~p", [Reason])),
        details => {file_error, Reason},
        location => #{file => Filename}
    }.

%% Each reason's fields are checked as the message uses them; a reason of another
%% shape is written as a term
-spec reason_text(term()) -> binary().
reason_text({not_a_number, Text}) when is_binary(Text) ->
    <<"not a number: ", Text/binary>>;
reason_text({bad_ttl, Text}) when is_binary(Text) ->
    <<"not a TTL: ", Text/binary>>;
reason_text({bad_ipv4, Text}) when is_binary(Text) ->
    <<"not an IPv4 address: ", Text/binary>>;
reason_text({bad_ipv6, Text}) when is_binary(Text) ->
    <<"not an IPv6 address: ", Text/binary>>;
reason_text({bad_hex, Text}) when is_binary(Text) ->
    <<"not hex: ", Text/binary>>;
reason_text({bad_base64, Text}) when is_binary(Text) ->
    <<"not base64: ", Text/binary>>;
reason_text({bad_base32hex, Text}) when is_binary(Text) ->
    <<"not base32hex: ", Text/binary>>;
reason_text({bad_uri, Text}) when is_binary(Text) ->
    <<"not a URI: ", Text/binary>>;
reason_text({bad_eui, Text}) when is_binary(Text) ->
    <<"not an EUI address: ", Text/binary>>;
reason_text({bad_ilnp64, Text}) when is_binary(Text) ->
    <<"not four groups of hex digits: ", Text/binary>>;
reason_text({bad_discovery_optional, Text}) when is_binary(Text) ->
    <<"the D-bit is not 0 or 1: ", Text/binary>>;
reason_text({unknown_type, Text}) when is_binary(Text) ->
    <<"unknown type: ", Text/binary>>;
reason_text({unknown_algorithm, Text}) when is_binary(Text) ->
    <<"unknown algorithm: ", Text/binary>>;
reason_text({quoted_name, Text}) when is_binary(Text) ->
    <<"a name cannot be quoted: ", Text/binary>>;
reason_text({quoted_owner, Text}) when is_binary(Text) ->
    <<"an owner name cannot be quoted: ", Text/binary>>;
reason_text({empty_label, Text}) when is_binary(Text) ->
    <<"a name with an empty label: ", Text/binary>>;
reason_text({bad_escape, Text}) when is_binary(Text) ->
    <<"a name with a bad escape: ", Text/binary>>;
reason_text({bad_string_escape, Text}) when is_binary(Text) ->
    <<"a string with a bad escape: ", Text/binary>>;
reason_text({bad_decimal, Text, Scale}) when is_binary(Text), is_integer(Scale) ->
    iolist_to_binary(io_lib:format("not a number with up to ~b decimals: ~s", [Scale, Text]));
reason_text({bad_coordinate, Text}) when is_binary(Text) ->
    <<"degrees, minutes or seconds out of range: ", Text/binary>>;
reason_text({unexpected_field, Text}) when is_binary(Text) ->
    <<"expected a TTL, a class or a type: ", Text/binary>>;
reason_text(no_type) ->
    ~"no type";
reason_text({no_rdata, Mnemonic}) when is_binary(Mnemonic) ->
    <<"no RDATA for ", Mnemonic/binary>>;
reason_text(unbalanced_parenthesis) ->
    ~"a closing parenthesis without an opening one";
reason_text(unclosed_parenthesis) ->
    ~"a parenthesis left open";
reason_text(unterminated_string) ->
    ~"a quoted string left open";
reason_text(unsupported_type) ->
    ~"no presentation format, use RFC 3597's \\# form";
reason_text(rfc3597_no_length) ->
    ~"\\# without a length";
reason_text({rfc3597_length_mismatch, Length, Actual}) ->
    iolist_to_binary(io_lib:format("\\# of length ~b with ~b octets", [Length, Actual]));
reason_text({bad_directive, Name, Args}) ->
    iolist_to_binary(
        io_lib:format("unknown directive, or one with ~b arguments: ~s", [Args, Name])
    );
reason_text({out_of_range, What, Text}) when is_binary(What), is_binary(Text) ->
    <<What/binary, " out of range: ", Text/binary>>;
reason_text({out_of_range, What, Value}) ->
    iolist_to_binary(io_lib:format("~s out of range: ~b", [What, Value]));
reason_text({bad_time, Time}) ->
    iolist_to_binary(io_lib:format("not a time: ~b", [Time]));
reason_text({bad_gateway, Type, Text}) when is_integer(Type), is_binary(Text) ->
    <<"not a gateway of type ", (integer_to_binary(Type))/binary, ": ", Text/binary>>;
%% The text of the zone is octets, which ~s and ~p write as they are
reason_text(Reason) ->
    iolist_to_binary(io_lib:format("~0p", [Reason])).

%% Messages and suggestions for RDATA that does not have the fields of its type
-spec rdata_error_message(binary(), [field()]) -> {binary(), binary() | undefined}.
rdata_error_message(~"SSHFP", Fields) when length(Fields) < 3 ->
    {
        <<"Invalid SSHFP record: expected 3 fields ", "(algorithm, fptype, fingerprint), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        SSHFP requires: algorithm fptype "hexfingerprint"
            Example: example.com. 3600 IN SSHFP 2 1 "123ABC..."
        """
    };
rdata_error_message(~"SSHFP", _Fields) ->
    {
        ~"Invalid SSHFP record: fingerprint must be even-length hex string",
        ~"Hex strings must have an even number of characters (each byte = 2 hex digits)"
    };
rdata_error_message(~"TLSA", Fields) when length(Fields) < 4 ->
    {
        <<"Invalid TLSA record: expected 4 fields ",
            "(usage, selector, matching-type, cert-data), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        TLSA requires: usage selector matching-type "hexcertdata",
            Example: _443._tcp.example.com. IN TLSA 3 1 1 "ABC123..."
        """
    };
rdata_error_message(~"TLSA", _Fields) ->
    {
        ~"Invalid TLSA record: certificate data must be even-length hex string",
        ~"Hex strings must have an even number of characters"
    };
rdata_error_message(~"NAPTR", Fields) when length(Fields) < 6 ->
    {
        <<"Invalid NAPTR record: expected 6 fields ",
            "(order, preference, flags, services, regexp, replacement), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        NAPTR requires: order preference "flags" "services" "regexp" replacement
            Example: example.com. IN NAPTR 100 10 "S" "SIP+D2T" _sip._tcp.example.com.
        """
    };
rdata_error_message(~"CERT", Fields) when length(Fields) < 4 ->
    {
        <<"Invalid CERT record: expected 4 fields ", "(type, keytag, algorithm, cert-data), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        CERT requires: type keytag algorithm "certdata"
            Example: example.com. IN CERT 1 12345 8 "MIICXAIBAAKBgQC8"
        """
    };
rdata_error_message(~"DHCID", _Fields) ->
    {
        ~"Invalid DHCID record: requires base64-encoded data",
        ~"""
        DHCID requires: "base64data"
            Example: example.com. IN DHCID "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="
        """
    };
rdata_error_message(~"DS", Fields) when length(Fields) < 4 ->
    {
        <<"Invalid DS record: expected 4 fields ", "(keytag, algorithm, digest-type, digest), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        DS requires: keytag algorithm digest-type "hexdigest"
            Example: example.com. IN DS 12345 8 2 "49FD46E6C4B45C55D4AC"
        """
    };
rdata_error_message(~"DS", _Fields) ->
    {
        ~"Invalid DS record: digest must be even-length hex string",
        ~"Hex strings must have an even number of characters"
    };
rdata_error_message(~"DNSKEY", Fields) when length(Fields) < 4 ->
    {
        <<"Invalid DNSKEY record: expected 4 fields ",
            "(flags, protocol, algorithm, public-key), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        DNSKEY requires: flags protocol algorithm "base64publickey"
            Example: example.com. IN DNSKEY 256 3 8 "AwEAAa..."
        """
    };
rdata_error_message(~"DNSKEY", _Fields) ->
    {
        ~"Invalid DNSKEY record: public key must be valid base64",
        ~"Public key should be base64-encoded key material"
    };
rdata_error_message(~"ZONEMD", Fields) when length(Fields) < 4 ->
    {
        <<"Invalid ZONEMD record: expected 4 fields ", "(serial, scheme, algorithm, hash), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        ZONEMD requires: serial scheme algorithm "hexhash"
            Example: example.com. IN ZONEMD 2025121100 1 1 F8857A5A89EF49FF..."
        """
    };
rdata_error_message(~"ZONEMD", _Fields) ->
    {
        ~"Invalid ZONEMD record: hash must be even-length hex string",
        ~"Hex strings must have an even number of characters"
    };
rdata_error_message(~"SVCB", Fields) when length(Fields) < 2 ->
    {
        <<"Invalid SVCB record: expected at least 2 fields ", "(priority, target), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        SVCB requires: priority target
            Example: example.com. IN SVCB 1 svc.example.com.
        """
    };
rdata_error_message(~"SVCB", _Fields) ->
    {
        ~"Invalid SVCB record: malformed priority or target",
        ~"Priority must be an integer, target must be a domain name"
    };
rdata_error_message(~"HTTPS", Fields) when length(Fields) < 2 ->
    {
        <<"Invalid HTTPS record: expected at least 2 fields ", "(priority, target), got ",
            (integer_to_binary(length(Fields)))/binary>>,
        ~"""
        HTTPS requires: priority target
            Example: example.com. IN HTTPS 1 .
        """
    };
rdata_error_message(~"HTTPS", _Fields) ->
    {
        ~"Invalid HTTPS record: malformed priority or target",
        ~"Priority must be an integer, target must be a domain name"
    };
rdata_error_message(TypeName, _Fields) when TypeName =:= ~"NID"; TypeName =:= ~"L64" ->
    {
        <<"Invalid ", TypeName/binary, " record: expected a preference and a 64-bit value">>,
        <<TypeName/binary,
            " requires: preference and four colon-separated groups of hex digits, "
            "without the \"::\" shorthand\n"
            "    Example: example.com. 3600 IN ", TypeName/binary, " 10 0014:4fff:ff20:ee64">>
    };
rdata_error_message(~"AMTRELAY", _Fields) ->
    {
        ~"Invalid AMTRELAY record: expected a precedence, a D-bit, a relay type and a relay",
        ~"""
        AMTRELAY requires: precedence (0-255), D-bit (0 or 1), relay type and relay, the relay
        being "." for type 0, an IPv4 address for type 1, an IPv6 address for type 2 and a
        domain name for type 3
            Example: 12.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 10 0 1 203.0.113.15
        """
    };
rdata_error_message(~"IPSECKEY", _Fields) ->
    {
        <<"Invalid IPSECKEY record: expected a precedence, a gateway type, an algorithm ",
            "and a gateway">>,
        ~"""
        IPSECKEY requires: precedence gateway-type algorithm gateway [base64-key], the
        gateway being "." for type 0, an IPv4 address for type 1, an IPv6 address for
        type 2 and a domain name for type 3 (RFC 4025)
            Example: 38.2.0.192.in-addr.arpa. 7200 IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG...
        """
    };
rdata_error_message(TypeName, _Fields) when TypeName =:= ~"HHIT"; TypeName =:= ~"BRID" ->
    {
        <<"Invalid ", TypeName/binary, " record: data must be valid base64">>,
        <<TypeName/binary,
            " requires: base64 CBOR data, which may be split into several pieces\n"
            "    Example: example.com. 3600 IN ", TypeName/binary, " ( gxJpM2ZmOCAw MDBhWQEY... )">>
    };
rdata_error_message(TypeName, _Fields) ->
    {<<"Invalid ", TypeName/binary, " record: malformed RDATA">>, undefined}.

-spec format_location(dns_zone:error_location(), dns_zone:error_type()) -> iolist().
format_location(#{line := Line, file := File}, Type) when File /= undefined ->
    io_lib:format("~s at ~s:~p (~p):~n", [capitalize(Type), File, Line, Type]);
format_location(#{file := File}, Type) when File /= undefined ->
    io_lib:format("~s at ~s (~p):~n", [capitalize(Type), File, Type]);
format_location(#{line := Line}, Type) ->
    io_lib:format("~s at line ~p (~p):~n", [capitalize(Type), Line, Type]);
format_location(_Location, Type) ->
    io_lib:format("~s:~n", [capitalize(Type)]).

-spec format_context(binary() | undefined) -> iolist().
format_context(undefined) ->
    [];
format_context(Context) ->
    ["  | ", Context, "\n"].

-spec format_suggestion(binary() | undefined) -> iolist().
format_suggestion(undefined) ->
    [];
format_suggestion(Suggestion) ->
    ["\nSuggestion:\n  ", Suggestion, "\n"].

-spec capitalize(atom()) -> unicode:chardata().
capitalize(Atom) ->
    string:titlecase(atom_to_list(Atom)).
