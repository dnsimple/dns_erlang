-module(dns_zone_encode).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-dialyzer(no_improper_lists).

-export([encode_rdata/2, encode_rdata/3, encode_rr/2, encode_string/2, encode_file/3]).
-export([ntoa/1]).

-define(DEFAULT_ORIGIN, <<>>).
-define(DEFAULT_RELATIVE_NAMES, true).
-define(DEFAULT_TTL_FORMAT, seconds).
-define(DEFAULT_OMIT_CLASS, false).
-define(DEFAULT_SEPARATOR, ~" ").
%% calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
-define(UNIX_EPOCH_GREGORIAN_SECONDS, 62_167_219_200).

-spec encode_file([dns:rr()], file:filename(), dns_zone:encode_options()) ->
    ok | {error, term()}.
encode_file(Records, Filename, Opts) ->
    IOData = encode_string(Records, Opts),
    file:write_file(Filename, IOData).

-spec encode_string([dns:rr()], dns_zone:encode_options()) -> iodata().
encode_string(Records, Opts) ->
    LwrOrigin = dns_domain:to_lower(maps:get(origin, Opts, ?DEFAULT_ORIGIN)),
    SortedRecords = sort_zone_records(Records),
    build_zone_lines(SortedRecords, LwrOrigin, Opts).

-spec encode_rr(dns:rr(), dns_zone:encode_options()) -> iolist().
encode_rr(#dns_rr{name = Name} = RR, Opts) ->
    encode_rr(dns_domain:to_lower(Name), RR, Opts).

%% A record, whose owner is LwrName, lowercased
-spec encode_rr(dns:dname(), dns:rr(), dns_zone:encode_options()) -> iolist().
encode_rr(LwrName, #dns_rr{type = Type, class = Class, ttl = TTL, data = Data}, Opts) ->
    LwrOrigin = dns_domain:to_lower(maps:get(origin, Opts, ?DEFAULT_ORIGIN)),
    OmitClass = maps:get(omit_class, Opts, ?DEFAULT_OMIT_CLASS),
    TTLFormat = maps:get(ttl_format, Opts, ?DEFAULT_TTL_FORMAT),
    RelativeNames = maps:get(relative_names, Opts, ?DEFAULT_RELATIVE_NAMES),
    Separator = maps:get(separator, Opts, ?DEFAULT_SEPARATOR),
    OwnerName = encode_dname(LwrName, LwrOrigin, RelativeNames),
    EncodedTTL = encode_ttl(TTL, TTLFormat),
    EncodedClass = maybe_encode_class(Class, OmitClass),
    TypeBin = encode_type(Type),
    RDataStr = rdata_text(Type, Data, LwrOrigin, RelativeNames, Separator),
    %% Combine all parts with separator
    %% Format: owner [TTL] [class] type rdata
    %% If TTL is empty and class is omitted, we still need proper spacing
    Tail =
        case EncodedClass of
            <<>> ->
                [TypeBin, Separator, RDataStr];
            _ ->
                [EncodedClass, Separator, TypeBin, Separator, RDataStr]
        end,
    case EncodedTTL of
        <<>> ->
            [OwnerName, Separator | Tail];
        _ ->
            [OwnerName, Separator, EncodedTTL, Separator | Tail]
    end.

-spec encode_rdata(dns:type(), dns:rrdata()) -> iodata().
encode_rdata(Type, RData) ->
    rdata_text(Type, RData, <<>>, true, ?DEFAULT_SEPARATOR).

-spec encode_rdata(dns:type(), dns:rrdata(), dns_zone:encode_options()) -> iodata().
encode_rdata(Type, RData, Opts) ->
    Origin = dns_domain:to_lower(maps:get(origin, Opts, ?DEFAULT_ORIGIN)),
    RelativeNames = maps:get(relative_names, Opts, ?DEFAULT_RELATIVE_NAMES),
    Separator = maps:get(separator, Opts, ?DEFAULT_SEPARATOR),
    rdata_text(Type, RData, Origin, RelativeNames, Separator).

%% ============================================================================
%% Helper Functions
%% ============================================================================

%% Encode domain name, optionally making it relative to origin.
%% When returning an absolute name (no origin or not under origin, or relative names
%% not wanted), ensure FQDN (trailing dot): without it a zone file reads the name as
%% relative to its origin, and the root, <<>> as dns_decode gives it, as nothing.
-spec encode_dname(dns:dname(), dns:dname(), boolean()) -> dns:dname().
encode_dname(Name, _Origin, false) ->
    escape_dname(ensure_fqdn(Name));
encode_dname(Name, <<>>, true) ->
    escape_dname(ensure_fqdn(Name));
encode_dname(Name, Origin, true) ->
    case is_subdomain(Name, Origin) of
        true ->
            %% Name is under origin, make it relative
            case make_relative(Name, Origin) of
                relative -> ~"@";
                RelativeName -> escape_dname(RelativeName)
            end;
        false ->
            %% Name is not under origin or no origin, use absolute FQDN
            escape_dname(ensure_fqdn(Name))
    end.

%% RFC1035§5.1: a name as BIND writes it, \DDD for an octet that is not printable
%% or is a blank, and a backslash before one a zone file reads otherwise: a quote,
%% a parenthesis, a semicolon, "@" and "$". A dot or a backslash within a label
%% is escaped already, as dns_erlang keeps names.
-spec escape_dname(dns:dname()) -> dns:dname().
escape_dname(Name) ->
    case plain_dname(Name) of
        true -> Name;
        false -> escape_dname(Name, <<>>)
    end.

-spec plain_dname(binary()) -> boolean().
plain_dname(<<C, Rest/binary>>) when
    $! =< C, C =< $~, C =/= $", C =/= $(, C =/= $), C =/= $;, C =/= $@, C =/= $$
->
    plain_dname(Rest);
plain_dname(<<_, _/binary>>) ->
    false;
plain_dname(<<>>) ->
    true.

-spec escape_dname(binary(), binary()) -> binary().
escape_dname(<<$\\, C, Rest/binary>>, Acc) ->
    escape_dname(Rest, <<Acc/binary, $\\, C>>);
escape_dname(<<C, Rest/binary>>, Acc) when C =< $\s; C > $~ ->
    Escaped = iolist_to_binary(io_lib:format("\\~3..0B", [C])),
    escape_dname(Rest, <<Acc/binary, Escaped/binary>>);
escape_dname(<<C, Rest/binary>>, Acc) when
    C =:= $"; C =:= $(; C =:= $); C =:= $;; C =:= $@; C =:= $$
->
    escape_dname(Rest, <<Acc/binary, $\\, C>>);
escape_dname(<<C, Rest/binary>>, Acc) ->
    escape_dname(Rest, <<Acc/binary, C>>);
escape_dname(<<>>, Acc) ->
    Acc.

%% Ensure domain name is fully qualified (trailing dot) for absolute form. A dot
%% a backslash escapes is within the last label, which the root still follows.
-spec ensure_fqdn(dns:dname()) -> dns:dname().
ensure_fqdn(Name) when is_binary(Name) ->
    case 0 < byte_size(Name) andalso unescaped_dot(Name, byte_size(Name) - 1) of
        true -> Name;
        false -> <<Name/binary, ".">>
    end.

%% Whether the octet at Pos is a dot that no backslash escapes: an even number of
%% backslashes before it
-spec unescaped_dot(binary(), non_neg_integer()) -> boolean().
unescaped_dot(Name, Pos) ->
    binary:at(Name, Pos) =:= $. andalso backslashes_before(Name, Pos, 0) rem 2 =:= 0.

-spec backslashes_before(binary(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
backslashes_before(_Name, 0, Count) ->
    Count;
backslashes_before(Name, Pos, Count) ->
    case binary:at(Name, Pos - 1) of
        $\\ -> backslashes_before(Name, Pos - 1, Count + 1);
        _ -> Count
    end.

%% Check if Name is a subdomain of Origin (or equals it)
-spec is_subdomain(dns:dname(), dns:dname()) -> boolean().
is_subdomain(_Name, <<>>) ->
    false;
is_subdomain(Name, Origin) ->
    NameLen = byte_size(Name),
    OriginLen = byte_size(Origin),
    %% Use longest_common_suffix to check if Name ends with Origin
    case binary:longest_common_suffix([Name, Origin]) of
        OriginLen ->
            %% Name ends with Origin
            case NameLen =:= OriginLen of
                true ->
                    %% Name equals origin
                    true;
                false ->
                    %% Check there's a dot before the origin part, which no backslash
                    %% makes part of a label
                    NameLen > OriginLen andalso unescaped_dot(Name, NameLen - OriginLen - 1)
            end;
        _ ->
            false
    end.

%% Encode TTL with optional unit formatting. Always include, even if 0
-spec encode_ttl(dns:ttl(), seconds | units) -> iodata().
encode_ttl(TTL, seconds) when is_integer(TTL) ->
    integer_to_binary(TTL);
encode_ttl(TTL, units) when is_integer(TTL) ->
    format_ttl_units(TTL).

%% Format TTL with time units (w, d, h, m, s)
-spec format_ttl_units(dns:ttl()) -> iodata().
format_ttl_units(Seconds) ->
    Weeks = Seconds div 604800,
    Days = (Seconds rem 604800) div 86400,
    Hours = (Seconds rem 86400) div 3600,
    Minutes = (Seconds rem 3600) div 60,
    Secs = Seconds rem 60,
    Parts = [
        case Weeks of
            0 -> <<>>;
            W -> <<(integer_to_binary(W))/binary, "w">>
        end,
        case Days of
            0 -> <<>>;
            D -> <<(integer_to_binary(D))/binary, "d">>
        end,
        case Hours of
            0 -> <<>>;
            H -> <<(integer_to_binary(H))/binary, "h">>
        end,
        case Minutes of
            0 -> <<>>;
            M -> <<(integer_to_binary(M))/binary, "m">>
        end,
        case Secs of
            0 -> <<>>;
            S -> <<(integer_to_binary(S))/binary, "s">>
        end
    ],
    FilteredParts = [P || P <- Parts, P =/= <<>>],
    case FilteredParts of
        [] -> ~"0";
        _ -> iolist_to_binary(FilteredParts)
    end.

-spec maybe_encode_class(dns:class(), boolean()) -> binary().
maybe_encode_class(?DNS_CLASS_IN, true) ->
    <<>>;
maybe_encode_class(Class, _) ->
    encode_class(Class).

%% Encode DNS class
-spec encode_class(dns:class()) -> binary().
encode_class(Class) ->
    case dns_names:class_name(Class) of
        undefined -> <<"CLASS", (integer_to_binary(Class))/binary>>;
        Name -> Name
    end.

%% Encode DNS type
-spec encode_type(dns:type()) -> binary().
encode_type(Type) ->
    case dns_names:type_name(Type) of
        undefined -> <<"TYPE", (integer_to_binary(Type))/binary>>;
        Name -> Name
    end.

%% Make a domain name relative to origin
%% Returns relative atom if name equals origin, otherwise returns relative dname binary.
%% The part before the origin keeps the case it has.
-spec make_relative(dns:dname(), dns:dname()) -> dns:dname() | relative.
make_relative(Name, Origin) ->
    NameLower = dns_domain:to_lower(Name),
    OriginLower = dns_domain:to_lower(Origin),
    case NameLower =:= OriginLower of
        true ->
            relative;
        false ->
            %% Remove origin suffix
            SuffixLen = byte_size(OriginLower),
            NameLen = byte_size(NameLower),
            case NameLen > SuffixLen of
                true ->
                    %% The part before the origin and the dot that parts them, which
                    %% ends in a dot only when a backslash makes it part of the label
                    binary:part(Name, 0, NameLen - SuffixLen - 1);
                false ->
                    Name
            end
    end.

%% RFC1035§3.3: a <character-string> is at most 255 octets, so a longer string is
%% written as the strings of 255 octets and the rest that dns_encode writes it as,
%% which other software reads
-spec character_strings([binary()]) -> [binary()].
character_strings(Strings) ->
    lists:append([split_string(String) || String <- Strings]).

-spec split_string(binary()) -> [binary(), ...].
split_string(<<String:255/binary, Rest/binary>>) when Rest =/= <<>> ->
    [String | split_string(Rest)];
split_string(String) ->
    [String].

%% Encode quoted string (for TXT, SPF, etc.)
%% TXT records can have multiple strings
%% SPF records are same format as TXT
-spec encode_quoted_strings([binary()], binary()) -> binary().
encode_quoted_strings([], _Separator) ->
    <<>>;
encode_quoted_strings([String], _Separator) ->
    encode_quoted_string(String);
encode_quoted_strings([String | Strings], Separator) ->
    Acc = encode_quoted_string(String),
    encode_more_quoted_strings(Strings, Acc, Separator).

-spec encode_more_quoted_strings([binary()], binary(), binary()) -> binary().
encode_more_quoted_strings([], Acc, _Separator) ->
    Acc;
encode_more_quoted_strings([S | Strings], Acc, Separator) ->
    Acc1 = do_escape_string(S, <<Acc/binary, Separator/binary, $">>),
    encode_more_quoted_strings(Strings, <<Acc1/binary, $">>, Separator).

-spec encode_quoted_string(binary()) -> binary().
encode_quoted_string(Bin) ->
    %% Escape backslashes and quotes, then wrap in quotes
    Escaped = do_escape_string(Bin, <<$">>),
    <<Escaped/binary, $">>.

%% Escape string for zone file format
-spec do_escape_string(binary(), binary()) -> binary().
do_escape_string(<<>>, Acc) ->
    Acc;
do_escape_string(<<$\\, Rest/binary>>, Acc) ->
    do_escape_string(Rest, <<Acc/binary, "\\\\">>);
do_escape_string(<<$", Rest/binary>>, Acc) ->
    do_escape_string(Rest, <<Acc/binary, "\\\"">>);
do_escape_string(<<C, Rest/binary>>, Acc) when C >= 32, C =< 126 ->
    do_escape_string(Rest, <<Acc/binary, C>>);
do_escape_string(<<C, Rest/binary>>, Acc) ->
    %% Non-printable, use escape format that matches decoder expectations
    %% Note: Using binary format (not octal) to match existing decoder behavior
    Escape = list_to_binary(io_lib:format("\\~3..0B", [C])),
    do_escape_string(Rest, <<Acc/binary, Escape/binary>>).

%% ============================================================================
%% Zone-Level Encoding
%% ============================================================================

%% Sort zone records: SOA first, then NS, then others by name. Each owner is
%% lowercased once, for the sort to compare and the record to be written with,
%% rather than at each comparison.
-spec sort_zone_records([dns:rr()]) -> [{dns:dname(), dns:rr()}].
sort_zone_records(Records) ->
    %% Separate SOA, NS, and others
    {SOA, NS, Others} = lists:foldl(
        fun(#dns_rr{name = Name, type = Type} = RR, {SOAAcc, NSAcc, OthersAcc}) ->
            Entry = {dns_domain:to_lower(Name), RR},
            case Type of
                ?DNS_TYPE_SOA -> {[Entry | SOAAcc], NSAcc, OthersAcc};
                ?DNS_TYPE_NS -> {SOAAcc, [Entry | NSAcc], OthersAcc};
                _ -> {SOAAcc, NSAcc, [Entry | OthersAcc]}
            end
        end,
        {[], [], []},
        Records
    ),
    %% Sort NS and Others by name
    SortedNS = lists:sort(fun compare_by_name/2, NS),
    SortedOthers = lists:sort(fun compare_by_name/2, Others),
    %% Combine: SOA first, then NS, then others
    lists:reverse(SOA, SortedNS ++ SortedOthers).

%% Compare two records by their lowercased owners for sorting
-spec compare_by_name({dns:dname(), dns:rr()}, {dns:dname(), dns:rr()}) -> boolean().
compare_by_name({Name1, _}, {Name2, _}) ->
    Name1 < Name2.

%% Build zone file lines from sorted records
-spec build_zone_lines([{dns:dname(), dns:rr()}], dns:dname(), dns_zone:encode_options()) ->
    iodata().
build_zone_lines(Records, Origin, Opts) ->
    OriginLine = origin_line(Origin),
    TTLLine = ttl_line(Opts),
    %% Encode all records and append newlines
    RecordLines = [[encode_rr(LwrName, RR, Opts) | ~"\n"] || {LwrName, RR} <- Records],
    [OriginLine, TTLLine | RecordLines].

%% Add $ORIGIN directive if origin is set
-spec origin_line(dns:dname()) -> iodata().
origin_line(<<>>) ->
    [];
origin_line(Origin) ->
    [~"$ORIGIN ", escape_dname(ensure_fqdn(Origin)) | ~"\n"].

%% Add $TTL directive if default_ttl is set
ttl_line(Opts) ->
    %% Add $TTL directive if default_ttl is set
    DefaultTTL = maps:get(default_ttl, Opts, undefined),
    case DefaultTTL of
        undefined ->
            [];
        TTL when is_integer(TTL) ->
            TTLFormat = maps:get(ttl_format, Opts, ?DEFAULT_TTL_FORMAT),
            [~"$TTL ", encode_ttl(TTL, TTLFormat) | ~"\n"]
    end.

%% ============================================================================
%% RDATA Encoding
%% ============================================================================

%% Helper: Encode salt field (empty -> "-", otherwise hex)
-spec encode_salt_hex(binary()) -> binary().
encode_salt_hex(<<>>) ->
    ~"-";
encode_salt_hex(Salt) ->
    binary:encode_hex(Salt).

%% Helper: Encode an ILNP NodeID or Locator64 as four colon-separated groups of
%% four hex digits, never with the "::" shorthand (RFC 6742 §2.1, §2.3)
-spec encode_ilnp64(<<_:64>>) -> iolist().
encode_ilnp64(<<A:16, B:16, C:16, D:16>>) ->
    io_lib:format("~4.16.0b:~4.16.0b:~4.16.0b:~4.16.0b", [A, B, C, D]).

%% inet:ntoa/1 writes a non-zero second word of an fe80::/16 or ff02::/16 address
%% as a zone index, fe80:1:: as "fe80::%01", which is another address and isn't
%% zone file text. With a first word of 1, which it doesn't single out and which
%% is as non-zero, it puts the "::" in the same place, and the 1 is dropped.
-spec ntoa(inet:ip_address()) -> string().
ntoa({Word, B, C, D, E, F, G, H}) when Word =:= 16#fe80; Word =:= 16#ff02 ->
    [$1 | Rest] = inet:ntoa({1, B, C, D, E, F, G, H}),
    string:lowercase(integer_to_list(Word, 16)) ++ Rest;
ntoa(IP) ->
    "" ++ _ = inet:ntoa(IP).

%% Helper: a LOC latitude or longitude, thousandths of a second of arc, positive
%% to the north or the east
-spec loc_angle(integer(), binary(), binary()) -> binary().
loc_angle(Angle, Positive, Negative) ->
    {Hemisphere, Abs} =
        case Angle < 0 of
            true -> {Negative, -Angle};
            false -> {Positive, Angle}
        end,
    iolist_to_binary(
        io_lib:format("~b ~b ~b.~3..0b ~s", [
            Abs div 3600000, Abs div 60000 rem 60, Abs div 1000 rem 60, Abs rem 1000, Hemisphere
        ])
    ).

%% Helper: centimetres as metres
-spec loc_metres(integer()) -> binary().
loc_metres(Cm) when Cm < 0 ->
    <<$-, (loc_metres(-Cm))/binary>>;
loc_metres(Cm) ->
    iolist_to_binary(io_lib:format("~b.~2..0bm", [Cm div 100, Cm rem 100])).

%% Helper: the RDATA of an RRSIG, its times written with Time
-spec encode_rrsig(
    dns:rrdata_rrsig(), fun((dns:uint32()) -> binary()), dns:dname(), boolean(), binary()
) -> iodata().
encode_rrsig(
    #dns_rrdata_rrsig{
        type_covered = TypeCovered,
        alg = Alg,
        labels = Labels,
        original_ttl = OriginalTTL,
        expiration = Expiration,
        inception = Inception,
        keytag = KeyTag,
        signers_name = SignersName,
        signature = Signature
    },
    Time,
    Origin,
    RelativeNames,
    Separator
) ->
    join_rdata_fields(
        [
            encode_type(TypeCovered),
            integer_to_binary(Alg),
            integer_to_binary(Labels),
            integer_to_binary(OriginalTTL),
            Time(Expiration),
            Time(Inception),
            integer_to_binary(KeyTag),
            encode_dname(dns_domain:to_lower(SignersName), Origin, RelativeNames),
            base64:encode(Signature)
        ],
        Separator
    ).

%% Helper: a SIG time as RFC 2535 §7.2 writes it, YYYYMMDDHHmmSS, in UTC
-spec sig_time(dns:uint32()) -> binary().
sig_time(Seconds) ->
    {{Y, Mo, D}, {H, Mi, S}} = calendar:gregorian_seconds_to_datetime(
        Seconds + ?UNIX_EPOCH_GREGORIAN_SECONDS
    ),
    iolist_to_binary(io_lib:format("~4..0b~2..0b~2..0b~2..0b~2..0b~2..0b", [Y, Mo, D, H, Mi, S])).

%% Helper: an EUI-48 or EUI-64 address
-spec encode_eui(binary()) -> iodata().
encode_eui(Addr) ->
    lists:join(~"-", [binary:encode_hex(<<Octet>>, lowercase) || <<Octet>> <= Addr]).

-spec alphanumeric(binary()) -> boolean().
alphanumeric(<<>>) ->
    false;
alphanumeric(Bin) ->
    lists:all(
        fun(C) ->
            ($a =< C andalso C =< $z) orelse ($A =< C andalso C =< $Z) orelse
                ($0 =< C andalso C =< $9)
        end,
        binary_to_list(Bin)
    ).

%% Helper: Encode SVCB/HTTPS record with service parameters
-spec encode_svcb_record(
    dns:uint16(),
    dns:dname(),
    dns:svcb_svc_params(),
    dns:dname(),
    boolean(),
    binary()
) -> string().
encode_svcb_record(Priority, Target, Params, Origin, RelativeNames, Separator) ->
    PriorityBin = integer_to_binary(Priority),
    TargetStr = encode_dname(Target, Origin, RelativeNames),
    ParamsStr = dns_svcb_params:to_zone(Params, Separator, fun encode_quoted_string/1),
    case ParamsStr of
        <<>> -> join_rdata_fields([PriorityBin, TargetStr], Separator);
        _ -> join_rdata_fields([PriorityBin, TargetStr, ParamsStr], Separator)
    end.

%% Helper: Join RDATA fields with separator
-spec join_rdata_fields([iodata()], binary()) -> iodata().
join_rdata_fields(Fields, Separator) ->
    lists:join(Separator, Fields).

%% Helper: Convert DNSKEY/CDNSKEY public_key (algorithm-specific form) to wire-format binary.
%% Mirrors dns_encode logic: RSA uses [E, M], DSA uses list [P,Q,G,Y], others use binary.
-spec public_key_to_wire_binary(dns:uint8(), iodata() | [integer()]) -> binary().
public_key_to_wire_binary(Alg, [E, M]) when
    (Alg =:= ?DNS_ALG_RSASHA1 orelse Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse Alg =:= ?DNS_ALG_RSASHA512) andalso
        is_integer(E) andalso
        is_integer(M)
->
    dns_encode:encode_rsa_key(E, M);
public_key_to_wire_binary(Alg, PKM) when
    (Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA) andalso
        is_list(PKM)
->
    dns_encode:encode_dsa_key(PKM);
public_key_to_wire_binary(_Alg, PK) when is_binary(PK) ->
    PK.

%% Helper: Encode DS/CDS/DLV/DNSKEY/CDNSKEY record
%% Encodes 3 integer fields and a data field (hex or base64 encoded)
-spec encode_key_record(dns:uint16(), dns:uint8(), dns:uint8(), iodata(), hex | base64, binary()) ->
    iodata().
encode_key_record(Flags, Protocol, Alg, Data, Encoding, Separator) when is_binary(Data) ->
    Field1Bin = integer_to_binary(Flags),
    Field2Bin = integer_to_binary(Protocol),
    Field3Bin = integer_to_binary(Alg),
    EncodedData =
        case Encoding of
            hex -> binary:encode_hex(Data);
            base64 -> base64:encode(Data)
        end,
    join_rdata_fields([Field1Bin, Field2Bin, Field3Bin, EncodedData], Separator).

%% Assumes origin is always in lowercase. RFC4034§6.2 lowercases the names in the
%% RDATA of the types it lists when they are signed, and those are written in
%% lowercase. RFC3597§7 keeps later types off that list and RFC6840§5.1 takes NSEC
%% off it, so the names in NSEC, IPSECKEY, HIP, LP, AMTRELAY, DSYNC, SVCB and HTTPS
%% RDATA are signed and written in the case they have.
-spec encode_rdata(dns:type(), dns:rrdata(), dns:dname(), boolean(), binary()) -> iodata().
encode_rdata(?DNS_TYPE_A, #dns_rrdata_a{ip = IP}, _Origin, _RelativeNames, _Separator) ->
    "" ++ _ = inet:ntoa(IP);
encode_rdata(?DNS_TYPE_AAAA, #dns_rrdata_aaaa{ip = IP}, _Origin, _RelativeNames, _Separator) ->
    ntoa(IP);
encode_rdata(?DNS_TYPE_NS, #dns_rrdata_ns{dname = DName}, Origin, RelativeNames, _Separator) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(
    ?DNS_TYPE_CNAME,
    #dns_rrdata_cname{dname = DName},
    Origin,
    RelativeNames,
    _Separator
) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(?DNS_TYPE_PTR, #dns_rrdata_ptr{dname = DName}, Origin, RelativeNames, _Separator) ->
    encode_dname(DName, Origin, RelativeNames);
encode_rdata(
    ?DNS_TYPE_MX,
    #dns_rrdata_mx{preference = Pref, exchange = Exchange},
    Origin,
    RelativeNames,
    Separator
) ->
    PrefBin = integer_to_binary(Pref),
    ExchangeStr = encode_dname(dns_domain:to_lower(Exchange), Origin, RelativeNames),
    [PrefBin, Separator | ExchangeStr];
encode_rdata(?DNS_TYPE_TXT, #dns_rrdata_txt{txt = Strings}, _Origin, _RelativeNames, Separator) ->
    encode_quoted_strings(character_strings(Strings), Separator);
encode_rdata(?DNS_TYPE_SPF, #dns_rrdata_spf{spf = Strings}, _Origin, _RelativeNames, Separator) ->
    encode_quoted_strings(character_strings(Strings), Separator);
encode_rdata(
    ?DNS_TYPE_SOA,
    #dns_rrdata_soa{
        mname = MName,
        rname = RName,
        serial = Serial,
        refresh = Refresh,
        retry = Retry,
        expire = Expire,
        minimum = Minimum
    },
    Origin,
    RelativeNames,
    Separator
) ->
    MNameStr = encode_dname(dns_domain:to_lower(MName), Origin, RelativeNames),
    RNameStr = encode_dname(dns_domain:to_lower(RName), Origin, RelativeNames),
    SerialBin = integer_to_binary(Serial),
    RefreshBin = integer_to_binary(Refresh),
    RetryBin = integer_to_binary(Retry),
    ExpireBin = integer_to_binary(Expire),
    MinimumBin = integer_to_binary(Minimum),
    join_rdata_fields(
        [
            MNameStr, RNameStr, SerialBin, RefreshBin, RetryBin, ExpireBin, MinimumBin
        ],
        Separator
    );
encode_rdata(
    ?DNS_TYPE_SRV,
    #dns_rrdata_srv{
        priority = Priority,
        weight = Weight,
        port = Port,
        target = Target
    },
    Origin,
    RelativeNames,
    Separator
) ->
    PriorityBin = integer_to_binary(Priority),
    WeightBin = integer_to_binary(Weight),
    PortBin = integer_to_binary(Port),
    TargetStr = encode_dname(dns_domain:to_lower(Target), Origin, RelativeNames),
    join_rdata_fields([PriorityBin, WeightBin, PortBin, TargetStr], Separator);
encode_rdata(
    ?DNS_TYPE_CAA,
    #dns_rrdata_caa{
        flags = Flags,
        tag = Tag,
        value = Value
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    FlagsBin = integer_to_binary(Flags),
    %% RFC8659§4.1.1: a tag is letters and digits, which BIND reads only unquoted.
    %% One of other octets is quoted, as no other software reads it anyway.
    TagBin =
        case alphanumeric(Tag) of
            true -> Tag;
            false -> encode_quoted_string(Tag)
        end,
    ValueBin = encode_quoted_string(Value),
    join_rdata_fields([FlagsBin, TagBin, ValueBin], Separator);
encode_rdata(
    ?DNS_TYPE_NAPTR,
    #dns_rrdata_naptr{
        order = Order,
        preference = Preference,
        flags = Flags,
        services = Services,
        regexp = Regexp,
        replacement = Replacement
    },
    Origin,
    RelativeNames,
    Separator
) ->
    OrderBin = integer_to_binary(Order),
    PrefBin = integer_to_binary(Preference),
    FlagsBin = encode_quoted_string(Flags),
    ServicesBin = encode_quoted_string(Services),
    RegexpBin = encode_quoted_string(Regexp),
    ReplacementStr = encode_dname(dns_domain:to_lower(Replacement), Origin, RelativeNames),
    join_rdata_fields(
        [OrderBin, PrefBin, FlagsBin, ServicesBin, RegexpBin, ReplacementStr], Separator
    );
encode_rdata(
    ?DNS_TYPE_HINFO,
    #dns_rrdata_hinfo{
        cpu = CPU,
        os = OS
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    encode_quoted_strings([CPU, OS], Separator);
encode_rdata(
    ?DNS_TYPE_HIP,
    #dns_rrdata_hip{alg = Alg, hit = HIT, public_key = PublicKey, rendezvous_servers = Servers},
    Origin,
    RelativeNames,
    Separator
) ->
    %% RFC 8005 §6: the HIT in hex and the key in base64, each without whitespace
    ServerStrs = [encode_dname(S, Origin, RelativeNames) || S <- Servers],
    join_rdata_fields(
        [integer_to_binary(Alg), binary:encode_hex(HIT), base64:encode(PublicKey) | ServerStrs],
        Separator
    );
encode_rdata(
    ?DNS_TYPE_RP,
    #dns_rrdata_rp{
        mbox = Mbox,
        txt = Txt
    },
    Origin,
    RelativeNames,
    Separator
) ->
    MboxStr = encode_dname(dns_domain:to_lower(Mbox), Origin, RelativeNames),
    TxtStr = encode_dname(dns_domain:to_lower(Txt), Origin, RelativeNames),
    join_rdata_fields([MboxStr, TxtStr], Separator);
encode_rdata(
    ?DNS_TYPE_AFSDB,
    #dns_rrdata_afsdb{
        subtype = Subtype,
        hostname = Hostname
    },
    Origin,
    RelativeNames,
    Separator
) ->
    SubtypeBin = integer_to_binary(Subtype),
    HostnameStr = encode_dname(dns_domain:to_lower(Hostname), Origin, RelativeNames),
    join_rdata_fields([SubtypeBin, HostnameStr], Separator);
encode_rdata(
    ?DNS_TYPE_RT,
    #dns_rrdata_rt{
        preference = Preference,
        host = Host
    },
    Origin,
    RelativeNames,
    Separator
) ->
    PrefBin = integer_to_binary(Preference),
    HostStr = encode_dname(dns_domain:to_lower(Host), Origin, RelativeNames),
    join_rdata_fields([PrefBin, HostStr], Separator);
encode_rdata(
    ?DNS_TYPE_KX,
    #dns_rrdata_kx{
        preference = Preference,
        exchange = Exchange
    },
    Origin,
    RelativeNames,
    Separator
) ->
    PrefBin = integer_to_binary(Preference),
    ExchangeStr = encode_dname(dns_domain:to_lower(Exchange), Origin, RelativeNames),
    join_rdata_fields([PrefBin, ExchangeStr], Separator);
encode_rdata(
    ?DNS_TYPE_PX,
    #dns_rrdata_px{preference = Preference, map822 = Map822, mapx400 = MapX400},
    Origin,
    RelativeNames,
    Separator
) ->
    join_rdata_fields(
        [
            integer_to_binary(Preference),
            encode_dname(dns_domain:to_lower(Map822), Origin, RelativeNames),
            encode_dname(dns_domain:to_lower(MapX400), Origin, RelativeNames)
        ],
        Separator
    );
encode_rdata(
    ?DNS_TYPE_DNAME,
    #dns_rrdata_dname{dname = DName},
    Origin,
    RelativeNames,
    _Separator
) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(?DNS_TYPE_MB, #dns_rrdata_mb{madname = DName}, Origin, RelativeNames, _Separator) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(?DNS_TYPE_MG, #dns_rrdata_mg{madname = DName}, Origin, RelativeNames, _Separator) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(?DNS_TYPE_MR, #dns_rrdata_mr{newname = DName}, Origin, RelativeNames, _Separator) ->
    encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames);
encode_rdata(
    ?DNS_TYPE_MINFO,
    #dns_rrdata_minfo{
        rmailbx = RMailbx,
        emailbx = EmailBx
    },
    Origin,
    RelativeNames,
    Separator
) ->
    RMailbxStr = encode_dname(dns_domain:to_lower(RMailbx), Origin, RelativeNames),
    EmailBxStr = encode_dname(dns_domain:to_lower(EmailBx), Origin, RelativeNames),
    join_rdata_fields([RMailbxStr, EmailBxStr], Separator);
encode_rdata(
    ?DNS_TYPE_DS,
    #dns_rrdata_ds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    encode_key_record(KeyTag, Alg, DigestType, Digest, hex, Separator);
encode_rdata(
    ?DNS_TYPE_CDS,
    #dns_rrdata_cds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    encode_key_record(KeyTag, Alg, DigestType, Digest, hex, Separator);
encode_rdata(
    ?DNS_TYPE_DLV,
    #dns_rrdata_dlv{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    encode_key_record(KeyTag, Alg, DigestType, Digest, hex, Separator);
encode_rdata(
    ?DNS_TYPE_DNSKEY,
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    PublicKeyBin = public_key_to_wire_binary(Alg, PublicKey),
    encode_key_record(Flags, Protocol, Alg, PublicKeyBin, base64, Separator);
encode_rdata(
    ?DNS_TYPE_CDNSKEY,
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    PublicKeyBin = public_key_to_wire_binary(Alg, PublicKey),
    encode_key_record(Flags, Protocol, Alg, PublicKeyBin, base64, Separator);
encode_rdata(?DNS_TYPE_RRSIG, #dns_rrdata_rrsig{} = RRSig, Origin, RelativeNames, Separator) ->
    encode_rrsig(RRSig, fun integer_to_binary/1, Origin, RelativeNames, Separator);
encode_rdata(?DNS_TYPE_SIG, #dns_rrdata_sig{} = Sig, Origin, RelativeNames, Separator) ->
    %% RFC 2535 §7.2: as RRSIG's, which took it over field for field, but for the
    %% times, which RFC 2535 writes only as dates, and which BIND reads only so
    encode_rrsig(dns_encode:sig_to_rrsig(Sig), fun sig_time/1, Origin, RelativeNames, Separator);
encode_rdata(
    ?DNS_TYPE_NSEC,
    #dns_rrdata_nsec{
        next_dname = NextDName,
        types = Types
    },
    Origin,
    RelativeNames,
    Separator
) ->
    NextDNameStr = encode_dname(NextDName, Origin, RelativeNames),
    TypeStrs = [encode_type(T) || T <- Types],
    join_rdata_fields([NextDNameStr | TypeStrs], Separator);
encode_rdata(
    ?DNS_TYPE_NSEC3,
    #dns_rrdata_nsec3{
        hash_alg = HashAlg,
        opt_out = OptOut,
        iterations = Iterations,
        salt = Salt,
        hash = Hash,
        types = Types
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    HashAlgBin = integer_to_binary(HashAlg),
    FlagsBin = integer_to_binary(
        case OptOut of
            true -> 1;
            false -> 0
        end
    ),
    IterationsBin = integer_to_binary(Iterations),
    SaltHex = encode_salt_hex(Salt),
    %% RFC5155§3.3: base32hex without padding
    HashHex = base32:encode(Hash, [hex, nopad]),
    TypeBins = [encode_type(T) || T <- Types],
    join_rdata_fields(
        [HashAlgBin, FlagsBin, IterationsBin, SaltHex, HashHex | TypeBins], Separator
    );
encode_rdata(
    ?DNS_TYPE_NSEC3PARAM,
    #dns_rrdata_nsec3param{
        hash_alg = HashAlg,
        flags = Flags,
        iterations = Iterations,
        salt = Salt
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    HashAlgBin = integer_to_binary(HashAlg),
    FlagsBin = integer_to_binary(Flags),
    IterationsBin = integer_to_binary(Iterations),
    SaltHex = encode_salt_hex(Salt),
    join_rdata_fields([HashAlgBin, FlagsBin, IterationsBin, SaltHex], Separator);
encode_rdata(
    ?DNS_TYPE_SSHFP,
    #dns_rrdata_sshfp{
        alg = Alg,
        fp_type = FpType,
        fp = Fp
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    AlgBin = integer_to_binary(Alg),
    FpTypeBin = integer_to_binary(FpType),
    FpHex = binary:encode_hex(Fp),
    join_rdata_fields([AlgBin, FpTypeBin, FpHex], Separator);
encode_rdata(
    ?DNS_TYPE_TLSA,
    #dns_rrdata_tlsa{
        usage = Usage,
        selector = Selector,
        matching_type = MatchingType,
        certificate = Cert
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    UsageBin = integer_to_binary(Usage),
    SelectorBin = integer_to_binary(Selector),
    MatchingTypeBin = integer_to_binary(MatchingType),
    CertHex = binary:encode_hex(Cert),
    join_rdata_fields([UsageBin, SelectorBin, MatchingTypeBin, CertHex], Separator);
encode_rdata(
    ?DNS_TYPE_SMIMEA,
    #dns_rrdata_smimea{
        usage = Usage,
        selector = Selector,
        matching_type = MatchingType,
        certificate = Cert
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    %% Same format as TLSA
    UsageBin = integer_to_binary(Usage),
    SelectorBin = integer_to_binary(Selector),
    MatchingTypeBin = integer_to_binary(MatchingType),
    CertHex = binary:encode_hex(Cert),
    join_rdata_fields([UsageBin, SelectorBin, MatchingTypeBin, CertHex], Separator);
encode_rdata(
    ?DNS_TYPE_CERT,
    #dns_rrdata_cert{
        type = Type,
        keytag = KeyTag,
        alg = Alg,
        cert = Cert
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    TypeBin = integer_to_binary(Type),
    KeyTagBin = integer_to_binary(KeyTag),
    AlgBin = integer_to_binary(Alg),
    %% CERT can be base64 or hex, prefer base64
    CertBin = base64:encode(Cert),
    join_rdata_fields([TypeBin, KeyTagBin, AlgBin, CertBin], Separator);
encode_rdata(
    ?DNS_TYPE_DHCID,
    #dns_rrdata_dhcid{data = Data},
    _Origin,
    _RelativeNames,
    _Separator
) ->
    base64:encode(Data);
encode_rdata(
    ?DNS_TYPE_OPENPGPKEY, #dns_rrdata_openpgpkey{data = Data}, _Origin, _RelativeNames, _Separator
) ->
    base64:encode(Data);
encode_rdata(?DNS_TYPE_HHIT, #dns_rrdata_hhit{data = Data}, _Origin, _RelativeNames, _Separator) ->
    base64:encode(Data);
encode_rdata(?DNS_TYPE_BRID, #dns_rrdata_brid{data = Data}, _Origin, _RelativeNames, _Separator) ->
    base64:encode(Data);
encode_rdata(
    ?DNS_TYPE_WALLET, #dns_rrdata_wallet{data = Strings}, _Origin, _RelativeNames, Separator
) ->
    encode_quoted_strings(character_strings(Strings), Separator);
encode_rdata(
    ?DNS_TYPE_URI,
    #dns_rrdata_uri{
        priority = Priority,
        weight = Weight,
        target = Target
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    PriorityBin = integer_to_binary(Priority),
    WeightBin = integer_to_binary(Weight),
    %% RFC7553§4.4: the target in quotes
    join_rdata_fields([PriorityBin, WeightBin, encode_quoted_string(Target)], Separator);
encode_rdata(
    ?DNS_TYPE_RESINFO, #dns_rrdata_resinfo{data = Strings}, _Origin, _RelativeNames, Separator
) ->
    encode_quoted_strings(character_strings(Strings), Separator);
%% RFC7043§3.2, §4.2: the octets in hex, separated by hyphens
encode_rdata(
    ?DNS_TYPE_EUI48, #dns_rrdata_eui48{address = Addr}, _Origin, _RelativeNames, _Separator
) ->
    encode_eui(Addr);
encode_rdata(
    ?DNS_TYPE_EUI64, #dns_rrdata_eui64{address = Addr}, _Origin, _RelativeNames, _Separator
) ->
    encode_eui(Addr);
encode_rdata(
    ?DNS_TYPE_NID,
    #dns_rrdata_nid{preference = Pref, node_id = NodeID},
    _Origin,
    _RelativeNames,
    Separator
) ->
    join_rdata_fields([integer_to_binary(Pref), encode_ilnp64(NodeID)], Separator);
encode_rdata(
    ?DNS_TYPE_L32,
    #dns_rrdata_l32{preference = Pref, locator32 = Locator32},
    _Origin,
    _RelativeNames,
    Separator
) ->
    "" ++ _ = Locator32Str = inet:ntoa(Locator32),
    join_rdata_fields([integer_to_binary(Pref), Locator32Str], Separator);
encode_rdata(
    ?DNS_TYPE_L64,
    #dns_rrdata_l64{preference = Pref, locator64 = Locator64},
    _Origin,
    _RelativeNames,
    Separator
) ->
    join_rdata_fields([integer_to_binary(Pref), encode_ilnp64(Locator64)], Separator);
encode_rdata(
    ?DNS_TYPE_LP,
    #dns_rrdata_lp{preference = Pref, fqdn = FQDN},
    Origin,
    RelativeNames,
    Separator
) ->
    FQDNStr = encode_dname(FQDN, Origin, RelativeNames),
    join_rdata_fields([integer_to_binary(Pref), FQDNStr], Separator);
encode_rdata(
    ?DNS_TYPE_ZONEMD,
    #dns_rrdata_zonemd{
        serial = Serial,
        scheme = Scheme,
        algorithm = Algorithm,
        hash = Hash
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    SerialBin = integer_to_binary(Serial),
    SchemeBin = integer_to_binary(Scheme),
    AlgorithmBin = integer_to_binary(Algorithm),
    HashHex = binary:encode_hex(Hash),
    join_rdata_fields([SerialBin, SchemeBin, AlgorithmBin, HashHex], Separator);
encode_rdata(
    ?DNS_TYPE_CSYNC,
    #dns_rrdata_csync{
        soa_serial = SOASerial,
        flags = Flags,
        types = Types
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    SOASerialBin = integer_to_binary(SOASerial),
    FlagsBin = integer_to_binary(Flags),
    TypeStrs = [encode_type(T) || T <- Types],
    join_rdata_fields([SOASerialBin, FlagsBin | TypeStrs], Separator);
encode_rdata(
    ?DNS_TYPE_DSYNC,
    #dns_rrdata_dsync{
        rrtype = RRType,
        scheme = Scheme,
        port = Port,
        target = Target
    },
    Origin,
    RelativeNames,
    Separator
) ->
    RRTypeStr = encode_type(RRType),
    SchemeBin = integer_to_binary(Scheme),
    PortBin = integer_to_binary(Port),
    TargetStr = encode_dname(Target, Origin, RelativeNames),
    join_rdata_fields([RRTypeStr, SchemeBin, PortBin, TargetStr], Separator);
encode_rdata(
    ?DNS_TYPE_SVCB,
    #dns_rrdata_svcb{
        svc_priority = Priority,
        target_name = Target,
        svc_params = Params
    },
    Origin,
    RelativeNames,
    Separator
) ->
    encode_svcb_record(Priority, Target, Params, Origin, RelativeNames, Separator);
encode_rdata(
    ?DNS_TYPE_HTTPS,
    #dns_rrdata_https{
        svc_priority = Priority,
        target_name = Target,
        svc_params = Params
    },
    Origin,
    RelativeNames,
    Separator
) ->
    encode_svcb_record(Priority, Target, Params, Origin, RelativeNames, Separator);
%% RFC1876§3: latitude and longitude in degrees, minutes and seconds, altitude,
%% size and precisions in metres
encode_rdata(
    ?DNS_TYPE_LOC,
    #dns_rrdata_loc{
        size = Size,
        horiz = Horiz,
        vert = Vert,
        lat = Lat,
        lon = Lon,
        alt = Alt
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    join_rdata_fields(
        [
            loc_angle(Lat, ~"N", ~"S"),
            loc_angle(Lon, ~"E", ~"W"),
            loc_metres(Alt),
            loc_metres(Size),
            loc_metres(Horiz),
            loc_metres(Vert)
        ],
        Separator
    );
%% RFC4025§3.1: precedence, gateway type, algorithm, gateway, "." for none, and
%% the key in base64
encode_rdata(
    ?DNS_TYPE_IPSECKEY,
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Alg,
        gateway = Gateway,
        public_key = PublicKey
    },
    Origin,
    RelativeNames,
    Separator
) ->
    {GatewayType, GatewayStr} =
        case Gateway of
            <<>> -> {0, ~"."};
            {_, _, _, _} -> {1, "" ++ _ = inet:ntoa(Gateway)};
            {_, _, _, _, _, _, _, _} -> {2, ntoa(Gateway)};
            DName when is_binary(DName) -> {3, encode_dname(DName, Origin, RelativeNames)}
        end,
    join_rdata_fields(
        [
            integer_to_binary(Precedence),
            integer_to_binary(GatewayType),
            integer_to_binary(Alg),
            GatewayStr,
            base64:encode(PublicKey)
        ],
        Separator
    );
encode_rdata(
    ?DNS_TYPE_AMTRELAY,
    #dns_rrdata_amtrelay{
        precedence = Precedence,
        discovery_optional = DiscoveryOptional,
        relay_type = RelayType,
        relay = Relay
    },
    Origin,
    RelativeNames,
    Separator
) ->
    %% RFC 8777 §4.3.1: the relay is "." when there is none
    RelayStr =
        case {RelayType, Relay} of
            {0, _} -> ~".";
            {3, Name} when is_binary(Name) -> encode_dname(Name, Origin, RelativeNames);
            {_, IP} when is_tuple(IP) -> ntoa(IP)
        end,
    DBin =
        case DiscoveryOptional of
            true -> ~"1";
            false -> ~"0"
        end,
    join_rdata_fields(
        [integer_to_binary(Precedence), DBin, integer_to_binary(RelayType), RelayStr], Separator
    );
encode_rdata(
    ?DNS_TYPE_KEY,
    #dns_rrdata_key{
        type = Type,
        xt = XT,
        name_type = NameType,
        sig = Sig,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey
    },
    _Origin,
    _RelativeNames,
    Separator
) ->
    %% Construct flags: Type (2 bits) | Reserved (1 bit) | XT (1 bit) | Reserved (2 bits) |
    %%                  NameType (2 bits) | Reserved (4 bits) | Sig (4 bits)
    Flags = (Type bsl 14) bor (XT bsl 12) bor (NameType bsl 8) bor Sig,
    FlagsBin = integer_to_binary(Flags),
    ProtocolBin = integer_to_binary(Protocol),
    AlgBin = integer_to_binary(Alg),
    %% public_key can be iodata, convert to binary first. RFC2535§3.1.2: a key
    %% whose flags say there is none is left out, and so is any empty one.
    Key =
        case iolist_to_binary(PublicKey) of
            <<>> -> [];
            PublicKeyBin -> [base64:encode(PublicKeyBin)]
        end,
    join_rdata_fields([FlagsBin, ProtocolBin, AlgBin | Key], Separator);
encode_rdata(
    ?DNS_TYPE_NXT,
    #dns_rrdata_nxt{
        dname = DName,
        types = Types
    },
    Origin,
    RelativeNames,
    Separator
) ->
    DNameStr = encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames),
    TypeBins = [encode_type(T) || T <- Types],
    join_rdata_fields([DNameStr | TypeBins], Separator);
encode_rdata(
    ?DNS_TYPE_TSIG,
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = Fudge,
        mac = MAC,
        msgid = MsgID,
        err = Err,
        other = Other
    },
    Origin,
    RelativeNames,
    Separator
) ->
    AlgStr = encode_dname(dns_domain:to_lower(Alg), Origin, RelativeNames),
    TimeBin = integer_to_binary(Time),
    FudgeBin = integer_to_binary(Fudge),
    MACSize = byte_size(MAC),
    MACSizeBin = integer_to_binary(MACSize),
    MACB64 = base64:encode(MAC),
    MsgIDBin = integer_to_binary(MsgID),
    ErrBin = integer_to_binary(Err),
    OtherLen = byte_size(Other),
    OtherLenBin = integer_to_binary(OtherLen),
    OtherBin =
        case OtherLen of
            0 ->
                <<>>;
            _ ->
                base64:encode(Other)
        end,
    join_rdata_fields(
        [
            AlgStr,
            TimeBin,
            FudgeBin,
            MACSizeBin,
            MACB64,
            MsgIDBin,
            ErrBin,
            OtherLenBin,
            OtherBin
        ],
        Separator
    );
%% RFC 3597 fallback for unknown types
encode_rdata(_Type, Data, _Origin, _RelativeNames, Separator) when is_binary(Data) ->
    generic_rdata(Data, Separator).

%% RFC3597§5: \# with the length and the hex of the RDATA, for any type
-spec generic_rdata(binary(), binary()) -> iodata().
generic_rdata(<<>>, Separator) ->
    [~"\\#", Separator, ~"0"];
generic_rdata(Data, Separator) ->
    [~"\\#", Separator, integer_to_binary(byte_size(Data)), Separator, binary:encode_hex(Data)].

%% RDATA with a field its presentation format has no way to write empty is
%% written in RFC 3597's generic form, which reads back to the same octets
-spec rdata_text(dns:type(), dns:rrdata(), dns:dname(), boolean(), binary()) -> iodata().
rdata_text(Type, RData, Origin, RelativeNames, Separator) ->
    case has_unwritable_field(RData) of
        true -> generic_rdata(dns_encode:encode_rrdata(?DNS_CLASS_IN, RData), Separator);
        false -> encode_rdata(Type, RData, Origin, RelativeNames, Separator)
    end.

-spec has_unwritable_field(dns:rrdata()) -> boolean().
has_unwritable_field(#dns_rrdata_txt{txt = []}) -> true;
has_unwritable_field(#dns_rrdata_spf{spf = []}) -> true;
has_unwritable_field(#dns_rrdata_resinfo{data = []}) -> true;
has_unwritable_field(#dns_rrdata_wallet{data = []}) -> true;
has_unwritable_field(#dns_rrdata_ds{digest = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_cds{digest = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_dlv{digest = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_dnskey{public_key = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_cdnskey{public_key = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_rrsig{signature = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_sig{signature = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_sshfp{fp = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_tlsa{certificate = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_smimea{certificate = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_zonemd{hash = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_cert{cert = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_dhcid{data = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_openpgpkey{data = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_nsec3{hash = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_hip{hit = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_hip{public_key = <<>>}) -> true;
%% RFC4025§3.1 has no form for an IPSECKEY without a key, which BIND refuses in
%% any form, but which dnspython reads in this one
has_unwritable_field(#dns_rrdata_ipseckey{public_key = <<>>}) -> true;
has_unwritable_field(#dns_rrdata_loc{lat = Lat, lon = Lon}) -> not loc_writable(Lat, Lon);
has_unwritable_field(#dns_rrdata_svcb{svc_params = Params}) -> repeats_mandatory_key(Params);
has_unwritable_field(#dns_rrdata_https{svc_params = Params}) -> repeats_mandatory_key(Params);
has_unwritable_field(_RData) -> false.

%% RFC1876§3 writes latitudes up to 90 degrees and longitudes up to 180, which the
%% 32 bits of the wire format go past, and which the reader holds to, as BIND does
-spec loc_writable(integer(), integer()) -> boolean().
loc_writable(Lat, Lon) ->
    abs(Lat) =< 90 * 3600000 andalso abs(Lon) =< 180 * 3600000.

%% RFC9460§8 lists a key in mandatory once, which the reader holds to, and the wire
%% format can list it more than once
-spec repeats_mandatory_key(dns:svcb_svc_params()) -> boolean().
repeats_mandatory_key(#{?DNS_SVCB_PARAM_MANDATORY := Keys}) when is_list(Keys) ->
    length(lists:usort(Keys)) =/= length(Keys);
repeats_mandatory_key(_Params) ->
    false.
