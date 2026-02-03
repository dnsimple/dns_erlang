-module(dns_zone_encode).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-dialyzer(no_improper_lists).
-elvis([{elvis_style, dont_repeat_yourself, #{ignore => [{dns_zone_encode, encode_rdata}]}}]).

-export([encode_rdata/2, encode_rdata/3, encode_rr/2, encode_string/2, encode_file/3]).

-define(DEFAULT_ORIGIN, <<>>).
-define(DEFAULT_RELATIVE_NAMES, true).
-define(DEFAULT_TTL_FORMAT, seconds).
-define(DEFAULT_OMIT_CLASS, false).
-define(DEFAULT_SEPARATOR, ~" ").

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
encode_rr(#dns_rr{name = Name, type = Type, class = Class, ttl = TTL, data = Data}, Opts) ->
    LwrName = dns_domain:to_lower(Name),
    LwrOrigin = dns_domain:to_lower(maps:get(origin, Opts, ?DEFAULT_ORIGIN)),
    OmitClass = maps:get(omit_class, Opts, ?DEFAULT_OMIT_CLASS),
    TTLFormat = maps:get(ttl_format, Opts, ?DEFAULT_TTL_FORMAT),
    RelativeNames = maps:get(relative_names, Opts, ?DEFAULT_RELATIVE_NAMES),
    Separator = maps:get(separator, Opts, ?DEFAULT_SEPARATOR),
    OwnerName = encode_dname(LwrName, LwrOrigin, RelativeNames),
    EncodedTTL = encode_ttl(TTL, TTLFormat),
    EncodedClass = maybe_encode_class(Class, OmitClass),
    TypeBin = encode_type(Type),
    RDataStr = encode_rdata(Type, Data, LwrOrigin, RelativeNames, Separator),
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
    encode_rdata(Type, RData, <<>>, true, ?DEFAULT_SEPARATOR).

-spec encode_rdata(dns:type(), dns:rrdata(), dns_zone:encode_options()) -> iodata().
encode_rdata(Type, RData, Opts) ->
    Origin = dns_domain:to_lower(maps:get(origin, Opts, ?DEFAULT_ORIGIN)),
    RelativeNames = maps:get(relative_names, Opts, ?DEFAULT_RELATIVE_NAMES),
    Separator = maps:get(separator, Opts, ?DEFAULT_SEPARATOR),
    encode_rdata(Type, RData, Origin, RelativeNames, Separator).

%% ============================================================================
%% Helper Functions
%% ============================================================================

%% Encode domain name, optionally making it relative to origin
%% Assumes always receive input in lowercase
-spec encode_dname(dns:dname(), dns:dname(), boolean()) -> dns:dname().
encode_dname(Name, _Origin, false) ->
    Name;
encode_dname(Name, <<>>, true) ->
    Name;
encode_dname(Name, Origin, true) ->
    case is_subdomain(Name, Origin) of
        true ->
            %% Name is under origin, make it relative
            case make_relative(Name, Origin) of
                relative -> ~"@";
                RelativeName -> RelativeName
            end;
        false ->
            %% Name is not under origin or no origin, use absolute
            Name
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
                    %% Check there's a dot before the origin part
                    BeforeOrigin = binary:part(Name, 0, NameLen - OriginLen),
                    byte_size(BeforeOrigin) > 0 andalso binary:last(BeforeOrigin) =:= $.
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
%% Returns relative atom if name equals origin, otherwise returns relative dname binary
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
                    %% Extract the part before origin
                    BeforeOrigin = binary:part(NameLower, 0, NameLen - SuffixLen - 1),
                    %% Remove trailing dot if present
                    case byte_size(BeforeOrigin) > 0 andalso binary:last(BeforeOrigin) =:= $. of
                        true -> binary:part(BeforeOrigin, 0, byte_size(BeforeOrigin) - 1);
                        false -> BeforeOrigin
                    end;
                false ->
                    Name
            end
    end.

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

%% Sort zone records: SOA first, then NS, then others by name
-spec sort_zone_records([dns:rr()]) -> [dns:rr()].
sort_zone_records(Records) ->
    %% Separate SOA, NS, and others
    {SOA, NS, Others} = lists:foldl(
        fun
            (#dns_rr{type = ?DNS_TYPE_SOA} = RR, {SOAAcc, NSAcc, OthersAcc}) ->
                {[RR | SOAAcc], NSAcc, OthersAcc};
            (#dns_rr{type = ?DNS_TYPE_NS} = RR, {SOAAcc, NSAcc, OthersAcc}) ->
                {SOAAcc, [RR | NSAcc], OthersAcc};
            (RR, {SOAAcc, NSAcc, OthersAcc}) ->
                {SOAAcc, NSAcc, [RR | OthersAcc]}
        end,
        {[], [], []},
        Records
    ),
    %% Sort NS and Others by name
    SortedNS = lists:sort(fun compare_rr_by_name/2, NS),
    SortedOthers = lists:sort(fun compare_rr_by_name/2, Others),
    %% Combine: SOA first, then NS, then others
    lists:reverse(SOA, SortedNS ++ SortedOthers).

%% Compare two RRs by name for sorting
-spec compare_rr_by_name(dns:rr(), dns:rr()) -> boolean().
compare_rr_by_name(#dns_rr{name = Name1}, #dns_rr{name = Name2}) ->
    Name1Lower = dns_domain:to_lower(Name1),
    Name2Lower = dns_domain:to_lower(Name2),
    Name1Lower < Name2Lower.

%% Build zone file lines from sorted records
-spec build_zone_lines([dns:rr()], dns:dname(), dns_zone:encode_options()) -> iodata().
build_zone_lines(Records, Origin, Opts) ->
    OriginLine = origin_line(Origin),
    TTLLine = ttl_line(Opts),
    %% Encode all records and append newlines
    RecordLines = [[encode_rr(RR, Opts) | ~"\n"] || RR <- Records],
    [OriginLine, TTLLine | RecordLines].

%% Add $ORIGIN directive if origin is set
-spec origin_line(dns:dname()) -> iodata().
origin_line(<<>>) ->
    [];
origin_line(Origin) ->
    case binary:last(Origin) of
        $. -> [~"$ORIGIN ", Origin | ~"\n"];
        _ -> [~"$ORIGIN ", Origin, ~"." | ~"\n"]
    end.

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
    LwrTarget = dns_domain:to_lower(Target),
    LwrOrigin = dns_domain:to_lower(Origin),
    PriorityBin = integer_to_binary(Priority),
    TargetStr = encode_dname(LwrTarget, LwrOrigin, RelativeNames),
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
        Alg =:= ?DNS_ALG_RSASHA256 orelse Alg =:= ?DNS_ALG_RSASHA512),
    is_integer(E),
    is_integer(M)
->
    dns_encode:encode_rsa_key(E, M);
public_key_to_wire_binary(Alg, PKM) when
    (Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA),
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

%% Assumes origin is always in lowercase
-spec encode_rdata(dns:type(), dns:rrdata(), dns:dname(), boolean(), binary()) -> iodata().
encode_rdata(?DNS_TYPE_A, #dns_rrdata_a{ip = IP}, _Origin, _RelativeNames, _Separator) ->
    "" ++ _ = inet:ntoa(IP);
encode_rdata(?DNS_TYPE_AAAA, #dns_rrdata_aaaa{ip = IP}, _Origin, _RelativeNames, _Separator) ->
    "" ++ _ = inet:ntoa(IP);
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
    encode_quoted_strings(Strings, Separator);
encode_rdata(?DNS_TYPE_SPF, #dns_rrdata_spf{spf = Strings}, _Origin, _RelativeNames, Separator) ->
    encode_quoted_strings(Strings, Separator);
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
    %% CAA tag should always be quoted to ensure it's parsed as a string token
    %% (unquoted tags like "9" might be parsed as integers)
    TagBin = encode_quoted_string(Tag),
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
encode_rdata(
    ?DNS_TYPE_RRSIG,
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
    Origin,
    RelativeNames,
    Separator
) ->
    TypeCoveredBin = encode_type(TypeCovered),
    AlgBin = integer_to_binary(Alg),
    LabelsBin = integer_to_binary(Labels),
    OriginalTTLBin = integer_to_binary(OriginalTTL),
    ExpirationBin = integer_to_binary(Expiration),
    InceptionBin = integer_to_binary(Inception),
    KeyTagBin = integer_to_binary(KeyTag),
    SignersNameStr = encode_dname(dns_domain:to_lower(SignersName), Origin, RelativeNames),
    SignatureB64 = base64:encode(Signature),
    join_rdata_fields(
        [
            TypeCoveredBin,
            AlgBin,
            LabelsBin,
            OriginalTTLBin,
            ExpirationBin,
            InceptionBin,
            KeyTagBin,
            SignersNameStr,
            SignatureB64
        ],
        Separator
    );
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
    NextDNameStr = encode_dname(dns_domain:to_lower(NextDName), Origin, RelativeNames),
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
    HashHex = base32:encode(Hash, [hex]),
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
encode_rdata(
    ?DNS_TYPE_WALLET, #dns_rrdata_wallet{data = Data}, _Origin, _RelativeNames, _Separator
) ->
    base64:encode(Data);
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
    join_rdata_fields([PriorityBin, WeightBin, Target], Separator);
encode_rdata(
    ?DNS_TYPE_RESINFO, #dns_rrdata_resinfo{data = Strings}, _Origin, _RelativeNames, Separator
) ->
    encode_quoted_strings(Strings, Separator);
encode_rdata(
    ?DNS_TYPE_EUI48, #dns_rrdata_eui48{address = Addr}, _Origin, _RelativeNames, _Separator
) ->
    binary:encode_hex(Addr);
encode_rdata(
    ?DNS_TYPE_EUI64, #dns_rrdata_eui64{address = Addr}, _Origin, _RelativeNames, _Separator
) ->
    binary:encode_hex(Addr);
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
    TargetStr = encode_dname(dns_domain:to_lower(Target), Origin, RelativeNames),
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
%% LOC record (RFC 1876) - complex encoding
%% TODO: Implement proper LOC encoding with degrees/minutes/seconds format
%% Current implementation uses simplified integer format
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
    %% LOC format: lat lon alt size horiz_prec vert_prec
    %% Coordinates are in 1/1000th of a second
    %% Proper format should be: degrees minutes seconds.milliseconds N/S
    %%   degrees minutes seconds.milliseconds E/W altm altcm sizem sizecm horizm vertm
    %% For now, use simplified format
    SizeBin = integer_to_binary(Size),
    HorizBin = integer_to_binary(Horiz),
    VertBin = integer_to_binary(Vert),
    LatBin = integer_to_binary(Lat),
    LonBin = integer_to_binary(Lon),
    AltBin = integer_to_binary(Alt),
    join_rdata_fields([LatBin, LonBin, AltBin, SizeBin, HorizBin, VertBin], Separator);
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
    PrecedenceBin = integer_to_binary(Precedence),
    AlgBin = integer_to_binary(Alg),
    GatewayStr =
        case Gateway of
            {_, _, _, _} = IPv4 ->
                %% IPv4 address
                "" ++ _ = inet:ntoa(IPv4);
            {_, _, _, _, _, _, _, _} = IPv6 ->
                %% IPv6 address
                "" ++ _ = inet:ntoa(IPv6);
            DName when is_binary(DName) ->
                %% Domain name
                encode_dname(dns_domain:to_lower(DName), Origin, RelativeNames)
        end,
    PublicKeyHex = binary:encode_hex(PublicKey),
    join_rdata_fields([PrecedenceBin, AlgBin, GatewayStr, PublicKeyHex], Separator);
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
    %% public_key can be iodata, convert to binary first
    PublicKeyBin = iolist_to_binary(PublicKey),
    PublicKeyB64 = base64:encode(PublicKeyBin),
    join_rdata_fields([FlagsBin, ProtocolBin, AlgBin, PublicKeyB64], Separator);
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
    Length = byte_size(Data),
    Hex = binary:encode_hex(Data),
    LengthBin = integer_to_binary(Length),
    [~"\\#", Separator, LengthBin, Separator, Hex].
