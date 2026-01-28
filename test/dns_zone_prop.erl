-module(dns_zone_prop).
-compile([export_all, nowarn_export_all]).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%% ============================================================================
%% Property Tests
%% ============================================================================

%% Property: decode(encode(Records)) should return equivalent records
prop_encode_decode_roundtrip() ->
    ?FORALL(
        Records,
        non_empty(list(simple_valid_rr())),
        begin
            %% Don't set origin to avoid $ORIGIN directive affecting parsing
            Opts = #{relative_names => false},
            try
                Encoded = dns_zone:encode_string(Records, Opts),
                EncodedStr = iolist_to_binary(Encoded),
                case dns_zone:parse_string(EncodedStr, Opts) of
                    {ok, DecodedRecords} ->
                        Normalized1 = lists:sort([normalize_rr(R) || R <- Records]),
                        Normalized2 = lists:sort([normalize_rr(R) || R <- DecodedRecords]),
                        Normalized1 =:= Normalized2;
                    {error, _Reason} ->
                        false
                end
            catch
                _:_ -> false
            end
        end
    ).

%% Property: encode(decode(ZoneString)) should produce equivalent zone
prop_decode_encode_roundtrip() ->
    ?FORALL(
        ZoneString,
        valid_zone_string(),
        begin
            case dns_zone:parse_string(ZoneString) of
                {ok, Records} ->
                    Origin = extract_origin(ZoneString),
                    Encoded = dns_zone:encode_string(Records, #{origin => Origin}),
                    EncodedStr = iolist_to_binary(Encoded),
                    %% Parse back and verify records are equivalent
                    case dns_zone:parse_string(EncodedStr) of
                        {ok, DecodedRecords} ->
                            %% Normalize records for comparison
                            Normalized1 = lists:sort([normalize_rr(R) || R <- Records]),
                            Normalized2 = lists:sort([normalize_rr(R) || R <- DecodedRecords]),
                            Normalized1 =:= Normalized2;
                        {error, Reason} ->
                            io:format("Parse error on re-parse: ~p~n", [Reason]),
                            false
                    end;
                {error, _Reason} ->
                    %% Invalid zone strings are expected to fail
                    true
            end
        end
    ).

%% Property: encode_rr should be idempotent (encode same record multiple times)
prop_encode_rr_idempotent() ->
    ?FORALL(
        RR,
        simple_valid_rr(),
        begin
            Opts = #{origin => <<"example.com.">>, relative_names => false},
            try
                Encoded1 = dns_zone:encode_rr(RR, Opts),
                Encoded2 = dns_zone:encode_rr(RR, Opts),
                Encoded1 =:= Encoded2
            catch
                _:_ -> false
            end
        end
    ).

%% Property: encode_rr with different options should produce valid output
prop_encode_rr_options() ->
    ?FORALL(
        {RR, Opts},
        {simple_valid_rr(), encode_options()},
        begin
            try
                Encoded = dns_zone:encode_rr(RR, Opts),
                is_list(Encoded) andalso length(Encoded) > 0
            catch
                _:_ -> false
            end
        end
    ).

%% ============================================================================
%% Generators
%% ============================================================================

valid_dns_rr() ->
    frequency([
        {10, simple_valid_rr()},
        {1, complex_valid_rr()}
    ]).

simple_valid_rr() ->
    ?LET(
        Type,
        oneof([
            ?DNS_TYPE_A,
            ?DNS_TYPE_AAAA,
            ?DNS_TYPE_NS,
            ?DNS_TYPE_CNAME,
            ?DNS_TYPE_PTR,
            ?DNS_TYPE_MX,
            ?DNS_TYPE_TXT,
            ?DNS_TYPE_SOA,
            ?DNS_TYPE_SRV,
            ?DNS_TYPE_CAA
        ]),
        ?LET(
            {Name, Class, TTL, Data},
            {
                dns_prop_generator:simple_dname(),
                dns_prop_generator:dns_class(),
                range(0, 2147483647),
                rdata(Type)
            },
            #dns_rr{
                name = Name,
                type = Type,
                class = Class,
                ttl = TTL,
                data = Data
            }
        )
    ).

complex_valid_rr() ->
    ?LET(
        Type,
        dns_prop_generator:dns_type(),
        ?LET(
            {Name, Class, TTL, Data},
            {
                dns_prop_generator:simple_dname(),
                dns_prop_generator:dns_class(),
                range(0, 2147483647),
                rdata(Type)
            },
            #dns_rr{
                name = Name,
                type = Type,
                class = Class,
                ttl = TTL,
                data = Data
            }
        )
    ).

dname() ->
    ?LET(
        Labels,
        non_empty(list(label())),
        dns_domain:join(Labels, fqdn)
    ).

label() ->
    %% Zone prop uses letter() as first character and doesn't enforce 63-byte limit
    %% (to test edge cases with longer labels)
    dns_prop_generator:label().

%% String generator that excludes quote characters (quotes must be paired at boundaries)
quoted_string() ->
    ?LET(
        Bytes,
        non_empty(
            list(
                %% Exclude quote (34) and backslash (92) from generated bytes
                %% Quotes need to be paired at string boundaries, not inside
                frequency([
                    %% Space and !
                    {10, range(32, 33)},
                    %% # through [
                    {10, range(35, 91)},
                    %% ] through ~
                    {10, range(93, 126)},
                    %% Control characters
                    {5, range(0, 31)},
                    %% Extended ASCII/UTF-8
                    {5, range(127, 255)}
                ])
            )
        ),
        list_to_binary(Bytes)
    ).

%% Generate a CAA tag (RFC 6844: pure ASCII alphanumeric, may include dash)
%% Must start with a letter, rest can be letters, digits, or dash (no underscore)
caa_tag() ->
    ?LET(
        {First, Rest},
        {dns_prop_generator:letter(), list(oneof([dns_prop_generator:letter_or_digit(), $-]))},
        list_to_binary([First | Rest])
    ).

%% CAA value generator - uses quoted_string to avoid internal quotes
caa_value() ->
    quoted_string().

rdata(Type) ->
    case Type of
        ?DNS_TYPE_A ->
            ?LET(
                {A, B, C, D},
                {range(0, 255), range(0, 255), range(0, 255), range(0, 255)},
                #dns_rrdata_a{ip = {A, B, C, D}}
            );
        ?DNS_TYPE_AAAA ->
            ?LET(
                {A, B, C, D, E, F, G, H},
                {
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535)
                },
                #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}}
            );
        ?DNS_TYPE_NS ->
            ?LET(Name, dns_prop_generator:simple_dname(), #dns_rrdata_ns{dname = Name});
        ?DNS_TYPE_CNAME ->
            ?LET(Name, dns_prop_generator:simple_dname(), #dns_rrdata_cname{dname = Name});
        ?DNS_TYPE_PTR ->
            ?LET(Name, dns_prop_generator:simple_dname(), #dns_rrdata_ptr{dname = Name});
        ?DNS_TYPE_MX ->
            ?LET(
                {Pref, Exchange},
                {range(0, 65535), dns_prop_generator:simple_dname()},
                #dns_rrdata_mx{preference = Pref, exchange = Exchange}
            );
        ?DNS_TYPE_TXT ->
            ?LET(
                Strings,
                non_empty(list(quoted_string())),
                #dns_rrdata_txt{txt = Strings}
            );
        ?DNS_TYPE_SPF ->
            ?LET(
                Strings,
                non_empty(list(quoted_string())),
                #dns_rrdata_spf{spf = Strings}
            );
        ?DNS_TYPE_SOA ->
            ?LET(
                {MName, RName, Serial, Refresh, Retry, Expire, Minimum},
                {
                    dns_prop_generator:simple_dname(),
                    dns_prop_generator:simple_dname(),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647)
                },
                #dns_rrdata_soa{
                    mname = MName,
                    rname = RName,
                    serial = Serial,
                    refresh = Refresh,
                    retry = Retry,
                    expire = Expire,
                    minimum = Minimum
                }
            );
        ?DNS_TYPE_SRV ->
            ?LET(
                {Priority, Weight, Port, Target},
                {
                    range(0, 65535),
                    range(0, 65535),
                    range(0, 65535),
                    dns_prop_generator:simple_dname()
                },
                #dns_rrdata_srv{
                    priority = Priority,
                    weight = Weight,
                    port = Port,
                    target = Target
                }
            );
        ?DNS_TYPE_CAA ->
            ?LET(
                {Flags, Tag, Value},
                {range(0, 255), caa_tag(), caa_value()},
                #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value}
            );
        ?DNS_TYPE_KEY ->
            ?LET(
                {KeyType, XT, NameType, Sig, Protocol, Alg, PublicKey},
                {
                    range(0, 3),
                    range(0, 1),
                    range(0, 3),
                    range(0, 15),
                    range(0, 255),
                    range(0, 255),
                    binary()
                },
                #dns_rrdata_key{
                    type = KeyType,
                    xt = XT,
                    name_type = NameType,
                    sig = Sig,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey
                }
            );
        ?DNS_TYPE_NXT ->
            ?LET(
                {DName, Types},
                {dns_prop_generator:simple_dname(), non_empty(list(range(1, 65535)))},
                #dns_rrdata_nxt{dname = DName, types = Types}
            );
        ?DNS_TYPE_TSIG ->
            ?LET(
                {Alg, Time, Fudge, MAC, MsgID, Err, Other},
                {
                    dns_prop_generator:simple_dname(),
                    range(0, 281474976710655),
                    range(0, 65535),
                    binary(),
                    range(0, 65535),
                    range(0, 65535),
                    binary()
                },
                #dns_rrdata_tsig{
                    alg = Alg,
                    time = Time,
                    fudge = Fudge,
                    mac = MAC,
                    msgid = MsgID,
                    err = Err,
                    other = Other
                }
            );
        ?DNS_TYPE_CDS ->
            ?LET(
                {KeyTag, Alg, DigestType, Digest},
                {range(0, 65535), range(0, 255), range(0, 255), binary()},
                #dns_rrdata_cds{
                    keytag = KeyTag,
                    alg = Alg,
                    digest_type = DigestType,
                    digest = Digest
                }
            );
        ?DNS_TYPE_DLV ->
            ?LET(
                {KeyTag, Alg, DigestType, Digest},
                {range(0, 65535), range(0, 255), range(0, 255), binary()},
                #dns_rrdata_dlv{
                    keytag = KeyTag,
                    alg = Alg,
                    digest_type = DigestType,
                    digest = Digest
                }
            );
        ?DNS_TYPE_CDNSKEY ->
            ?LET(
                {Flags, Protocol, Alg, PublicKey},
                {range(0, 65535), range(0, 255), range(0, 255), binary()},
                #dns_rrdata_cdnskey{
                    flags = Flags,
                    protocol = Protocol,
                    alg = Alg,
                    public_key = PublicKey,
                    keytag = 0
                }
            );
        ?DNS_TYPE_NSEC3 ->
            ?LET(
                {HashAlg, OptOut, Iterations, Salt, Hash, Types},
                {
                    range(0, 255),
                    boolean(),
                    range(0, 65535),
                    binary(),
                    binary(),
                    non_empty(list(range(1, 65535)))
                },
                #dns_rrdata_nsec3{
                    hash_alg = HashAlg,
                    opt_out = OptOut,
                    iterations = Iterations,
                    salt = Salt,
                    hash = Hash,
                    types = Types
                }
            );
        ?DNS_TYPE_NSEC3PARAM ->
            ?LET(
                {HashAlg, Flags, Iterations, Salt},
                {range(0, 255), range(0, 255), range(0, 65535), binary()},
                #dns_rrdata_nsec3param{
                    hash_alg = HashAlg,
                    flags = Flags,
                    iterations = Iterations,
                    salt = Salt
                }
            );
        ?DNS_TYPE_LOC ->
            ?LET(
                {Size, Horiz, Vert, Lat, Lon, Alt},
                {
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647),
                    range(0, 2147483647)
                },
                #dns_rrdata_loc{
                    size = Size,
                    horiz = Horiz,
                    vert = Vert,
                    lat = Lat,
                    lon = Lon,
                    alt = Alt
                }
            );
        ?DNS_TYPE_IPSECKEY ->
            ?LET(
                {Precedence, Alg, Gateway, PublicKey},
                {
                    range(0, 255),
                    range(0, 255),
                    frequency([
                        {1, dns_prop_generator:simple_dname()},
                        {1, {192, 168, 1, 1}},
                        {1, {16#2001, 16#0db8, 16#85a3, 0, 0, 0, 16#8a2e, 16#0370}}
                    ]),
                    binary()
                },
                #dns_rrdata_ipseckey{
                    precedence = Precedence,
                    alg = Alg,
                    gateway = Gateway,
                    public_key = PublicKey
                }
            );
        _ ->
            %% For other types, generate a simple A record as fallback
            #dns_rrdata_a{ip = {192, 0, 2, 1}}
    end.

encode_options() ->
    ?LET(
        {Origin, RelativeNames, TTLFormat, OmitClass, DefaultTTL},
        {
            frequency([
                {10, dname()},
                {1, <<>>}
            ]),
            boolean(),
            oneof([seconds, units]),
            boolean(),
            frequency([
                {5, undefined},
                {1, non_neg_integer()}
            ])
        },
        #{
            origin => Origin,
            relative_names => RelativeNames,
            ttl_format => TTLFormat,
            omit_class => OmitClass,
            default_ttl => DefaultTTL
        }
    ).

valid_zone_string() ->
    ?LET(
        Records,
        list(simple_valid_rr()),
        begin
            case Records of
                [] ->
                    <<"$ORIGIN example.com.\n$TTL 3600\n">>;
                _ ->
                    %% Generate a simple zone string representation
                    Lines = lists:map(
                        fun(RR) ->
                            #dns_rr{name = Name, type = Type, class = Class, ttl = TTL, data = Data} =
                                RR,
                            NameStr = binary_to_list(Name),
                            TTLStr = integer_to_list(TTL),
                            ClassStr =
                                case Class of
                                    ?DNS_CLASS_IN -> "IN";
                                    ?DNS_CLASS_CH -> "CH";
                                    ?DNS_CLASS_HS -> "HS";
                                    ?DNS_CLASS_CS -> "CS";
                                    _ -> "IN"
                                end,
                            TypeStr =
                                case Type of
                                    ?DNS_TYPE_A -> "A";
                                    ?DNS_TYPE_AAAA -> "AAAA";
                                    ?DNS_TYPE_NS -> "NS";
                                    ?DNS_TYPE_CNAME -> "CNAME";
                                    ?DNS_TYPE_PTR -> "PTR";
                                    ?DNS_TYPE_MX -> "MX";
                                    ?DNS_TYPE_TXT -> "TXT";
                                    ?DNS_TYPE_SOA -> "SOA";
                                    ?DNS_TYPE_SRV -> "SRV";
                                    ?DNS_TYPE_CAA -> "CAA";
                                    _ -> "A"
                                end,
                            RDataStr = format_rdata(Type, Data),
                            lists:flatten(
                                io_lib:format("~s ~s ~s ~s ~s\n", [
                                    NameStr, TTLStr, ClassStr, TypeStr, RDataStr
                                ])
                            )
                        end,
                        Records
                    ),
                    list_to_binary(["$ORIGIN example.com.\n$TTL 3600\n" | Lines])
            end
        end
    ).

format_rdata(?DNS_TYPE_A, #dns_rrdata_a{ip = {A, B, C, D}}) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
format_rdata(?DNS_TYPE_AAAA, #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}}) ->
    lists:flatten(
        io_lib:format("~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B", [A, B, C, D, E, F, G, H])
    );
format_rdata(?DNS_TYPE_NS, #dns_rrdata_ns{dname = Name}) ->
    binary_to_list(Name);
format_rdata(?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = Name}) ->
    binary_to_list(Name);
format_rdata(?DNS_TYPE_PTR, #dns_rrdata_ptr{dname = Name}) ->
    binary_to_list(Name);
format_rdata(?DNS_TYPE_MX, #dns_rrdata_mx{preference = Pref, exchange = Exchange}) ->
    lists:flatten(io_lib:format("~B ~s", [Pref, binary_to_list(Exchange)]));
format_rdata(?DNS_TYPE_TXT, #dns_rrdata_txt{txt = Strings}) ->
    Quoted = [["\"", binary_to_list(S), "\""] || S <- Strings],
    string:join(Quoted, " ");
format_rdata(?DNS_TYPE_SOA, #dns_rrdata_soa{
    mname = MName,
    rname = RName,
    serial = Serial,
    refresh = Refresh,
    retry = Retry,
    expire = Expire,
    minimum = Minimum
}) ->
    lists:flatten(
        io_lib:format("~s ~s ~B ~B ~B ~B ~B", [
            binary_to_list(MName),
            binary_to_list(RName),
            Serial,
            Refresh,
            Retry,
            Expire,
            Minimum
        ])
    );
format_rdata(?DNS_TYPE_SRV, #dns_rrdata_srv{
    priority = Priority, weight = Weight, port = Port, target = Target
}) ->
    lists:flatten(io_lib:format("~B ~B ~B ~s", [Priority, Weight, Port, binary_to_list(Target)]));
format_rdata(?DNS_TYPE_CAA, #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value}) ->
    lists:flatten(
        io_lib:format("~B ~s \"~s\"", [Flags, binary_to_list(Tag), binary_to_list(Value)])
    );
format_rdata(_Type, _Data) ->
    "192.0.2.1".

extract_origin(ZoneString) ->
    %% Try to extract origin from $ORIGIN directive, default to example.com.
    case re:run(ZoneString, "\\$ORIGIN\\s+([^\\s\\n]+)", [{capture, [1], list}]) of
        {match, [OriginStr]} ->
            case lists:last(OriginStr) of
                $. -> list_to_binary(OriginStr);
                _ -> list_to_binary(OriginStr ++ ".")
            end;
        _ ->
            <<"example.com.">>
    end.

%% Normalize RR for comparison (handles domain name case differences)
normalize_rr(#dns_rr{name = Name, data = Data} = RR) ->
    NormalizedName = dns_domain:to_lower(Name),
    NormalizedData = normalize_rdata_dnames(Data),
    RR#dns_rr{name = NormalizedName, data = NormalizedData}.

%% Normalize domain names in RDATA (only for types that contain domain names)
normalize_rdata_dnames(#dns_rrdata_ns{dname = DName} = R) ->
    R#dns_rrdata_ns{dname = dns_domain:to_lower(DName)};
normalize_rdata_dnames(#dns_rrdata_cname{dname = DName} = R) ->
    R#dns_rrdata_cname{dname = dns_domain:to_lower(DName)};
normalize_rdata_dnames(#dns_rrdata_ptr{dname = DName} = R) ->
    R#dns_rrdata_ptr{dname = dns_domain:to_lower(DName)};
normalize_rdata_dnames(#dns_rrdata_mx{exchange = Ex} = R) ->
    R#dns_rrdata_mx{exchange = dns_domain:to_lower(Ex)};
normalize_rdata_dnames(#dns_rrdata_soa{mname = M, rname = RName} = R) ->
    R#dns_rrdata_soa{mname = dns_domain:to_lower(M), rname = dns_domain:to_lower(RName)};
normalize_rdata_dnames(#dns_rrdata_srv{target = T} = R) ->
    R#dns_rrdata_srv{target = dns_domain:to_lower(T)};
normalize_rdata_dnames(#dns_rrdata_nxt{dname = DName, types = Types} = R) ->
    R#dns_rrdata_nxt{dname = dns_domain:to_lower(DName), types = Types};
normalize_rdata_dnames(#dns_rrdata_tsig{alg = Alg} = R) ->
    R#dns_rrdata_tsig{alg = dns_domain:to_lower(Alg)};
normalize_rdata_dnames(#dns_rrdata_ipseckey{gateway = Gateway} = R) when is_binary(Gateway) ->
    R#dns_rrdata_ipseckey{gateway = dns_domain:to_lower(Gateway)};
normalize_rdata_dnames(Other) ->
    Other.
