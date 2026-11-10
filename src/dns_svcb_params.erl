-module(dns_svcb_params).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-type escape_callback() :: fun((binary()) -> binary()).

-export_type([escape_callback/0]).

-export([to_wire/1, from_wire/1]).
-export([to_json/1, from_json/1]).
-export([to_zone/3, from_zone/1]).

-spec to_wire(dns:svcb_svc_params()) -> binary().
to_wire(SvcParams) ->
    SortedParams = lists:sort(maps:to_list(SvcParams)),
    to_wire(SortedParams, <<>>).

to_wire([], Acc) ->
    Acc;
to_wire([{Key, Value} | Rest], Acc) ->
    ValueBin =
        case Key of
            ?DNS_SVCB_PARAM_MANDATORY when is_list(Value) ->
                SortedKeys = lists:sort(Value),
                <<<<K:16>> || K <- SortedKeys>>;
            ?DNS_SVCB_PARAM_ALPN when is_list(Value) ->
                encode_alpn_list(wire, Value);
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN when Value =:= none ->
                <<>>;
            ?DNS_SVCB_PARAM_PORT when is_integer(Value) ->
                <<Value:16/integer>>;
            ?DNS_SVCB_PARAM_ECH when is_binary(Value) ->
                Value;
            ?DNS_SVCB_PARAM_IPV4HINT when is_list(Value) ->
                <<<<A, B, C, D>> || {A, B, C, D} <- Value>>;
            ?DNS_SVCB_PARAM_IPV6HINT when is_list(Value) ->
                <<
                    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
                 || {A, B, C, D, E, F, G, H} <- Value
                >>;
            Key when is_integer(Key) ->
                encode_unknown_key(wire, Key, Value, undefined)
        end,
    Acc1 = <<Acc/binary, Key:16/integer, (byte_size(ValueBin)):16/integer, ValueBin/binary>>,
    to_wire(Rest, Acc1).

-spec from_wire(binary()) -> dns:svcb_svc_params().
from_wire(Bin) ->
    from_wire(Bin, #{}, -1).

from_wire(<<>>, SvcParams, _PrevKey) ->
    validate_mandatory_params(wire, SvcParams);
from_wire(<<Key:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams, K0) when K0 < Key ->
    NewSvcParams =
        case Key of
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN when Len =:= 0 ->
                SvcParams#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none};
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN ->
                error({svcb_bad_no_default_alpn, Len});
            ?DNS_SVCB_PARAM_MANDATORY ->
                Value = [K || <<K:16>> <= exact_multiple(mandatory, 2, ValueBin)],
                SvcParams#{?DNS_SVCB_PARAM_MANDATORY => Value};
            ?DNS_SVCB_PARAM_ALPN ->
                Value = decode_alpn_list(wire, ValueBin),
                SvcParams#{?DNS_SVCB_PARAM_ALPN => Value};
            ?DNS_SVCB_PARAM_PORT when Len =:= 2 ->
                <<Port:16/integer>> = ValueBin,
                SvcParams#{?DNS_SVCB_PARAM_PORT => Port};
            ?DNS_SVCB_PARAM_ECH ->
                SvcParams#{?DNS_SVCB_PARAM_ECH => ValueBin};
            ?DNS_SVCB_PARAM_IPV4HINT ->
                Value = [
                    {A, B, C, D}
                 || <<A, B, C, D>> <= exact_multiple(ipv4hint, 4, ValueBin)
                ],
                SvcParams#{?DNS_SVCB_PARAM_IPV4HINT => Value};
            ?DNS_SVCB_PARAM_IPV6HINT ->
                Value = [
                    {A, B, C, D, E, F, G, H}
                 || <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> <=
                        exact_multiple(ipv6hint, 16, ValueBin)
                ],
                SvcParams#{?DNS_SVCB_PARAM_IPV6HINT => Value};
            _ when Len =:= 0 ->
                SvcParams#{Key => none};
            _ ->
                SvcParams#{Key => ValueBin}
        end,
    from_wire(Rest, NewSvcParams, Key);
from_wire(<<Key:16, Len:16, _:Len/binary, _/binary>>, _, K0) when Key =< K0 ->
    error({svcb_key_ordering_error, {prev_key, K0}, {current_key, Key}}).

%% RFC9460 §7.4 and §8: ipv4hint and ipv6hint are each a sequence of fixed-width elements
-spec exact_multiple(atom(), pos_integer(), binary()) -> binary().
exact_multiple(_Param, Width, Bin) when byte_size(Bin) rem Width =:= 0 ->
    Bin;
exact_multiple(Param, Width, Bin) ->
    error({svcb_truncated_param, Param, {expected_multiple_of, Width}, byte_size(Bin)}).

-spec to_json(dns:svcb_svc_params()) -> json:encode_value().
to_json(SvcParams) ->
    maps:from_list([to_json_pair(K, V) || K := V <- SvcParams]).

-spec to_json_pair(dynamic(), dynamic()) -> {binary(), dynamic()}.
to_json_pair(K, V) ->
    Name = svcb_param_name(K),
    {Name, encode_value_to_json(K, V)}.

-spec from_json(#{binary() => json:decode_value()}) -> dns:svcb_svc_params().
from_json(JsonMap) ->
    SvcParams = parse_svcb_params_from_json(maps:to_list(JsonMap), #{}),
    validate_mandatory_params(json, SvcParams).

-spec parse_svcb_params_from_json([{binary(), term()}], dns:svcb_svc_params()) ->
    dns:svcb_svc_params().
parse_svcb_params_from_json([], Acc) ->
    Acc;
parse_svcb_params_from_json([{Key, Value} | Rest], Acc) ->
    ParamKey = dns_names:name_svcb_param(Key),
    NewAcc =
        case ParamKey of
            ?DNS_SVCB_PARAM_MANDATORY when is_list(Value) ->
                KeyNums = [dns_names:name_svcb_param(K) || K <- Value],
                Acc#{ParamKey => KeyNums};
            ?DNS_SVCB_PARAM_ALPN when is_list(Value) ->
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN when Value =:= null ->
                Acc#{ParamKey => none};
            ?DNS_SVCB_PARAM_PORT when is_integer(Value) ->
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_ECH when is_binary(Value) ->
                Acc#{ParamKey => decode_ech_from_json(Value)};
            ?DNS_SVCB_PARAM_IPV4HINT when is_list(Value) ->
                IPs = [parse_ipv4_for_json(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            ?DNS_SVCB_PARAM_IPV6HINT when is_list(Value) ->
                IPs = [parse_ipv6_for_json(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            %% Unknown keys (key >= 7) stored as-is; key0-key6 with wrong value type are invalid
            NNNN when is_integer(NNNN), 7 =< NNNN, null =:= Value ->
                Acc#{NNNN => none};
            NNNN when is_integer(NNNN), 7 =< NNNN, is_binary(Value) ->
                Acc#{NNNN => Value};
            undefined ->
                Acc;
            _ ->
                error({svcb_param_invalid_value, ParamKey, Value})
        end,
    parse_svcb_params_from_json(Rest, NewAcc).

%% RFC9460 Appendix A: the SvcParams of a zone file, each a key and its value, the
%% value's <character-string> already decoded, or none for a key alone
-spec from_zone([{binary(), binary() | none}]) -> {ok, dns:svcb_svc_params()} | {error, term()}.
from_zone(Params) ->
    try lists:foldl(fun from_zone_param/2, #{}, Params) of
        SvcParams -> validate_mandatory_params(zone, SvcParams)
    catch
        error:{?MODULE, Reason} -> {error, Reason}
    end.

-spec from_zone_param({binary(), binary() | none}, dns:svcb_svc_params()) ->
    dns:svcb_svc_params().
from_zone_param({Name, Value}, Acc) ->
    Key = zone_key(Name, invalid_svcparam_format),
    %% RFC9460§2.1: SvcParamKeys SHALL NOT be repeated
    maps:is_key(Key, Acc) andalso zone_error({duplicate_svcparam_key, Name}),
    Parsed =
        case Name of
            ~"tls-supported-groups" -> tls_supported_groups(Value);
            _ -> zone_value(Key, Value)
        end,
    Acc#{Key => Parsed}.

%% RFC9460§14.3.2's names, and those of keys 7, 8 and 9: dohpath (RFC9461),
%% ohttp (RFC9540) and tls-supported-groups (draft-ietf-tls-key-share-prediction)
-spec zone_key(binary(), atom()) -> dns:uint16().
zone_key(~"dohpath", _Error) ->
    7;
zone_key(~"ohttp", _Error) ->
    8;
zone_key(~"tls-supported-groups", _Error) ->
    9;
zone_key(Name, Error) ->
    case dns_names:name_svcb_param(Name) of
        undefined -> zone_error({Error, Name});
        Key -> Key
    end.

-spec zone_value(dns:uint16(), binary() | none) -> dynamic().
%% RFC9460§8: keys in mandatory MUST NOT appear more than once, by name or number
zone_value(?DNS_SVCB_PARAM_MANDATORY, Value) when is_binary(Value) ->
    Keys = [
        zone_key(Name, invalid_mandatory_key)
     || Name <- zone_list(?DNS_SVCB_PARAM_MANDATORY, Value)
    ],
    length(lists:usort(Keys)) =:= length(Keys) orelse
        zone_error({duplicate_mandatory_key, Value}),
    Keys;
zone_value(?DNS_SVCB_PARAM_ALPN, <<>>) ->
    [];
zone_value(?DNS_SVCB_PARAM_ALPN, Value) when is_binary(Value) ->
    Ids = alpn_list(Value, <<>>, []),
    lists:member(<<>>, Ids) andalso
        zone_error({svcb_param_invalid_value, ?DNS_SVCB_PARAM_ALPN, Value}),
    Ids;
zone_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none) ->
    none;
zone_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, _Value) ->
    zone_error({svcb_param_no_value_allowed, no_default_alpn});
zone_value(?DNS_SVCB_PARAM_PORT, <<C, _/binary>> = Value) when $0 =< C, C =< $9 ->
    try binary_to_integer(Value) of
        Port when Port =< 65535 -> Port;
        _ -> zone_error({invalid_port, Value})
    catch
        error:badarg -> zone_error({invalid_port, Value})
    end;
zone_value(?DNS_SVCB_PARAM_PORT, Value) when is_binary(Value) ->
    zone_error({invalid_port, Value});
zone_value(?DNS_SVCB_PARAM_IPV4HINT, Value) when is_binary(Value) ->
    [
        zone_ip(inet:parse_ipv4strict_address(binary_to_list(IP)), invalid_ipv4_in_hint, IP)
     || IP <- zone_list(?DNS_SVCB_PARAM_IPV4HINT, Value)
    ];
zone_value(?DNS_SVCB_PARAM_ECH, Value) when is_binary(Value) ->
    case safe_base64_decode(Value) of
        error -> zone_error({invalid_svcparam_format, Value});
        ECHConfig -> ECHConfig
    end;
zone_value(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_binary(Value) ->
    [zone_ipv6(IP) || IP <- zone_list(?DNS_SVCB_PARAM_IPV6HINT, Value)];
zone_value(Key, none) when 7 =< Key ->
    none;
zone_value(Key, <<>>) when 7 =< Key ->
    none;
zone_value(Key, Value) when 7 =< Key, is_binary(Value) ->
    Value;
zone_value(Key, Value) ->
    zone_error({svcb_param_invalid_value, Key, Value}).

%% draft-ietf-tls-key-share-prediction-05§3.1: a non-empty list of decimal numbers
%% up to 65535, none twice, kept as its wire format, 2 octets each, as the values
%% of the other keys past 6 are. Written as key9, which is how the writer writes
%% it, the value is those octets (RFC9460§2.1).
-spec tls_supported_groups(binary() | none) -> binary().
tls_supported_groups(Value) when is_binary(Value), Value =/= <<>> ->
    Groups = [tls_group(Item, Value) || Item <- zone_list(9, Value)],
    length(lists:usort(Groups)) =:= length(Groups) orelse
        zone_error({svcb_param_invalid_value, 9, Value}),
    <<<<Group:16>> || Group <- Groups>>;
tls_supported_groups(Value) ->
    zone_error({svcb_param_invalid_value, 9, Value}).

%% A group's number, in digits, past any leading zeros
-spec tls_group(binary(), binary()) -> dns:uint16().
tls_group(Item, Value) ->
    Significant = skip_zeros(Item),
    case [C || <<C>> <= Item, C < $0 orelse C > $9] of
        [] when Significant =:= <<>> ->
            0;
        [] when byte_size(Significant) =< 5 ->
            case binary_to_integer(Significant) of
                Group when Group =< 65535 -> Group;
                _ -> zone_error({svcb_param_invalid_value, 9, Value})
            end;
        _ ->
            zone_error({svcb_param_invalid_value, 9, Value})
    end.

-spec skip_zeros(binary()) -> binary().
skip_zeros(<<$0, Rest/binary>>) -> skip_zeros(Rest);
skip_zeros(Rest) -> Rest.

%% An IPv6 address, without the "%" and zone index that inet would take and drop
-spec zone_ipv6(binary()) -> inet:ip6_address().
zone_ipv6(IP) ->
    case binary:match(IP, ~"%") of
        nomatch ->
            zone_ip(inet:parse_ipv6strict_address(binary_to_list(IP)), invalid_ipv6_in_hint, IP);
        _ ->
            zone_error({invalid_ipv6_in_hint, IP, einval})
    end.

-spec zone_ip({ok, IP} | {error, term()}, atom(), binary()) -> IP.
zone_ip({ok, IP}, _Error, _Text) ->
    IP;
zone_ip({error, Reason}, Error, Text) ->
    zone_error({Error, Text, Reason}).

%% RFC9460§7.1.1, §7.3, §8: a comma-separated list, none of whose items is empty
%% or holds a comma. An empty value is an empty list, as the parser read it.
-spec zone_list(dns:uint16(), binary()) -> [binary()].
zone_list(_Key, <<>>) ->
    [];
zone_list(Key, Value) ->
    Items = binary:split(Value, ~",", [global]),
    lists:member(<<>>, Items) andalso zone_error({svcb_param_invalid_value, Key, Value}),
    Items.

%% RFC9460 Appendix A.1: after the <character-string> is decoded, "\," is a comma
%% within an item and "\\" a backslash
-spec alpn_list(binary(), binary(), [binary()]) -> [binary()].
alpn_list(<<$\\, C, Rest/binary>>, Item, Acc) ->
    alpn_list(Rest, <<Item/binary, C>>, Acc);
alpn_list(<<$,, Rest/binary>>, Item, Acc) ->
    alpn_list(Rest, <<>>, [Item | Acc]);
alpn_list(<<C, Rest/binary>>, Item, Acc) ->
    alpn_list(Rest, <<Item/binary, C>>, Acc);
alpn_list(<<>>, Item, Acc) ->
    lists:reverse([Item | Acc]).

-spec zone_error(term()) -> no_return().
zone_error(Reason) ->
    erlang:error({?MODULE, Reason}).

%% Encode SVCB/HTTPS service parameters to zone file format
%% Takes params, separator, and an escape function for unknown key values
-spec to_zone(dns:svcb_svc_params(), binary(), escape_callback()) -> iodata().
to_zone(Params, _Separator, _EscapeFun) when map_size(Params) =:= 0 ->
    <<>>;
to_zone(Params, Separator, EscapeFun) ->
    ParamList = to_zone_list(Params, [], EscapeFun),
    join_with_separator(Separator, ParamList).

-spec to_zone_list(dns:svcb_svc_params(), [iodata()], escape_callback()) -> [iodata()].
to_zone_list(SvcParams, Acc, EscapeFun) ->
    SortedParams = lists:sort(maps:to_list(SvcParams)),
    lists:foldr(
        fun
            ({?DNS_SVCB_PARAM_MANDATORY, Keys}, Acc0) ->
                KeyNames = [svcb_param_name(K) || K <- Keys],
                [[~"mandatory=\"", join_with_separator(~",", KeyNames), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_ALPN, Protocols}, Acc0) ->
                AlpnStr = iolist_to_binary(encode_alpn_list(zone, Protocols)),
                [[~"alpn=", EscapeFun(AlpnStr)] | Acc0];
            ({?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none}, Acc0) ->
                [~"no-default-alpn" | Acc0];
            ({?DNS_SVCB_PARAM_PORT, Port}, Acc0) ->
                [[~"port=\"", integer_to_binary(Port), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_IPV4HINT, IPs}, Acc0) ->
                IPStrs = [inet:ntoa(IP) || IP <- IPs],
                [[~"ipv4hint=\"", join_with_separator(~",", IPStrs), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_IPV6HINT, IPs}, Acc0) ->
                IPStrs = [dns_zone_encode:ntoa(IP) || IP <- IPs],
                [[~"ipv6hint=\"", join_with_separator(~",", IPStrs), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_ECH, ECHConfig}, Acc0) ->
                [[~"ech=\"", base64:encode(ECHConfig), ~"\""] | Acc0];
            ({KeyNum, Value}, Acc0) when is_integer(KeyNum) ->
                [encode_unknown_key(zone, KeyNum, Value, EscapeFun) | Acc0]
        end,
        Acc,
        SortedParams
    ).

%% Validate mandatory params for wire format (throws on error)
-spec validate_mandatory_params
    (wire, dns:svcb_svc_params()) -> dns:svcb_svc_params();
    (zone, dns:svcb_svc_params()) -> {ok, dns:svcb_svc_params()} | {error, term()};
    (json, dns:svcb_svc_params()) -> dns:svcb_svc_params().
validate_mandatory_params(wire, SvcParams) ->
    case validate_mandatory_params_core(SvcParams) of
        {error, Reason} ->
            error({svcb_mandatory_validation_error, Reason});
        SvcParams ->
            SvcParams
    end;
validate_mandatory_params(zone, SvcParams) ->
    case validate_mandatory_params_core(SvcParams) of
        {error, Error} ->
            {error, Error};
        SvcParams ->
            {ok, SvcParams}
    end;
validate_mandatory_params(json, SvcParams) ->
    case validate_mandatory_params_core(SvcParams) of
        {error, Error} ->
            error({svcb_mandatory_validation_error, Error});
        SvcParams ->
            SvcParams
    end.

%% Core validation logic - returns validation result without throwing
-spec validate_mandatory_params_core(dns:svcb_svc_params()) ->
    dns:svcb_svc_params() | {error, {atom(), dynamic()}}.
validate_mandatory_params_core(#{?DNS_SVCB_PARAM_MANDATORY := MandatoryKeys} = SvcParams) ->
    %% Check that mandatory doesn't reference itself (key 0)
    case lists:member(?DNS_SVCB_PARAM_MANDATORY, MandatoryKeys) of
        true ->
            {error, {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY}};
        false ->
            %% Check that all mandatory keys exist in SvcParams
            MissingKeys = [K || K <- MandatoryKeys, not maps:is_key(K, SvcParams)],
            case MissingKeys of
                [] ->
                    SvcParams;
                _ ->
                    {error, {missing_mandatory_keys, MissingKeys}}
            end
    end;
validate_mandatory_params_core(SvcParams) ->
    SvcParams.

-spec encode_value_to_json(dns:uint16(), dynamic()) -> term().
encode_value_to_json(?DNS_SVCB_PARAM_MANDATORY, Value) when is_list(Value) ->
    [svcb_param_name(K) || K <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_ALPN, Value) when is_list(Value) ->
    Value;
encode_value_to_json(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none) ->
    null;
encode_value_to_json(?DNS_SVCB_PARAM_PORT, Value) when is_integer(Value) ->
    Value;
encode_value_to_json(?DNS_SVCB_PARAM_IPV4HINT, Value) when is_list(Value) ->
    [list_to_binary(inet:ntoa(V)) || V <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_ECH, Value) when is_binary(Value) ->
    base64:encode(Value);
encode_value_to_json(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_list(Value) ->
    [list_to_binary(dns_zone_encode:ntoa(V)) || V <- Value];
encode_value_to_json(Key, none) when is_integer(Key) ->
    null;
encode_value_to_json(Key, Value) when is_integer(Key), is_binary(Value) ->
    Value;
encode_value_to_json(Key, Value) ->
    error({svcb_param_invalid_value, Key, Value}).

%% ============================================================================
%% Helpers
%% ============================================================================

%% An ECHConfigList is arbitrary octets, which a JSON string cannot carry, so
%% JSON holds it in base64, as the zone file presentation format does.
-spec decode_ech_from_json(binary()) -> binary() | no_return().
decode_ech_from_json(Value) ->
    case safe_base64_decode(Value) of
        error ->
            error({svcb_param_invalid_value, ?DNS_SVCB_PARAM_ECH, Value});
        ECHConfig ->
            ECHConfig
    end.

-spec safe_base64_decode(string() | binary()) -> binary() | error.
safe_base64_decode(Value) ->
    try
        base64:decode(Value)
    catch
        error:_ ->
            error
    end.

-spec parse_ipv4_for_json(binary() | string()) -> inet:ip4_address() | no_return().
parse_ipv4_for_json(IP) when is_binary(IP) ->
    parse_ipv4_for_json(binary_to_list(IP));
parse_ipv4_for_json(IP) when is_list(IP) ->
    case inet:parse_ipv4strict_address(IP) of
        {ok, ParsedIP} -> ParsedIP;
        {error, Reason} -> error({invalid_ipv4_in_json, list_to_binary(IP), Reason})
    end.

-spec parse_ipv6_for_json(binary() | string()) -> inet:ip6_address() | no_return().
parse_ipv6_for_json(IP) when is_binary(IP) ->
    parse_ipv6_for_json(binary_to_list(IP));
parse_ipv6_for_json(IP) when is_list(IP) ->
    case inet:parse_ipv6strict_address(IP) of
        {ok, ParsedIP} -> ParsedIP;
        {error, Reason} -> error({invalid_ipv6_in_json, list_to_binary(IP), Reason})
    end.

%% Encode unknown key for wire format
-spec encode_unknown_key
    (wire, dns:uint16(), term(), undefined) -> binary();
    (zone, dns:uint16(), term(), escape_callback()) -> iodata().
encode_unknown_key(wire, _KeyNum, none, _) ->
    ~"";
encode_unknown_key(wire, _KeyNum, Value, _) when is_binary(Value) ->
    Value;
encode_unknown_key(zone, KeyNum, none, _Escape) ->
    [[~"key", integer_to_binary(KeyNum)]];
encode_unknown_key(zone, KeyNum, Value, EscapeFun) when is_binary(Value) ->
    KeyNumBin = integer_to_binary(KeyNum),
    EscapedValue = EscapeFun(Value),
    [[~"key", KeyNumBin, "=", EscapedValue]];
encode_unknown_key(_, _KeyNum, Value, _) ->
    error({invalid_svcparam_format, Value}).

-spec encode_alpn_list
    (wire, [binary()]) -> binary();
    (zone, [binary()]) -> iodata().
encode_alpn_list(wire, Protocols) ->
    <<<<(alpn_id_size(P)):8, P/binary>> || P <- Protocols>>;
encode_alpn_list(zone, Protocols) ->
    %% RFC9460 Appendix A.1: a comma or a backslash within an alpn-id is escaped
    join_with_separator(~",", [escape_alpn_id(P, <<>>) || P <- Protocols]).

-spec escape_alpn_id(binary(), binary()) -> binary().
escape_alpn_id(<<C, Rest/binary>>, Acc) when C =:= $,; C =:= $\\ ->
    escape_alpn_id(Rest, <<Acc/binary, $\\, C>>);
escape_alpn_id(<<C, Rest/binary>>, Acc) ->
    escape_alpn_id(Rest, <<Acc/binary, C>>);
escape_alpn_id(<<>>, Acc) ->
    Acc.

-spec decode_alpn_list(wire, binary()) -> [binary()].
decode_alpn_list(wire, Bin) when is_binary(Bin) ->
    decode_alpn_wire(Bin).

%% RFC9460§7.1: an alpn-id is a length-prefixed byte string, so it cannot be longer than 255 bytes.
-spec alpn_id_size(binary()) -> byte().
alpn_id_size(P) when is_binary(P), byte_size(P) =< 255 ->
    byte_size(P);
alpn_id_size(P) ->
    error({svcb_invalid_alpn_id, P}).

-spec decode_alpn_wire(binary()) -> [binary()].
decode_alpn_wire(<<Len:8, Str:Len/binary, Rest/binary>>) ->
    [Str | decode_alpn_wire(Rest)];
decode_alpn_wire(<<>>) ->
    [].

-spec join_with_separator(binary(), [iodata()]) -> iodata().
join_with_separator(Separator, Strings) ->
    lists:join(Separator, Strings).

-spec svcb_param_name(dns:uint16()) -> unicode:latin1_binary().
svcb_param_name(K) ->
    case dns_names:svcb_param_name(K) of
        undefined ->
            error({svcb_param_invalid_key, K});
        Name ->
            Name
    end.
