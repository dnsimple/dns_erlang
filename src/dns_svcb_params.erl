-module(dns_svcb_params).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-endif.
?MODULEDOC(false).

-include_lib("dns_erlang/include/dns.hrl").

-type zone_rdata() ::
    {int, integer()}
    | {string, string()}
    | {ipv4, string()}
    | {ipv6, string()}
    | {domain, string()}
    | {rfc3597, string()}.

-type error_callback() :: fun((term()) -> term()).

-type escape_callback() :: fun((binary()) -> binary()).

-type format() :: wire | zone | json.
-export_type([zone_rdata/0, error_callback/0, escape_callback/0]).

-export([to_wire/1, from_wire/1]).
-export([to_json/1, from_json/1]).
-export([from_zone/2, to_zone/3]).

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
                encode_unknown_key(wire, Key, Value, fun(V) -> V end)
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
                Value = [K || <<K:16>> <= ValueBin],
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
                Value = [{A, B, C, D} || <<A, B, C, D>> <= ValueBin],
                SvcParams#{?DNS_SVCB_PARAM_IPV4HINT => Value};
            ?DNS_SVCB_PARAM_IPV6HINT ->
                Value = [
                    {A, B, C, D, E, F, G, H}
                 || <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> <= ValueBin
                ],
                SvcParams#{?DNS_SVCB_PARAM_IPV6HINT => Value};
            _ ->
                SvcParams#{Key => ValueBin}
        end,
    from_wire(Rest, NewSvcParams, Key);
from_wire(<<Key:16, Len:16, _:Len/binary, _/binary>>, _, K0) when Key =< K0 ->
    error({svcb_key_ordering_error, {prev_key, K0}, {current_key, Key}}).

-spec to_json(dns:svcb_svc_params()) -> map().
to_json(SvcParams) ->
    #{
        dns_names:svcb_param_name(K) => encode_value_to_json(K, V)
     || K := V <- SvcParams
    }.

-spec from_json(map()) -> dns:svcb_svc_params().
from_json(JsonMap) ->
    #{
        dns_names:name_svcb_param(K) =>
            decode_value_from_json(dns_names:name_svcb_param(K), V)
     || K := V <- JsonMap
    }.

%% Parse SVCB/HTTPS service parameters from zone parser's rdata format
%% Handles both parsed key=value pairs and labels containing = (from lexer)
-spec from_zone([zone_rdata()], error_callback()) ->
    {ok, dns:svcb_svc_params()} | {error, term()}.
from_zone(SvcParams, MakeError) ->
    from_zone(SvcParams, MakeError, #{}).

-spec from_zone([zone_rdata()], error_callback(), dns:svcb_svc_params()) ->
    {ok, dns:svcb_svc_params()} | {error, term()}.
from_zone([], MakeError, Acc) ->
    case validate_mandatory_params(zone, Acc) of
        {ok, Validated} -> {ok, Validated};
        {error, Error} -> {error, MakeError(Error)}
    end;
from_zone([{domain, "no-default-alpn"} | Rest], MakeError, Acc) ->
    NewAcc = Acc#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none},
    from_zone(Rest, MakeError, NewAcc);
from_zone([{domain, "alpn=" ++ Alpn} | Rest], MakeError, Acc) ->
    Protocols = decode_alpn_list(zone, Alpn),
    NewAcc = Acc#{?DNS_SVCB_PARAM_ALPN => Protocols},
    from_zone(Rest, MakeError, NewAcc);
from_zone([{domain, "port=" ++ PortStr} | Rest], MakeError, Acc) ->
    case string:to_integer(PortStr) of
        {Port, ""} when Port >= 0, Port =< 65535 ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_PORT => Port},
            from_zone(Rest, MakeError, NewAcc);
        _ ->
            {error, MakeError({invalid_port, PortStr})}
    end;
from_zone([{domain, "ipv4hint=" ++ Value} | Rest], MakeError, Acc) ->
    IPs = [string:trim(IP) || IP <- string:split(Value, ",", all), IP =/= ""],
    case parse_ipv4_list_for_zone(IPs, MakeError) of
        {ok, IPList} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_IPV4HINT => IPList},
            from_zone(Rest, MakeError, NewAcc);
        {error, _} = Error ->
            Error
    end;
from_zone([{domain, "ipv6hint=" ++ Value} | Rest], MakeError, Acc) ->
    IPs = [string:trim(IP) || IP <- string:split(Value, ",", all), IP =/= ""],
    case parse_ipv6_list_for_zone(IPs, MakeError) of
        {ok, IPList} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_IPV6HINT => IPList},
            from_zone(Rest, MakeError, NewAcc);
        {error, _} = Error ->
            Error
    end;
from_zone([{domain, "mandatory=" ++ Mandatory} | Rest], MakeError, Acc) ->
    Keys = [string:trim(K) || K <- string:split(Mandatory, ",", all), K =/= ""],
    case parse_mandatory_keys_for_zone(Keys, MakeError) of
        {ok, KeyNums} ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_MANDATORY => KeyNums},
            from_zone(Rest, MakeError, NewAcc);
        {error, _} = Error ->
            Error
    end;
from_zone([{domain, "ech="}, {string, Value} | Rest], MakeError, Acc) ->
    try
        ECHConfig = base64:decode(Value),
        NewAcc = Acc#{?DNS_SVCB_PARAM_ECH => ECHConfig},
        from_zone(Rest, MakeError, NewAcc)
    catch
        _:Reason ->
            {error, MakeError({invalid_svcparam_format, Reason})}
    end;
from_zone([{domain, "key" ++ RestStr}, {string, Value} | Rest], MakeError, Acc) ->
    %% Check for unknown key with quoted value: keyNNNNN="value"
    [KeyNumStr, ""] = string:split(RestStr, "=", leading),
    case string:to_integer(KeyNumStr) of
        {KeyNum, ""} when KeyNum >= 0, KeyNum =< 65535 ->
            ValueBin = base64:decode(Value),
            NewAcc = Acc#{KeyNum => ValueBin},
            from_zone(Rest, MakeError, NewAcc);
        _ ->
            {error, MakeError({invalid_key_number, KeyNumStr})}
    end;
from_zone([{domain, "key" ++ KeyNumStr} | Rest], MakeError, Acc) ->
    %% keyNNNNN (no value, like no-default-alpn)
    case string:to_integer(KeyNumStr) of
        {KeyNum, ""} when KeyNum >= 0, KeyNum =< 65535 ->
            NewAcc = Acc#{KeyNum => none},
            from_zone(Rest, MakeError, NewAcc);
        _ ->
            {error, MakeError({invalid_svcparam_format, KeyNumStr})}
    end;
from_zone([Other | _], MakeError, _) ->
    {error, MakeError({invalid_svcparam_format, Other})}.

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
                KeyNames = [dns_names:svcb_param_name(K) || K <- Keys],
                [[~"mandatory=\"", join_with_separator(~",", KeyNames), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_ALPN, Protocols}, Acc0) ->
                AlpnStr = encode_alpn_list(zone, Protocols),
                [[~"alpn=\"", AlpnStr, ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none}, Acc0) ->
                [~"no-default-alpn" | Acc0];
            ({?DNS_SVCB_PARAM_PORT, Port}, Acc0) ->
                [[~"port=\"", integer_to_binary(Port), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_IPV4HINT, IPs}, Acc0) ->
                IPStrs = [inet:ntoa(IP) || IP <- IPs],
                [[~"ipv4hint=\"", join_with_separator(~",", IPStrs), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_IPV6HINT, IPs}, Acc0) ->
                IPStrs = [inet:ntoa(IP) || IP <- IPs],
                [[~"ipv6hint=\"", join_with_separator(~",", IPStrs), ~"\""] | Acc0];
            ({?DNS_SVCB_PARAM_ECH, ECHConfig}, Acc0) ->
                [[~"ech=\"", base64:encode(ECHConfig), ~"\""] | Acc0];
            ({KeyNum, Value}, Acc0) when is_integer(KeyNum) ->
                [encode_unknown_key(zone, KeyNum, Value, EscapeFun) | Acc0]
        end,
        Acc,
        SortedParams
    ).

%% Parse mandatory parameter keys for zone format (e.g., "alpn,port" -> [1, 3])
-spec parse_mandatory_keys_for_zone([string()], error_callback()) ->
    {ok, [dns:uint16()]} | {error, term()}.
parse_mandatory_keys_for_zone(Keys, MakeError) ->
    parse_mandatory_keys_for_zone(Keys, MakeError, []).

-spec parse_mandatory_keys_for_zone([string()], error_callback(), [dns:uint16()]) ->
    {ok, [dns:uint16()]} | {error, term()}.
parse_mandatory_keys_for_zone([], _MakeError, Acc) ->
    {ok, lists:reverse(Acc)};
parse_mandatory_keys_for_zone(["alpn" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_ALPN | Acc]);
parse_mandatory_keys_for_zone(["no-default-alpn" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_NO_DEFAULT_ALPN | Acc]);
parse_mandatory_keys_for_zone(["port" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_PORT | Acc]);
parse_mandatory_keys_for_zone(["ipv4hint" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_IPV4HINT | Acc]);
parse_mandatory_keys_for_zone(["ipv6hint" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_IPV6HINT | Acc]);
parse_mandatory_keys_for_zone(["key" ++ IntStr | Rest], MakeError, Acc) ->
    case string:to_integer(IntStr) of
        {KeyNum, ""} when 0 =< KeyNum, KeyNum =< 65535 ->
            parse_mandatory_keys_for_zone(Rest, MakeError, [KeyNum | Acc]);
        _ ->
            {error, MakeError({invalid_mandatory_key, IntStr})}
    end;
parse_mandatory_keys_for_zone([Key | _], MakeError, _) ->
    {error, MakeError({invalid_mandatory_key, Key})}.

%% Validate mandatory params for wire format (throws on error)
-spec validate_mandatory_params
    (wire, dns:svcb_svc_params()) -> dns:svcb_svc_params() | no_return();
    (zone, dns:svcb_svc_params()) -> {ok, dns:svcb_svc_params()} | no_return() | {error, term()}.
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
    [integer_to_binary(V) || V <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_ALPN, Value) when is_list(Value) ->
    encode_alpn_list(json, Value);
encode_value_to_json(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none) ->
    ~"none";
encode_value_to_json(?DNS_SVCB_PARAM_PORT, Value) when is_integer(Value) ->
    integer_to_binary(Value);
encode_value_to_json(?DNS_SVCB_PARAM_IPV4HINT, Value) when is_list(Value) ->
    [list_to_binary(inet:ntoa(V)) || V <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_ECH, Value) when is_binary(Value) ->
    base64:encode(Value);
encode_value_to_json(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_list(Value) ->
    [list_to_binary(inet:ntoa(V)) || V <- Value];
encode_value_to_json(Key, Value) when is_integer(Key) ->
    encode_unknown_key(json, Key, Value, fun(V) -> V end).

-spec decode_value_from_json(dns:uint16(), term()) -> term().
decode_value_from_json(?DNS_SVCB_PARAM_MANDATORY, Value) when is_list(Value) ->
    [binary_to_integer(V) || V <- Value];
decode_value_from_json(?DNS_SVCB_PARAM_ALPN, Value) when is_list(Value) ->
    decode_alpn_list(json, Value);
decode_value_from_json(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, ~"none") ->
    none;
decode_value_from_json(?DNS_SVCB_PARAM_PORT, Value) when is_binary(Value) ->
    binary_to_integer(Value);
decode_value_from_json(?DNS_SVCB_PARAM_IPV4HINT, Value) when is_list(Value) ->
    %% Parse IPv4 addresses from JSON format - fail on any invalid IP
    decode_ipv4_list_from_json(Value);
decode_value_from_json(?DNS_SVCB_PARAM_ECH, Value) when is_binary(Value) ->
    base64:decode(Value);
decode_value_from_json(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_list(Value) ->
    %% Parse IPv6 addresses from JSON format - fail on any invalid IP
    decode_ipv6_list_from_json(Value);
decode_value_from_json(Key, Value) when is_integer(Key) ->
    %% Unknown key - decode as binary
    decode_unknown_key(json, Key, Value);
decode_value_from_json(_Key, Value) ->
    Value.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Decode IPv4 list from JSON format - throws on invalid IP
-spec decode_ipv4_list_from_json([binary()]) -> [inet:ip4_address()] | no_return().
decode_ipv4_list_from_json(ValueList) ->
    decode_ipv4_list_from_json(ValueList, []).

-spec decode_ipv4_list_from_json([binary()], [inet:ip4_address()]) ->
    [inet:ip4_address()] | no_return().
decode_ipv4_list_from_json([], Acc) ->
    lists:reverse(Acc);
decode_ipv4_list_from_json([V | Rest], Acc) ->
    case parse_ipv4(json, V) of
        {ok, IP} ->
            decode_ipv4_list_from_json(Rest, [IP | Acc]);
        {error, Reason} ->
            error({invalid_ipv4_in_json, V, Reason})
    end.

%% Decode IPv6 list from JSON format - throws on invalid IP
-spec decode_ipv6_list_from_json([binary()]) -> [inet:ip6_address()] | no_return().
decode_ipv6_list_from_json(ValueList) ->
    decode_ipv6_list_from_json(ValueList, []).

-spec decode_ipv6_list_from_json([binary()], [inet:ip6_address()]) ->
    [inet:ip6_address()] | no_return().
decode_ipv6_list_from_json([], Acc) ->
    lists:reverse(Acc);
decode_ipv6_list_from_json([V | Rest], Acc) ->
    case parse_ipv6(json, V) of
        {ok, IP} ->
            decode_ipv6_list_from_json(Rest, [IP | Acc]);
        {error, Reason} ->
            error({invalid_ipv6_in_json, V, Reason})
    end.

%% Encode unknown key for wire format
-spec encode_unknown_key
    (wire, dns:uint16(), term(), escape_callback()) -> binary();
    (zone, dns:uint16(), term(), escape_callback()) -> iodata();
    (json, dns:uint16(), term(), escape_callback()) -> term().
encode_unknown_key(wire, _KeyNum, Value, _Escape) when is_binary(Value) ->
    Value;
encode_unknown_key(zone, KeyNum, none, _Escape) ->
    [[~"key", integer_to_binary(KeyNum)]];
encode_unknown_key(zone, KeyNum, Value, EscapeFun) when is_binary(Value) ->
    KeyNumBin = integer_to_binary(KeyNum),
    EscapedValue = EscapeFun(Value),
    [[~"key", KeyNumBin, "=", EscapedValue]];
encode_unknown_key(json, _KeyNum, Value, _Escape) when is_binary(Value) ->
    base64:encode(Value);
encode_unknown_key(json, _KeyNum, Value, _Escape) ->
    Value.

%% Decode unknown key from JSON format
-spec decode_unknown_key(json, dns:uint16(), term()) -> binary() | term().
decode_unknown_key(json, _KeyNum, Value) when is_binary(Value) ->
    try
        base64:decode(Value)
    catch
        _:_ -> Value
    end;
decode_unknown_key(json, _KeyNum, Value) ->
    Value.

-spec parse_ipv4(format(), binary() | string()) -> {ok, inet:ip4_address()} | {error, term()}.
parse_ipv4(zone, IPStr) when is_list(IPStr) ->
    case inet:parse_ipv4strict_address(IPStr) of
        {ok, IP} -> {ok, IP};
        Error -> Error
    end;
parse_ipv4(json, IPBin) when is_binary(IPBin) ->
    case inet:parse_ipv4strict_address(binary_to_list(IPBin)) of
        {ok, IP} -> {ok, IP};
        Error -> Error
    end.

%% Parse IPv6 address from different formats
-spec parse_ipv6(format(), binary() | string()) -> {ok, inet:ip6_address()} | {error, term()}.
parse_ipv6(zone, IPStr) when is_list(IPStr) ->
    case inet:parse_ipv6strict_address(IPStr) of
        {ok, IP} -> {ok, IP};
        Error -> Error
    end;
parse_ipv6(json, IPBin) when is_binary(IPBin) ->
    case inet:parse_ipv6strict_address(binary_to_list(IPBin)) of
        {ok, IP} -> {ok, IP};
        Error -> Error
    end.

%% Parse a list of IPv4 addresses for zone format
-spec parse_ipv4_list_for_zone([string()], error_callback()) ->
    {ok, [inet:ip4_address()]} | {error, term()}.
parse_ipv4_list_for_zone(IPs, MakeError) ->
    parse_ipv4_list_for_zone(IPs, MakeError, []).

-spec parse_ipv4_list_for_zone([string()], error_callback(), [inet:ip4_address()]) ->
    {ok, [inet:ip4_address()]} | {error, term()}.
parse_ipv4_list_for_zone([], _MakeError, Acc) ->
    {ok, lists:reverse(Acc)};
parse_ipv4_list_for_zone([IP | Rest], MakeError, Acc) ->
    case parse_ipv4(zone, IP) of
        {ok, IPAddr} ->
            parse_ipv4_list_for_zone(Rest, MakeError, [IPAddr | Acc]);
        {error, Reason} ->
            {error, MakeError({invalid_ipv4_in_hint, IP, Reason})}
    end.

%% Parse a list of IPv6 addresses for zone format
-spec parse_ipv6_list_for_zone([string()], error_callback()) ->
    {ok, [inet:ip6_address()]} | {error, term()}.
parse_ipv6_list_for_zone(IPs, MakeError) ->
    parse_ipv6_list_for_zone(IPs, MakeError, []).

-spec parse_ipv6_list_for_zone([string()], error_callback(), [inet:ip6_address()]) ->
    {ok, [inet:ip6_address()]} | {error, term()}.
parse_ipv6_list_for_zone([], _MakeError, Acc) ->
    {ok, lists:reverse(Acc)};
parse_ipv6_list_for_zone([IP | Rest], MakeError, Acc) ->
    case parse_ipv6(zone, IP) of
        {ok, IPAddr} ->
            parse_ipv6_list_for_zone(Rest, MakeError, [IPAddr | Acc]);
        {error, Reason} ->
            {error, MakeError({invalid_ipv6_in_hint, IP, Reason})}
    end.

-spec encode_alpn_list
    (wire, [binary()]) -> binary();
    (zone, [binary()]) -> iodata();
    (json, [binary()]) -> [binary()].
encode_alpn_list(wire, Protocols) ->
    <<<<(byte_size(P)):8, P/binary>> || P <- Protocols>>;
encode_alpn_list(zone, Protocols) ->
    join_with_separator(~",", Protocols);
encode_alpn_list(json, Protocols) ->
    [base64:encode(P) || P <- Protocols].

-spec decode_alpn_list
    (wire, binary()) -> [binary()];
    (zone, string()) -> [binary()];
    (json, [binary()]) -> [binary()].
decode_alpn_list(wire, Bin) when is_binary(Bin) ->
    decode_alpn_wire(Bin);
decode_alpn_list(zone, AlpnStr) when is_list(AlpnStr) ->
    [list_to_binary(string:trim(P)) || P <- string:split(AlpnStr, ",", all), P =/= ""];
decode_alpn_list(json, ValueList) when is_list(ValueList) ->
    [base64:decode(V) || V <- ValueList].

-spec decode_alpn_wire(binary()) -> [binary()].
decode_alpn_wire(<<Len:8, Str:Len/binary, Rest/binary>>) ->
    [Str | decode_alpn_wire(Rest)];
decode_alpn_wire(<<>>) ->
    [].

-spec join_with_separator(binary(), [iodata()]) -> iodata().
join_with_separator(Separator, Strings) ->
    lists:join(Separator, Strings).
