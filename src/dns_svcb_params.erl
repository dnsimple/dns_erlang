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

-export_type([zone_rdata/0, error_callback/0]).

-export([
    to_wire/1,
    from_wire/1,
    to_json/1,
    from_json/1
]).

-export([
    from_zone/2
]).

%% ============================================================================
%% High-level conversion functions
%% ============================================================================

-spec to_wire(dns:svcb_svc_params()) -> binary().
to_wire(SvcParams) ->
    SortedParams = lists:sort(maps:to_list(SvcParams)),
    to_wire(SortedParams, <<>>).

to_wire([], Bin) ->
    Bin;
to_wire([{Key, Value} | Rest], Bin) ->
    ValueBin =
        case Key of
            ?DNS_SVCB_PARAM_MANDATORY when is_list(Value) ->
                SortedKeys = lists:sort(Value),
                <<<<K:16>> || K <- SortedKeys>>;
            ?DNS_SVCB_PARAM_ALPN when is_list(Value) ->
                <<<<(byte_size(P)):8, P/binary>> || P <- Value>>;
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
            _ when is_binary(Value) ->
                Value
        end,
    NewBin = <<Bin/binary, Key:16/integer, (byte_size(ValueBin)):16/integer, ValueBin/binary>>,
    to_wire(Rest, NewBin).

-spec from_wire(binary()) -> dns:svcb_svc_params().
from_wire(Bin) ->
    from_wire(Bin, #{}, -1).

from_wire(<<>>, SvcParams, _PrevKey) ->
    validate_mandatory_params(SvcParams);
from_wire(
    <<Key:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams, PrevKey
) when PrevKey < Key ->
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
                Value = decode_alpn_list(ValueBin),
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
from_wire(<<Key:16, Len:16, _:Len/binary, _/binary>>, _, PrevKey) when
    Key =< PrevKey
->
    error({svcb_key_ordering_error, {prev_key, PrevKey}, {current_key, Key}}).

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

%% ============================================================================
%% Wire Format Conversions (internal <-> binary)
%% ============================================================================

decode_alpn_list(<<Len:8, Str:Len/binary, Rest/binary>>) ->
    [Str | decode_alpn_list(Rest)];
decode_alpn_list(<<>>) ->
    [].

%% ============================================================================
%% JSON Format Conversions (internal <-> JSON-friendly)
%% ============================================================================

-spec encode_value_to_json(dns:uint16(), term()) -> term().
encode_value_to_json(?DNS_SVCB_PARAM_MANDATORY, Value) when is_list(Value) ->
    [integer_to_binary(V) || V <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_ALPN, Value) when is_list(Value) ->
    [base64:encode(V) || V <- Value];
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
encode_value_to_json(_Key, Value) when is_binary(Value) ->
    base64:encode(Value);
encode_value_to_json(_Key, Value) ->
    Value.

-spec decode_value_from_json(dns:uint16(), term()) -> term().
decode_value_from_json(?DNS_SVCB_PARAM_MANDATORY, Value) when is_list(Value) ->
    [binary_to_integer(V) || V <- Value];
decode_value_from_json(?DNS_SVCB_PARAM_ALPN, Value) when is_list(Value) ->
    [base64:decode(V) || V <- Value];
decode_value_from_json(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, ~"none") ->
    none;
decode_value_from_json(?DNS_SVCB_PARAM_PORT, Value) when is_binary(Value) ->
    binary_to_integer(Value);
decode_value_from_json(?DNS_SVCB_PARAM_IPV4HINT, Value) when is_list(Value) ->
    [
        element(2, inet:parse_address(binary_to_list(V)))
     || V <- Value
    ];
decode_value_from_json(?DNS_SVCB_PARAM_ECH, Value) when is_binary(Value) ->
    base64:decode(Value);
decode_value_from_json(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_list(Value) ->
    [
        element(2, inet:parse_address(binary_to_list(V)))
     || V <- Value
    ];
decode_value_from_json(_Key, Value) when is_binary(Value) ->
    try
        base64:decode(Value)
    catch
        _:_ -> Value
    end;
decode_value_from_json(_Key, Value) ->
    Value.

%% ============================================================================
%% Zone Format Parsing (token format from zone parser -> internal)
%% ============================================================================

%% Parse SVCB/HTTPS service parameters from zone parser's rdata format
%% Handles both parsed key=value pairs and labels containing = (from lexer)
-spec from_zone([zone_rdata()], error_callback()) ->
    {ok, dns:svcb_svc_params()} | {error, term()}.
from_zone(SvcParams, MakeError) ->
    from_zone(SvcParams, MakeError, #{}).

-spec from_zone([zone_rdata()], error_callback(), dns:svcb_svc_params()) ->
    {ok, dns:svcb_svc_params()} | {error, term()}.
from_zone([], MakeError, Acc) ->
    case validate_mandatory_params_for_zone(Acc, MakeError) of
        {ok, Validated} -> {ok, Validated};
        {error, _} = Error -> Error
    end;
from_zone([{domain, "no-default-alpn"} | Rest], MakeError, Acc) ->
    NewAcc = Acc#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none},
    from_zone(Rest, MakeError, NewAcc);
from_zone([{domain, "alpn=" ++ Alpn} | Rest], MakeError, Acc) ->
    Protocols = [list_to_binary(string:trim(P)) || P <- string:split(Alpn, ",", all), P =/= ""],
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
from_zone(
    [{domain, "key" ++ RestStr}, {string, Value} | Rest], MakeError, Acc
) ->
    %% Check for unknown key with quoted value: keyNNNNN="value"
    case string:split(RestStr, "=", leading) of
        [KeyNumStr, ""] ->
            case string:to_integer(KeyNumStr) of
                {KeyNum, ""} when KeyNum >= 0, KeyNum =< 65535 ->
                    ValueBin =
                        try
                            base64:decode(Value)
                        catch
                            _:_ -> list_to_binary(Value)
                        end,
                    NewAcc = Acc#{KeyNum => ValueBin},
                    from_zone(Rest, MakeError, NewAcc);
                _ ->
                    {error, MakeError({invalid_key_number, KeyNumStr})}
            end;
        _ ->
            %% Not keyNNNNN= format, error
            {error, MakeError({invalid_svcparam_format, RestStr})}
    end;
from_zone([{domain, ParamStr}, {string, _} | _], MakeError, _) ->
    {error, MakeError({invalid_svcparam_format, ParamStr})};
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
    KeyNum =
        case string:to_integer(IntStr) of
            {Num, ""} when Num >= 0, Num =< 65535 -> Num;
            _ -> undefined
        end,
    parse_mandatory_keys_for_zone(Rest, MakeError, [KeyNum | Acc]);
parse_mandatory_keys_for_zone([Key | _], MakeError, _) ->
    {error, MakeError({invalid_mandatory_key, Key})}.

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
    case inet:parse_address(IP) of
        {ok, {A, B, C, D}} ->
            parse_ipv4_list_for_zone(Rest, MakeError, [{A, B, C, D} | Acc]);
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
    case inet:parse_address(IP) of
        {ok, {A, B, C, D, E, F, G, H}} ->
            parse_ipv6_list_for_zone(Rest, MakeError, [{A, B, C, D, E, F, G, H} | Acc]);
        {error, Reason} ->
            {error, MakeError({invalid_ipv6_in_hint, IP, Reason})}
    end.

%% Validate mandatory params for zone format (returns {ok, Params} | {error, ErrorDetail})
-spec validate_mandatory_params_for_zone(dns:svcb_svc_params(), error_callback()) ->
    {ok, dns:svcb_svc_params()} | {error, term()}.
validate_mandatory_params_for_zone(
    #{?DNS_SVCB_PARAM_MANDATORY := MandatoryKeys} = SvcParams, MakeError
) ->
    %% Check that mandatory doesn't reference itself (key 0)
    case lists:member(?DNS_SVCB_PARAM_MANDATORY, MandatoryKeys) of
        true ->
            Error = {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY},
            {error, MakeError(Error)};
        false ->
            %% Check that all mandatory keys exist in SvcParams
            MissingKeys = [K || K <- MandatoryKeys, not maps:is_key(K, SvcParams)],
            case MissingKeys of
                [] ->
                    {ok, SvcParams};
                _ ->
                    Error = {missing_mandatory_keys, MissingKeys},
                    {error, MakeError(Error)}
            end
    end;
validate_mandatory_params_for_zone(SvcParams, _MakeError) ->
    {ok, SvcParams}.

-spec validate_mandatory_params(dns:svcb_svc_params()) -> dns:svcb_svc_params() | no_return().
validate_mandatory_params(#{?DNS_SVCB_PARAM_MANDATORY := MandatoryKeys} = SvcParams) ->
    %% Check that mandatory doesn't reference itself (key 0)
    case lists:member(?DNS_SVCB_PARAM_MANDATORY, MandatoryKeys) of
        true ->
            Reason = {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY},
            error({svcb_mandatory_validation_error, Reason});
        false ->
            %% Check that all mandatory keys exist in SvcParams
            MissingKeys = [K || K <- MandatoryKeys, not maps:is_key(K, SvcParams)],
            case MissingKeys of
                [] ->
                    SvcParams;
                _ ->
                    Reason = {missing_mandatory_keys, MissingKeys},
                    error({svcb_mandatory_validation_error, Reason})
            end
    end;
validate_mandatory_params(SvcParams) ->
    SvcParams.
