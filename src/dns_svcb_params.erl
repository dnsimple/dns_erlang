-module(dns_svcb_params).
-moduledoc false.

%% Suppress "created fun only terminates with explicit exception" for the default error callback.
-dialyzer({nowarn_function, validate_dohpath_utf8/1}).

-include_lib("dns_erlang/include/dns.hrl").

-type zone_rdata() ::
    {int, integer()}
    | {string, string()}
    | {ipv4, string()}
    | {ipv6, string()}
    | {domain, string()}
    | {rfc3597, string()}.

-type error_callback() :: fun((dynamic()) -> dynamic()).

-type escape_callback() :: fun((binary()) -> binary()).

-export_type([zone_rdata/0, error_callback/0, escape_callback/0]).

-export([to_wire/1, from_wire/1]).
-export([to_json/1, from_json/1]).
-export([to_zone/3, from_zone/2]).

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
            ?DNS_SVCB_PARAM_DOHPATH when is_binary(Value) ->
                validate_dohpath_utf8(Value);
            ?DNS_SVCB_PARAM_OHTTP when Value =:= none ->
                <<>>;
            ?DNS_SVCB_PARAM_OHTTP ->
                error({svcb_bad_ohttp, value});
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
            ?DNS_SVCB_PARAM_DOHPATH ->
                UnicodeBin = validate_dohpath_utf8(ValueBin),
                SvcParams#{?DNS_SVCB_PARAM_DOHPATH => UnicodeBin};
            ?DNS_SVCB_PARAM_OHTTP when Len =:= 0 ->
                SvcParams#{?DNS_SVCB_PARAM_OHTTP => none};
            ?DNS_SVCB_PARAM_OHTTP ->
                error({svcb_bad_ohttp, Len});
            _ when Len =:= 0 ->
                SvcParams#{Key => none};
            _ ->
                SvcParams#{Key => ValueBin}
        end,
    from_wire(Rest, NewSvcParams, Key);
from_wire(<<Key:16, Len:16, _:Len/binary, _/binary>>, _, K0) when Key =< K0 ->
    error({svcb_key_ordering_error, {prev_key, K0}, {current_key, Key}}).

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
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_IPV4HINT when is_list(Value) ->
                IPs = [parse_ipv4_for_json(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            ?DNS_SVCB_PARAM_IPV6HINT when is_list(Value) ->
                IPs = [parse_ipv6_for_json(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            ?DNS_SVCB_PARAM_DOHPATH when is_binary(Value) ->
                UnicodeBin = validate_dohpath_utf8(Value),
                Acc#{ParamKey => UnicodeBin};
            ?DNS_SVCB_PARAM_OHTTP when Value =:= null ->
                Acc#{ParamKey => none};
            %% Unknown keys (key >= 9) stored as-is; key0-key8 with wrong value type are invalid
            NNNN when is_integer(NNNN), 9 =< NNNN, null =:= Value ->
                Acc#{NNNN => none};
            NNNN when is_integer(NNNN), 9 =< NNNN, is_binary(Value) ->
                Acc#{NNNN => Value};
            undefined ->
                Acc;
            _ ->
                error({svcb_param_invalid_value, ParamKey, Value})
        end,
    parse_svcb_params_from_json(Rest, NewAcc).

%% Parse SVCB/HTTPS service parameters from zone parser's rdata format
%% Handles both parsed key=value pairs and labels containing = (from lexer)
-spec from_zone([zone_rdata()], error_callback()) ->
    {ok, dns:svcb_svc_params()} | {error, dynamic()}.
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
from_zone([{domain, "ohttp"} | Rest], MakeError, Acc) ->
    NewAcc = Acc#{?DNS_SVCB_PARAM_OHTTP => none},
    from_zone(Rest, MakeError, NewAcc);
%% Zone quoted string: Value is list of bytes (lexer) or codepoints;
%% normalize to binary and validate UTF-8.
from_zone([{domain, "dohpath="}, {string, Value} | Rest], MakeError, Acc) ->
    case validate_dohpath_utf8(Value, MakeError) of
        Bin when is_binary(Bin) ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_DOHPATH => Bin},
            from_zone(Rest, MakeError, NewAcc);
        Error ->
            {error, Error}
    end;
from_zone([{domain, "dohpath=" ++ Value} | Rest], MakeError, Acc) ->
    case validate_dohpath_utf8(Value, MakeError) of
        Bin when is_binary(Bin) ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_DOHPATH => Bin},
            from_zone(Rest, MakeError, NewAcc);
        Error ->
            {error, Error}
    end;
from_zone([{domain, "ech="}, {string, Value} | Rest], MakeError, Acc) ->
    case safe_base64_decode(Value) of
        error ->
            {error, MakeError({invalid_svcparam_format, Value})};
        ECHConfig when is_binary(ECHConfig) ->
            NewAcc = Acc#{?DNS_SVCB_PARAM_ECH => ECHConfig},
            from_zone(Rest, MakeError, NewAcc)
    end;
from_zone([{domain, "key" ++ RestStr}, {string, Value} | Rest], MakeError, Acc) ->
    %% keyNNNNN="value"; key0-key8 redirect to named-param tokens
    case string:split(RestStr, "=", leading) of
        [KeyNumStr] ->
            apply_key_with_value(KeyNumStr, Value, Rest, MakeError, Acc);
        [KeyNumStr, ""] ->
            apply_key_with_value(KeyNumStr, Value, Rest, MakeError, Acc);
        [_NumStr, _AfterEq] ->
            {error, MakeError({invalid_svcparam_format, RestStr})}
    end;
from_zone([{domain, "key" ++ KeyNumStr} | Rest], MakeError, Acc) ->
    %% keyNNNNN (no value) or keyNNNN=value (value may be empty or contain =)
    case string:split(KeyNumStr, "=", leading) of
        [NumStr] ->
            %% No = in key part; keyNNNN (no value)
            case string:to_integer(NumStr) of
                {?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, ""} ->
                    NewAcc = Acc#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none},
                    from_zone(Rest, MakeError, NewAcc);
                {?DNS_SVCB_PARAM_OHTTP, ""} ->
                    NewAcc = Acc#{?DNS_SVCB_PARAM_OHTTP => none},
                    from_zone(Rest, MakeError, NewAcc);
                {KeyNum, ""} when 9 =< KeyNum, KeyNum =< 65535 ->
                    NewAcc = Acc#{KeyNum => none},
                    from_zone(Rest, MakeError, NewAcc);
                _ ->
                    {error, MakeError({invalid_svcparam_format, KeyNumStr})}
            end;
        [NumStr, ValueStr] ->
            %% keyNNNN=value (value may be empty or contain =)
            apply_key_with_value(NumStr, ValueStr, Rest, MakeError, Acc)
    end;
from_zone([Other | _], MakeError, _) ->
    {error, MakeError({invalid_svcparam_format, Other})}.

%% keyNNNN="value" path: key 0-8 -> named tokens + recurse
-spec apply_key_with_value(
    unicode:chardata(), term(), [zone_rdata()], error_callback(), dns:svcb_svc_params()
) -> {ok, dns:svcb_svc_params()} | {error, term()}.
apply_key_with_value(KeyNumStr, Value, Rest, MakeError, Acc) ->
    case {string:to_integer(KeyNumStr), Value} of
        {{KeyNum, ""}, _} when 0 =< KeyNum, KeyNum =< 8 ->
            case key_num_to_named_tokens(KeyNum, Value, Rest) of
                {error, Reason} ->
                    {error, MakeError(Reason)};
                Tokens when is_list(Tokens) ->
                    from_zone(Tokens, MakeError, Acc)
            end;
        {{KeyNum, ""}, ""} when 9 =< KeyNum, KeyNum =< 65535 ->
            NewAcc = Acc#{KeyNum => none},
            from_zone(Rest, MakeError, NewAcc);
        {{KeyNum, ""}, _} when 9 =< KeyNum, KeyNum =< 65535 ->
            %% Quoted value for key>=9: store as literal binary (same as unquoted)
            Bin = unicode:characters_to_binary(Value),
            NewAcc = Acc#{KeyNum => Bin},
            from_zone(Rest, MakeError, NewAcc);
        _ ->
            {error, MakeError({invalid_key_number, KeyNumStr})}
    end.

%% Map key0-key8 + value to the equivalent named-param token list so from_zone reuses validation.
-spec key_num_to_named_tokens(dns:uint16(), string() | binary(), [zone_rdata()]) ->
    [zone_rdata()] | {error, term()}.
key_num_to_named_tokens(?DNS_SVCB_PARAM_MANDATORY, Value, Rest) ->
    [{domain, "mandatory=" ++ ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_ALPN, Value, Rest) ->
    [{domain, "alpn=" ++ ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, _Value, _) ->
    {error, {svcb_param_no_value_allowed, no_default_alpn}};
key_num_to_named_tokens(?DNS_SVCB_PARAM_PORT, Value, Rest) ->
    [{domain, "port=" ++ ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_IPV4HINT, Value, Rest) ->
    [{domain, "ipv4hint=" ++ ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_ECH, Value, Rest) ->
    [{domain, "ech="}, {string, ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_IPV6HINT, Value, Rest) ->
    [{domain, "ipv6hint=" ++ ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_DOHPATH, Value, Rest) ->
    [{domain, "dohpath="}, {string, ensure_list(Value)} | Rest];
key_num_to_named_tokens(?DNS_SVCB_PARAM_OHTTP, _Value, _) ->
    {error, {svcb_param_no_value_allowed, ohttp}}.

ensure_list(Bin) when is_binary(Bin) -> binary_to_list(Bin);
ensure_list(L) when is_list(L) -> L.

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
            ({?DNS_SVCB_PARAM_DOHPATH, Path}, Acc0) ->
                UnicodeBin = validate_dohpath_utf8(Path),
                [[~"dohpath=", EscapeFun(UnicodeBin)] | Acc0];
            ({?DNS_SVCB_PARAM_OHTTP, none}, Acc0) ->
                [~"ohttp" | Acc0];
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
parse_mandatory_keys_for_zone(["dohpath" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_DOHPATH | Acc]);
parse_mandatory_keys_for_zone(["ohttp" | Rest], MakeError, Acc) ->
    parse_mandatory_keys_for_zone(Rest, MakeError, [?DNS_SVCB_PARAM_OHTTP | Acc]);
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
    Value;
encode_value_to_json(?DNS_SVCB_PARAM_IPV6HINT, Value) when is_list(Value) ->
    [list_to_binary(inet:ntoa(V)) || V <- Value];
encode_value_to_json(?DNS_SVCB_PARAM_DOHPATH, Value) when is_binary(Value) ->
    validate_dohpath_utf8(Value);
encode_value_to_json(?DNS_SVCB_PARAM_OHTTP, none) ->
    null;
encode_value_to_json(Key, none) when is_integer(Key) ->
    null;
encode_value_to_json(Key, Value) when is_integer(Key), is_binary(Value) ->
    Value;
encode_value_to_json(Key, Value) ->
    error({svcb_param_invalid_value, Key, Value}).

%% ============================================================================
%% Helpers
%% ============================================================================

%% RFC 9461: dohpath SvcParamValue is UTF-8. Reject invalid sequences.
%% Zone lexer may pass list of bytes (when zone was binary) or code points (when zone was list).
-spec validate_dohpath_utf8(unicode:chardata()) -> unicode:unicode_binary() | dynamic().
validate_dohpath_utf8(Input) ->
    validate_dohpath_utf8(Input, fun(Error) -> error(Error) end).

-spec validate_dohpath_utf8(unicode:chardata(), error_callback()) ->
    unicode:unicode_binary() | dynamic().
validate_dohpath_utf8(Input, MakeError) when is_binary(Input) ->
    case unicode:characters_to_binary(Input, utf8, utf8) of
        Bin when is_binary(Bin) -> Bin;
        _ -> MakeError({svcb_bad_dohpath_utf8, Input})
    end;
validate_dohpath_utf8(Input, MakeError) when is_list(Input) ->
    %% Try list as bytes first (zone parsed from binary);
    %% then as Unicode code points (zone as list).
    BinFromBytes = list_to_binary(Input),
    case unicode:characters_to_binary(BinFromBytes, utf8, utf8) of
        Bin when is_binary(Bin), Bin =:= BinFromBytes ->
            Bin;
        _ ->
            case unicode:characters_to_binary(Input, unicode, utf8) of
                Bin when is_binary(Bin) -> Bin;
                _ -> MakeError({svcb_bad_dohpath_utf8, Input})
            end
    end.

-spec safe_base64_decode(string() | binary()) -> binary() | error.
safe_base64_decode(Value) ->
    try
        base64:decode(Value)
    catch
        _:_ ->
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

-spec parse_ipv4(zone, string()) -> {ok, inet:ip4_address()} | {error, term()}.
parse_ipv4(zone, IPStr) when is_list(IPStr) ->
    case inet:parse_ipv4strict_address(IPStr) of
        {ok, IP} -> {ok, IP};
        Error -> Error
    end.

-spec parse_ipv6(zone, string()) -> {ok, inet:ip6_address()} | {error, term()}.
parse_ipv6(zone, IPStr) when is_list(IPStr) ->
    case inet:parse_ipv6strict_address(IPStr) of
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
    (zone, [binary()]) -> iodata().
encode_alpn_list(wire, Protocols) ->
    <<<<(byte_size(P)):8, P/binary>> || P <- Protocols>>;
encode_alpn_list(zone, Protocols) ->
    join_with_separator(~",", Protocols).

-spec decode_alpn_list
    (wire, binary()) -> [binary()];
    (zone, string()) -> [binary()].
decode_alpn_list(wire, Bin) when is_binary(Bin) ->
    decode_alpn_wire(Bin);
decode_alpn_list(zone, AlpnStr) when is_list(AlpnStr) ->
    [list_to_binary(string:trim(P)) || P <- string:split(AlpnStr, ",", all), P =/= ""].

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
