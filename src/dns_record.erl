%% -------------------------------------------------------------------
%%
%% Copyright (c) 2012 Andrew Tunnell-Jones. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(dns_record).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
The `dns_record` module exports `serialise` and `deserialise` functions
for serialising and deserialising messages.

You will generally not use these functions directly, rather you will use
the functions for encoding and decoding messages exported by `m:dns`.
""").

-export([serialise/1, serialise/2, deserialise/1, deserialise/2]).

-include_lib("dns_erlang/include/dns.hrl").

?DOC("Module's core type.").
-type t() :: binary() | {binary(), proplists:proplist()}.
?DOC("Options available for serialisation and deserialisation.").
-type opts() :: #{wrap_fun => fun((t()) -> t())}.
-export_type([t/0, opts/0]).

?DOC(#{equiv => serialise(Bin, #{})}).
-spec serialise(binary() | tuple()) -> any().
serialise(Bin) when is_binary(Bin) ->
    serialise(Bin, #{});
serialise(Tuple) when is_tuple(Tuple) ->
    serialise(Tuple, #{}).

?DOC("Serialise a dns record.").
-spec serialise(binary() | tuple(), opts()) -> any().
serialise(Term, Opts) when is_map(Opts) ->
    WrapFun = maps:get(wrap_fun, Opts, fun(X) -> X end),
    Term0 =
        case Term of
            Data when is_binary(Data) -> binary:encode_hex(Data);
            Data when is_tuple(Data) ->
                [Tag | Values] = tuple_to_list(Data),
                Fields = dns_record_info:fields(Tag),
                Fun = fun(Field, Value) ->
                    serialise(Tag, Field, Value, Opts)
                end,
                Proplist = lists:zipwith(Fun, Fields, Values),
                {atom_to_binary(Tag, utf8), Proplist};
            _ ->
                erlang:error(badarg)
        end,
    WrapFun(Term0).

-spec serialise(atom(), atom(), tuple() | [binary() | tuple()], opts()) -> {binary(), _}.
serialise(dns_message, Field, Datas, Opts) when is_list(Datas) ->
    Field0 = atom_to_binary(Field, utf8),
    Datas0 = [serialise(D, Opts) || D <- Datas],
    {Field0, Datas0};
serialise(dns_rr, data, Data, Opts) ->
    {<<"data">>, serialise(Data, Opts)};
serialise(Tag, ip, Tuple, _Opts) when
    Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa
->
    {<<"ip">>, list_to_binary(inet_parse:ntoa(Tuple))};
serialise(dns_rrdata_cert, cert, CRL, _Opts) ->
    {<<"cert">>, base64:encode(CRL)};
serialise(dns_rrdata_dhcid, data, Data, _Opts) ->
    {<<"data">>, base64:encode(Data)};
serialise(dns_rrdata_openpgpkey, data, Data, _Opts) ->
    {<<"data">>, base64:encode(Data)};
serialise(dns_rrdata_wallet, data, Data, _Opts) ->
    {<<"data">>, base64:encode(Data)};
serialise(dns_rrdata_dlv, Field, Value, Opts) ->
    serialise(dns_rrdata_ds, Field, Value, Opts);
serialise(dns_rrdata_key, public_key, PublicKey, _Opts) ->
    {<<"public_key">>, base64:encode(iolist_to_binary(PublicKey))};
serialise(dns_rrdata_dnskey, public_key, PublicKey, _Opts) when is_binary(PublicKey) ->
    {<<"public_key">>, base64:encode(PublicKey)};
serialise(dns_rrdata_dnskey, public_key, PublicKey, _Opts) ->
    PKMpint = lists:map(
        fun(I) ->
            BI = binary:encode_unsigned(I),
            L = byte_size(BI),
            <<L:32, BI/binary>>
        end,
        PublicKey
    ),
    {<<"public_key">>, base64:encode(iolist_to_binary(PKMpint))};
serialise(dns_rrdata_ds, digest, Digest, _Opts) ->
    {<<"digest">>, binary:encode_hex(Digest)};
serialise(dns_rrdata_zonemd, hash, Hash, _Opts) ->
    {<<"hash">>, binary:encode_hex(Hash)};
serialise(dns_rrdata_ipseckey, gateway, Tuple, _Opts) when is_tuple(Tuple) ->
    {<<"gateway">>, list_to_binary(inet_parse:ntoa(Tuple))};
serialise(dns_rrdata_ipseckey, public_key, PublicKey, _Opts) ->
    {<<"public_key">>, base64:encode(PublicKey)};
serialise(Tag, salt, Salt, _Opts) when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    Salt0 =
        case Salt of
            <<>> -> <<$->>;
            Salt -> binary:encode_hex(Salt)
        end,
    {<<"salt">>, Salt0};
serialise(dns_rrdata_nsec3, hash, Hash, _Opts) ->
    {<<"hash">>, base32:encode(Hash, [hex])};
serialise(dns_rrdata_rrsig, signature, Sig, _Opts) ->
    {<<"signature">>, base64:encode(Sig)};
serialise(dns_rrdata_smimea, certificate, Certificate, _Opts) ->
    {<<"certificate">>, base64:encode(Certificate)};
serialise(dns_rrdata_sshfp, fp, FP, _Opts) ->
    {<<"fp">>, binary:encode_hex(FP)};
serialise(dns_rrdata_eui48, address, Address, _Opts) ->
    {<<"address">>, binary:encode_hex(Address)};
serialise(dns_rrdata_eui64, address, Address, _Opts) ->
    {<<"address">>, binary:encode_hex(Address)};
serialise(Tag, svc_params, SvcParams, Opts) when
    Tag =:= dns_rrdata_svcb orelse Tag =:= dns_rrdata_https
->
    SvcParamsList = lists:sort(maps:to_list(SvcParams)),
    SerialisedParams = [
        {dns_names:svcb_param_name(K), serialise_svcb_param_value(K, V, Opts)}
     || {K, V} <- SvcParamsList
    ],
    {<<"svc_params">>, SerialisedParams};
serialise(dns_rrdata_tsig, mac, MAC, _Opts) ->
    {<<"mac">>, base64:encode(MAC)};
serialise(dns_rrdata_tsig, other, Other, _Opts) ->
    {<<"other">>, binary:encode_hex(Other)};
serialise(dns_optrr, data, Datas, Opts) when is_list(Datas) ->
    {<<"data">>, [serialise(D, Opts) || D <- Datas]};
serialise(dns_opt_nsid, data, Data, _Opts) when is_binary(Data) ->
    {<<"data">>, binary:encode_hex(Data)};
serialise(dns_opt_owner, Field, Data, _Opts) when is_binary(Data) ->
    {atom_to_binary(Field, utf8), binary:encode_hex(Data)};
serialise(dns_opt_ecs, Field, Data, _Opts) when is_binary(Data) ->
    {atom_to_binary(Field, utf8), binary:encode_hex(Data)};
serialise(dns_opt_unknown, bin, Bin, _Opts) when is_binary(Bin) ->
    {<<"bin">>, binary:encode_hex(Bin)};
serialise(_Tag, Field, Value, _Opts) ->
    {atom_to_binary(Field, utf8), Value}.

?DOC(#{equiv => deserialise(Bin, #{})}).
-spec deserialise(t()) -> bitstring() | tuple().
deserialise(Term) ->
    deserialise(Term, #{}).

?DOC("Deserialise a given term into a dns record").
-spec deserialise(t(), opts()) -> bitstring() | tuple().
deserialise(Term, Opts) ->
    UnwrapFun = maps:get(wrap_fun, Opts, fun(X) -> X end),
    case UnwrapFun(Term) of
        Bin when is_binary(Bin) -> binary:decode_hex(Bin);
        {TagBin, Props} when is_binary(TagBin) andalso is_list(Props) ->
            Tag = binary_to_existing_atom(TagBin, utf8),
            Fun = fun(Field) ->
                FieldBin = atom_to_binary(Field, utf8),
                Value = proplists:get_value(FieldBin, Props),
                deserialise(Tag, Field, Value, Opts)
            end,
            Values = [Fun(Field) || Field <- dns_record_info:fields(Tag)],
            list_to_tuple([Tag | Values])
    end.

-spec deserialise_dnskey_publickey(binary() | [dns:uint8()]) -> binary() | [integer()].
deserialise_dnskey_publickey(PublicKeyB64) ->
    PublicKey = base64:decode(PublicKeyB64),
    deserialise_dnskey_publickey(PublicKey, PublicKey, []).

-spec deserialise_dnskey_publickey(binary(), binary(), [integer()]) -> binary() | [integer()].
deserialise_dnskey_publickey(_PK, <<>>, Ints) ->
    lists:reverse(Ints);
deserialise_dnskey_publickey(PK, <<L:32, I:L/unit:8, Rest/binary>>, Ints) ->
    deserialise_dnskey_publickey(PK, Rest, [I | Ints]);
deserialise_dnskey_publickey(PK, _, _) ->
    PK.

-spec deserialise(atom(), atom(), tuple() | [binary() | tuple()], opts()) -> any().
deserialise(dns_message, _Field, Terms, Opts) when is_list(Terms) ->
    [deserialise(Term, Opts) || Term <- Terms];
deserialise(dns_rr, data, Term, Opts) ->
    deserialise(Term, Opts);
deserialise(Tag, ip, IP, _Opts) when Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa ->
    {ok, Tuple} = inet_parse:address(binary_to_list(IP)),
    Tuple;
deserialise(dns_rrdata_cert, cert, CRL, _Opts) ->
    base64:decode(CRL);
deserialise(dns_rrdata_dhcid, data, Data, _Opts) ->
    base64:decode(Data);
deserialise(dns_rrdata_openpgpkey, data, Data, _Opts) ->
    base64:decode(Data);
deserialise(dns_rrdata_wallet, data, Data, _Opts) ->
    base64:decode(Data);
deserialise(dns_rrdata_dlv, Field, Value, Opts) ->
    deserialise(dns_rrdata_ds, Field, Value, Opts);
deserialise(dns_rrdata_key, public_key, PublicKeyB64, _Opts) ->
    base64:decode(PublicKeyB64);
deserialise(dns_rrdata_dnskey, public_key, PublicKeyB64, _Opts) ->
    deserialise_dnskey_publickey(PublicKeyB64);
deserialise(dns_rrdata_ds, digest, Digest, _Opts) ->
    binary:decode_hex(Digest);
deserialise(dns_rrdata_zonemd, hash, Hash, _Opts) ->
    binary:decode_hex(Hash);
deserialise(dns_rrdata_ipseckey, gateway, Gateway, _Opts) ->
    case inet_parse:address(binary_to_list(Gateway)) of
        {ok, Tuple} -> Tuple;
        {error, einval} -> Gateway
    end;
deserialise(dns_rrdata_ipseckey, public_key, PublicKey, _Opts) ->
    base64:decode(PublicKey);
deserialise(Tag, salt, <<"-">>, _Opts) when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    <<>>;
deserialise(Tag, salt, Salt, _Opts) when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    binary:decode_hex(Salt);
deserialise(dns_rrdata_nsec3, hash, Hash, _Opts) ->
    base32:decode(Hash, [hex]);
deserialise(dns_rrdata_rrsig, signature, Sig, _Opts) ->
    base64:decode(Sig);
deserialise(dns_rrdata_smimea, certificate, Certificate, _Opts) ->
    base64:decode(Certificate);
deserialise(dns_rrdata_sshfp, fp, FP, _Opts) ->
    binary:decode_hex(FP);
deserialise(dns_rrdata_eui48, address, Address, _Opts) ->
    binary:decode_hex(Address);
deserialise(dns_rrdata_eui64, address, Address, _Opts) ->
    binary:decode_hex(Address);
deserialise(Tag, svc_params, SvcParamsList, Opts) when
    Tag =:= dns_rrdata_svcb orelse Tag =:= dns_rrdata_https
->
    DeserialisedParams = [
        {
            dns_names:name_svcb_param(K),
            deserialise_svcb_param_value(dns_names:name_svcb_param(K), V, Opts)
        }
     || {K, V} <- SvcParamsList
    ],
    maps:from_list(DeserialisedParams);
deserialise(dns_rrdata_tsig, mac, MAC, _Opts) ->
    base64:decode(MAC);
deserialise(dns_rrdata_tsig, other, Other, _Opts) ->
    binary:decode_hex(Other);
deserialise(dns_optrr, data, Terms, Opts) ->
    [deserialise(Term, Opts) || Term <- Terms];
deserialise(dns_opt_nsid, data, Data, _Opts) when is_binary(Data) ->
    binary:decode_hex(Data);
deserialise(dns_opt_owner, _Field, Data, _Opts) when is_binary(Data) ->
    binary:decode_hex(Data);
deserialise(dns_opt_ecs, _Field, Data, _Opts) when is_binary(Data) ->
    binary:decode_hex(Data);
deserialise(dns_opt_unknown, bin, Bin, _Opts) when is_binary(Bin) ->
    binary:decode_hex(Bin);
deserialise(_Tag, _Field, Value, _Opts) ->
    Value.

%% Helper functions for SVCB/HTTPS svc_params serialization
serialise_svcb_param_value(?DNS_SVCB_PARAM_MANDATORY, Value, _Opts) when is_list(Value) ->
    %% List of parameter key codes (integers)
    [integer_to_binary(V, 10) || V <- Value];
serialise_svcb_param_value(?DNS_SVCB_PARAM_ALPN, Value, _Opts) when is_list(Value) ->
    %% List of protocol name binaries
    [base64:encode(V) || V <- Value];
serialise_svcb_param_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none, _Opts) ->
    <<"none">>;
serialise_svcb_param_value(?DNS_SVCB_PARAM_PORT, Value, _Opts) when is_integer(Value) ->
    integer_to_binary(Value, 10);
serialise_svcb_param_value(?DNS_SVCB_PARAM_IPV4HINT, Value, _Opts) when is_list(Value) ->
    %% List of IPv4 address tuples
    [list_to_binary(inet_parse:ntoa(V)) || V <- Value];
serialise_svcb_param_value(?DNS_SVCB_PARAM_ECH, Value, _Opts) when is_binary(Value) ->
    base64:encode(Value);
serialise_svcb_param_value(?DNS_SVCB_PARAM_IPV6HINT, Value, _Opts) when is_list(Value) ->
    %% List of IPv6 address tuples
    [list_to_binary(inet_parse:ntoa(V)) || V <- Value];
serialise_svcb_param_value(_Key, Value, _Opts) when is_binary(Value) ->
    %% Unknown parameter - base64 encode binary values
    base64:encode(Value);
serialise_svcb_param_value(_Key, Value, _Opts) ->
    %% Fallback for unknown types
    Value.

deserialise_svcb_param_value(?DNS_SVCB_PARAM_MANDATORY, Value, _Opts) when is_list(Value) ->
    %% List of parameter key code strings -> integers
    [binary_to_integer(V) || V <- Value];
deserialise_svcb_param_value(?DNS_SVCB_PARAM_ALPN, Value, _Opts) when is_list(Value) ->
    %% List of base64-encoded protocol names -> binaries
    [base64:decode(V) || V <- Value];
deserialise_svcb_param_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, <<"none">>, _Opts) ->
    none;
deserialise_svcb_param_value(?DNS_SVCB_PARAM_PORT, Value, _Opts) when is_binary(Value) ->
    binary_to_integer(Value);
deserialise_svcb_param_value(?DNS_SVCB_PARAM_IPV4HINT, Value, _Opts) when is_list(Value) ->
    %% List of IP address strings -> IPv4 tuples
    [
        element(2, inet_parse:address(binary_to_list(V)))
     || V <- Value
    ];
deserialise_svcb_param_value(?DNS_SVCB_PARAM_ECH, Value, _Opts) when is_binary(Value) ->
    base64:decode(Value);
deserialise_svcb_param_value(?DNS_SVCB_PARAM_IPV6HINT, Value, _Opts) when is_list(Value) ->
    %% List of IP address strings -> IPv6 tuples
    [
        element(2, inet_parse:address(binary_to_list(V)))
     || V <- Value
    ];
deserialise_svcb_param_value(_Key, Value, _Opts) when is_binary(Value) ->
    %% Unknown parameter - try base64 decode
    try
        base64:decode(Value)
    catch
        _:_ -> Value
    end;
deserialise_svcb_param_value(_Key, Value, _Opts) ->
    %% Fallback for unknown types
    Value.
