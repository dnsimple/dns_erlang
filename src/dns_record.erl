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
-export([serialise/1, serialise/2, deserialise/1, deserialise/2]).

serialise(Bin) when is_binary(Bin) -> serialise(Bin, []);
serialise(Tuple) when is_tuple(Tuple) -> serialise(Tuple, []).

serialise(Term, Opts) when is_list(Opts) ->
    WrapFun = proplists:get_value(wrap_fun, Opts, fun(X) -> X end),
    Term0 =
        case Term of
            Data when is_binary(Data) -> bin_to_hex(Data);
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
serialise(dns_rrdata_dlv, Field, Value, Opts) ->
    serialise(dns_rrdata_ds, Field, Value, Opts);
serialise(dns_rrdata_key, public_key, PublicKey, _Opts) ->
    {<<"public_key">>, base64:encode(iolist_to_binary(PublicKey))};
serialise(dns_rrdata_dnskey, public_key, PublicKey, _Opts) when
    is_binary(PublicKey)
->
    {<<"public_key">>, base64:encode(PublicKey)};
serialise(dns_rrdata_dnskey, public_key, PublicKey, _Opts) ->
    PKMpint = [
        begin
            BI = binary:encode_unsigned(I),
            L = byte_size(BI),
            <<L:32, BI/binary>>
        end
     || I <- PublicKey
    ],
    {<<"public_key">>, base64:encode(iolist_to_binary(PKMpint))};
serialise(dns_rrdata_ds, digest, Digest, _Opts) ->
    {<<"digest">>, bin_to_hex(Digest)};
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
            Salt -> bin_to_hex(Salt)
        end,
    {<<"salt">>, Salt0};
serialise(dns_rrdata_nsec3, hash, Hash, _Opts) ->
    {<<"hash">>, base32:encode(Hash, [hex])};
serialise(dns_rrdata_rrsig, signature, Sig, _Opts) ->
    {<<"signature">>, base64:encode(Sig)};
serialise(dns_rrdata_sshfp, fp, FP, _Opts) ->
    {<<"fp">>, bin_to_hex(FP)};
serialise(dns_rrdata_tsig, mac, MAC, _Opts) ->
    {<<"mac">>, base64:encode(MAC)};
serialise(dns_rrdata_tsig, other, Other, _Opts) ->
    {<<"other">>, bin_to_hex(Other)};
serialise(dns_optrr, data, Datas, Opts) when is_list(Datas) ->
    {<<"data">>, [serialise(D, Opts) || D <- Datas]};
serialise(dns_opt_nsid, data, Data, _Opts) when is_binary(Data) ->
    {<<"data">>, bin_to_hex(Data)};
serialise(dns_opt_owner, Field, Data, _Opts) when is_binary(Data) ->
    {atom_to_binary(Field, utf8), bin_to_hex(Data)};
serialise(dns_opt_ecs, Field, Data, _Opts) when is_binary(Data) ->
    {atom_to_binary(Field, utf8), bin_to_hex(Data)};
serialise(dns_opt_unknown, bin, Bin, _Opts) when is_binary(Bin) ->
    {<<"bin">>, bin_to_hex(Bin)};
serialise(_Tag, Field, Value, _Opts) ->
    {atom_to_binary(Field, utf8), Value}.

deserialise(Term) -> deserialise(Term, []).

deserialise(Term, Opts) ->
    UnwrapFun = proplists:get_value(wrap_fun, Opts, fun(X) -> X end),
    case UnwrapFun(Term) of
        Bin when is_binary(Bin) -> hex_to_bin(Bin);
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

deserialise_dnskey_publickey(PublicKeyB64) ->
    PublicKey = base64:decode(PublicKeyB64),
    deserialise_dnskey_publickey(PublicKey, PublicKey, []).

deserialise_dnskey_publickey(_PK, <<>>, Ints) ->
    lists:reverse(Ints);
deserialise_dnskey_publickey(PK, <<L:32, I:L/unit:8, Rest/binary>>, Ints) ->
    deserialise_dnskey_publickey(PK, Rest, [I | Ints]);
deserialise_dnskey_publickey(PK, _, _) ->
    PK.

deserialise(dns_message, _Field, Terms, Opts) when is_list(Terms) ->
    [deserialise(Term, Opts) || Term <- Terms];
deserialise(dns_rr, data, Term, Opts) ->
    deserialise(Term, Opts);
deserialise(Tag, ip, IP, _Opts) when
    Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa
->
    {ok, Tuple} = inet_parse:address(binary_to_list(IP)),
    Tuple;
deserialise(dns_rrdata_cert, cert, CRL, _Opts) ->
    base64:decode(CRL);
deserialise(dns_rrdata_dhcid, data, Data, _Opts) ->
    base64:decode(Data);
deserialise(dns_rrdata_dlv, Field, Value, _Opts) ->
    deserialise(dns_rrdata_ds, Field, Value, _Opts);
deserialise(dns_rrdata_key, public_key, PublicKeyB64, _Opts) ->
    base64:decode(PublicKeyB64);
deserialise(dns_rrdata_dnskey, public_key, PublicKeyB64, _Opts) ->
    deserialise_dnskey_publickey(PublicKeyB64);
deserialise(dns_rrdata_ds, digest, Digest, _Opts) ->
    hex_to_bin(Digest);
deserialise(dns_rrdata_ipseckey, gateway, Gateway, _Opts) ->
    case inet_parse:address(binary_to_list(Gateway)) of
        {ok, Tuple} -> Tuple;
        {error, einval} -> Gateway
    end;
deserialise(dns_rrdata_ipseckey, public_key, PublicKey, _Opts) ->
    base64:decode(PublicKey);
deserialise(Tag, salt, Salt, _Opts) when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    hex_to_bin(Salt);
deserialise(dns_rrdata_nsec3, hash, Hash, _Opts) ->
    base32:decode(Hash, [hex]);
deserialise(dns_rrdata_rrsig, signature, Sig, _Opts) ->
    base64:decode(Sig);
deserialise(dns_rrdata_sshfp, fp, FP, _Opts) ->
    hex_to_bin(FP);
deserialise(dns_rrdata_tsig, mac, MAC, _Opts) ->
    base64:decode(MAC);
deserialise(dns_rrdata_tsig, other, Other, _Opts) ->
    hex_to_bin(Other);
deserialise(dns_optrr, data, Terms, Opts) ->
    [deserialise(Term, Opts) || Term <- Terms];
deserialise(dns_opt_nsid, data, Data, _Opts) when is_binary(Data) ->
    hex_to_bin(Data);
deserialise(dns_opt_owner, _Field, Data, _Opts) when is_binary(Data) ->
    hex_to_bin(Data);
deserialise(dns_opt_ecs, _Field, Data, _Opts) when is_binary(Data) ->
    hex_to_bin(Data);
deserialise(dns_opt_unknown, bin, Bin, _Opts) when is_binary(Bin) ->
    hex_to_bin(Bin);
deserialise(_Tag, _Field, Value, _Opts) ->
    Value.

%% Internal

bin_to_hex(Bin) when is_binary(Bin) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [V]) || <<V>> <= Bin]).

hex_to_bin(Bin) when is_binary(Bin) ->
    Fun = fun(A, B) ->
        case io_lib:fread("~16u", [A, B]) of
            {ok, [V], []} -> V;
            _ -> error(badarg)
        end
    end,
    <<<<(Fun(A, B))>> || <<A, B>> <= Bin>>.
