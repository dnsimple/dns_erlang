%% -------------------------------------------------------------------
%%
%% Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.
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
-module(dnssec).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
The `dnssec` module exports functions used for generating NSEC responses,
signing and verifying RRSIGs, and adding keytags to DNSKEY records.

For example, the `sign_rr/6` function can be given a collection of resource records,
the signer name, keytag, signing algorithm, private key, and a collection of options
and it will return a list of RRSIG records. Currently only DSA and RSA algorithms are
supported for signing RRSETs.
""").

%% API
-export([gen_nsec/1, gen_nsec/3, gen_nsec/4]).
-export([gen_nsec3/1, gen_nsec3/2]).
-export([sign_rr/5, sign_rr/6]).
-export([sign_rrset/5, sign_rrset/6]).
-export([verify_rrsig/4]).
-export([add_keytag_to_dnskey/1, add_keytag_to_cdnskey/1]).
-export([canonical_rrdata_form/1]).
-export([ih/4]).

%% Private
-ifdef(TEST).
-export([normalise_dname/1]).
-endif.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("dns_erlang/include/DNS-ASN1.hrl").

-export_type([
    sigalg/0,
    nsec3_hashalg/0,
    nsec3_hashalg_fun/0,
    nsec3_salt/0,
    nsec3_iterations/0,
    gen_nsec_opts/0,
    gen_nsec3_opts/0,
    sign_rr_opts/0,
    verify_rrsig_opts/0,
    keytag/0,
    key/0
]).
%% this isn't a redefinition of dns:alg() - the algorithms here may only be used
%% for signing zones. dns:alg() may contain other algorithms.
-type sigalg() ::
    ?DNS_ALG_DSA
    | ?DNS_ALG_NSEC3DSA
    | ?DNS_ALG_RSASHA1
    | ?DNS_ALG_NSEC3RSASHA1
    | ?DNS_ALG_RSASHA256
    | ?DNS_ALG_RSASHA512
    | ?DNS_ALG_ECDSAP256SHA256.
-type nsec3_hashalg() :: ?DNSSEC_NSEC3_ALG_SHA1.
-type nsec3_hashalg_fun() :: fun((iodata()) -> binary()).
-type nsec3_salt() :: binary().
-type nsec3_iterations() :: non_neg_integer().
-type gen_nsec_opts() :: #{base_types => [dns:type()]}.
-type gen_nsec3_opts() :: gen_nsec_opts().
-type keytag() :: integer().
-type key() :: [binary()].
-type sign_rr_opts() :: #{inception => dns:unix_time(), expiration => dns:unix_time()}.
-type verify_rrsig_opts() :: #{now => dns:unix_time()}.

-define(RSASHA1_PREFIX,
    <<16#30, 16#21, 16#30, 16#09, 16#06, 16#05, 16#2B, 16#0E, 16#03, 16#02, 16#1A, 16#05, 16#00,
        16#04, 16#14>>
).
-define(RSASHA256_PREFIX,
    <<16#30, 16#31, 16#30, 16#0d, 16#06, 16#09, 16#60, 16#86, 16#48, 16#01, 16#65, 16#03, 16#04,
        16#02, 16#01, 16#05, 16#00, 16#04, 16#20>>
).
-define(RSASHA512_PREFIX,
    <<16#30, 16#51, 16#30, 16#0d, 16#06, 16#09, 16#60, 16#86, 16#48, 16#01, 16#65, 16#03, 16#04,
        16#02, 16#03, 16#05, 16#00, 16#04, 16#40>>
).

-define(SECS_IN_YEAR, (365 * 24 * 60 * 60)).

?DOC("""
Generate NSEC records from a list of `t:dns:rr/0`.

The list must contain a SOA `t:dns:rr/0` which is used to determine zone name and TTL.
""").
-spec gen_nsec([dns:rr()]) -> [dns:rr()].
gen_nsec(RR) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RR) of
        false ->
            erlang:error(badarg);
        #dns_rr{name = ZoneName, data = #dns_rrdata_soa{minimum = TTL}} ->
            gen_nsec(ZoneName, RR, TTL)
    end.

?DOC(#{equiv => gen_nsec(ZoneName, RR, TTL, #{})}).
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl()) -> [dns:rr()].
gen_nsec(ZoneName, RR, TTL) ->
    gen_nsec(ZoneName, RR, TTL, #{}).

?DOC("Generate NSEC records.").
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl(), gen_nsec_opts()) -> [dns:rr()].
gen_nsec(ZoneNameM, RR, TTL, Opts) ->
    ZoneName = normalise_dname(ZoneNameM),
    BaseTypes = maps:get(base_types, Opts, [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]),
    Map = build_rrmap(RR, BaseTypes),
    Unsorted = [
        #dns_rr{
            name = Name,
            class = Class,
            type = ?DNS_TYPE_NSEC,
            ttl = TTL,
            data = #dns_rrdata_nsec{next_dname = Name, types = Types}
        }
     || {{Name, Class}, Types} <- Map
    ],
    Sorted = name_order(Unsorted),
    add_next_dname([], Sorted, ZoneName).

-spec add_next_dname([dns:rr()], [dns:rr(), ...], binary()) -> [dns:rr(), ...].
add_next_dname(Added, [#dns_rr{data = Data} = RR | [#dns_rr{name = Next} | _] = ToAdd], ZoneName) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec{next_dname = Next}},
    NewAdded = [NewRR | Added],
    add_next_dname(NewAdded, ToAdd, ZoneName);
add_next_dname(Added, [#dns_rr{type = ?DNS_TYPE_NSEC, data = Data} = RR], ZoneName) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec{next_dname = ZoneName}},
    lists:reverse([NewRR | Added]).

?DOC(#{equiv => gen_nsec3(RRs, #{})}).
-spec gen_nsec3([dns:rr()]) -> [dns:rr()].
gen_nsec3(RRs) ->
    gen_nsec3(RRs, #{}).

?DOC("""
Generate NSEC3 records from a list of `t:dns:rr/0`.

The list must contain a SOA `t:dns:rr/0` to source the zone name and
TTL from as well as as an NSEC3Param `t:dns:rr/0` to source the
hash algorithm, iterations and salt from.
""").
-spec gen_nsec3([dns:rr()], gen_nsec3_opts()) -> [dns:rr()].
gen_nsec3(RRs, Opts) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RRs) of
        false ->
            erlang:error(badarg);
        #dns_rr{name = ZoneName, data = #dns_rrdata_soa{minimum = TTL}} ->
            case lists:keyfind(?DNS_TYPE_NSEC3PARAM, #dns_rr.type, RRs) of
                false ->
                    erlang:error(badarg);
                #dns_rr{
                    class = Class,
                    data = #dns_rrdata_nsec3param{
                        hash_alg = HashAlg,
                        iterations = Iter,
                        salt = Salt
                    }
                } ->
                    gen_nsec3(RRs, ZoneName, HashAlg, Salt, Iter, TTL, Class, Opts)
            end
    end.

?DOC("Generate NSEC3 records.").
-spec gen_nsec3(
    [dns:rr()],
    dns:dname(),
    nsec3_hashalg(),
    nsec3_salt(),
    nsec3_iterations(),
    dns:ttl(),
    dns:class(),
    gen_nsec3_opts()
) -> [dns:rr()].
gen_nsec3(RRs, ZoneName, Alg, Salt, Iterations, TTL, Class, Opts) ->
    BaseTypes = maps:get(base_types, Opts, [?DNS_TYPE_RRSIG]),
    Map = build_rrmap(RRs, BaseTypes, ZoneName),
    Unsorted = lists:foldl(
        fun
            ({{Name, SClass}, Types}, Acc) when SClass =:= Class ->
                DName = dns_encode:encode_dname(Name),
                HashedName = ih(Alg, Salt, DName, Iterations),
                HexdHashName = base32:encode(HashedName, [hex, nopad]),
                NewName = <<HexdHashName/binary, $., ZoneName/binary>>,
                Data = #dns_rrdata_nsec3{
                    hash_alg = Alg,
                    opt_out = false,
                    iterations = Iterations,
                    salt = Salt,
                    hash = HashedName,
                    types = Types
                },
                NewRR = #dns_rr{
                    name = NewName,
                    class = Class,
                    type = ?DNS_TYPE_NSEC3,
                    ttl = TTL,
                    data = Data
                },
                [{HashedName, NewRR} | Acc];
            (_, Acc) ->
                Acc
        end,
        [],
        Map
    ),
    Sorted = [RR || {_, RR} <- lists:keysort(1, Unsorted)],
    add_next_hash(Sorted).

?DOC("NSEC3 iterative hash function").
-spec ih(nsec3_hashalg() | nsec3_hashalg_fun(), nsec3_salt(), binary(), nsec3_iterations()) ->
    binary().
ih(?DNSSEC_NSEC3_ALG_SHA1, Salt, X, I) when is_binary(Salt), is_binary(X), is_integer(I), 0 =< I ->
    ih_nsec3(Salt, X, I);
ih(H, Salt, X, I) when is_function(H, 1), is_binary(Salt), is_binary(X), is_integer(I), 0 =< I ->
    ih_nsec3_custom(H, Salt, X, I).

%% Optimise for the common case
-spec ih_nsec3(nsec3_salt(), binary(), nsec3_iterations()) -> binary().
ih_nsec3(Salt, X, 0) ->
    crypto:hash(sha, [X, Salt]);
ih_nsec3(Salt, X, I) ->
    ih_nsec3(Salt, crypto:hash(sha, [X, Salt]), I - 1).

-spec ih_nsec3_custom(fun((iodata()) -> binary()), nsec3_salt(), binary(), nsec3_iterations()) ->
    binary().
ih_nsec3_custom(H, Salt, X, 0) ->
    H([X, Salt]);
ih_nsec3_custom(H, Salt, X, I) ->
    ih_nsec3_custom(H, Salt, H([X, Salt]), I - 1).

-spec add_next_hash([dns:rr(), ...]) -> [dns:rr(), ...].
add_next_hash([#dns_rr{data = #dns_rrdata_nsec3{hash = First}} | _] = Hashes) ->
    add_next_hash(Hashes, [], First).

-spec add_next_hash([dns:rr(), ...], [dns:rr()], _) -> [dns:rr(), ...].
add_next_hash([#dns_rr{data = Data} = RR], RRs, FirstHash) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec3{hash = FirstHash}},
    lists:reverse([NewRR | RRs]);
add_next_hash(
    [
        #dns_rr{data = Data} = RR
        | [#dns_rr{data = #dns_rrdata_nsec3{hash = NextHash}} | _] = Hashes
    ],
    RRs,
    FirstHash
) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec3{hash = NextHash}},
    add_next_hash(Hashes, [NewRR | RRs], FirstHash).

-spec normalise_rr(dns:rr()) -> dns:rr().
normalise_rr(#dns_rr{name = Name} = RR) ->
    RR#dns_rr{name = dns:dname_to_lower(Name)}.

-spec build_rrmap([dns:rr()], [integer()]) -> [{_, _}].
build_rrmap(RR, BaseTypes) ->
    Base = build_rrmap_gbt(RR, BaseTypes),
    maps:to_list(Base).

-spec build_rrmap([dns:rr()], [integer()], _) -> [{_, _}].
build_rrmap(RR, BaseTypes, ZoneName) ->
    Base = build_rrmap_gbt(RR, BaseTypes),
    WithNonTerm = build_rrmap_nonterm(ZoneName, maps:keys(Base), Base),
    maps:to_list(WithNonTerm).

-spec build_rrmap_nonterm(_, [{dns:dname(), dns:class()} | binary()], #{
    {dns:dname(), dns:class()} => [integer()]
}) ->
    #{{dns:dname(), dns:class()} => [integer()]}.
build_rrmap_nonterm(_, [], Map) ->
    Map;
build_rrmap_nonterm(ZoneName, [{Name, Class} | Rest], Map) when is_binary(ZoneName) ->
    NameAncs = name_ancestors(Name, ZoneName),
    NewMap = build_rrmap_nonterm(Class, NameAncs, Map),
    build_rrmap_nonterm(ZoneName, Rest, NewMap);
build_rrmap_nonterm(Class, [Name | Rest], Map) ->
    Key = {Name, Class},
    case maps:is_key(Key, Map) of
        true ->
            Map;
        false ->
            NewMap = Map#{Key => []},
            build_rrmap_nonterm(Class, Rest, NewMap)
    end.

-spec build_rrmap_gbt([dns:rr()], [integer()]) -> #{{dns:dname(), dns:class()} => [integer()]}.
build_rrmap_gbt(RR, BaseTypes) ->
    build_rrmap_gbt(RR, BaseTypes, #{}).

-spec build_rrmap_gbt([dns:rr()], [integer()], #{{dns:dname(), dns:class()} => [integer()]}) ->
    #{{dns:dname(), dns:class()} => [integer()]}.
build_rrmap_gbt([], _BaseTypes, Map) ->
    Map;
build_rrmap_gbt([#dns_rr{} = RR | Rest], BaseTypes, Map) ->
    #dns_rr{name = Name, class = Class, type = Type} = normalise_rr(RR),
    Key = {Name, Class},
    NewMap = maps:update_with(
        Key,
        fun(Types) ->
            case lists:member(Type, Types) of
                true -> Types;
                false -> [Type | Types]
            end
        end,
        [Type | BaseTypes],
        Map
    ),
    build_rrmap_gbt(Rest, BaseTypes, NewMap).

-type tree_key() :: {dns:dname(), dns:class(), dns:type()}.

-spec rrs_to_rrsets([dns:rr()]) -> [[dns:rr()]].
rrs_to_rrsets(RR) when is_list(RR) ->
    rrs_to_rrsets(RR, #{}, #{}).

-spec rrs_to_rrsets([dns:rr()], #{tree_key() => dns:ttl()}, #{tree_key() => [dns:rrdata()]}) ->
    [[dns:rr()]].
rrs_to_rrsets([], TTLMap, RRSets) ->
    [rrs_to_rrsets(TTLMap, RRSet) || RRSet <- maps:to_list(RRSets)];
rrs_to_rrsets([#dns_rr{} = RR | RRs], TTLMap, RRSets) ->
    #dns_rr{
        name = Name,
        class = Class,
        type = Type,
        ttl = TTL,
        data = Data
    } = normalise_rr(RR),
    Key = {Name, Class, Type},
    NewTTLMap = maps:update_with(Key, fun(OldTTL) -> max(OldTTL, TTL) end, TTL, TTLMap),
    NewRRSets = maps:update_with(Key, fun(OldData) -> [Data | OldData] end, [Data], RRSets),
    rrs_to_rrsets(RRs, NewTTLMap, NewRRSets).

-spec rrs_to_rrsets(#{tree_key() => dns:ttl()}, {tree_key(), [dns:rrdata()]}) ->
    [dns:rr()].
rrs_to_rrsets(TTLMap, {{Name, Class, Type} = Key, Datas}) ->
    TTL = maps:get(Key, TTLMap),
    [
        #dns_rr{
            name = Name,
            class = Class,
            type = Type,
            ttl = TTL,
            data = Data
        }
     || Data <- Datas
    ].

?DOC(#{equiv => sign_rr(RR, SignerName, KeyTag, Alg, Key, [])}).
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key) ->
    sign_rr(RR, SignerName, KeyTag, Alg, Key, #{}).

?DOC("Signs a list of `t:dns:rr/0`.").
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key(), sign_rr_opts()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key, Opts) when is_map(Opts) ->
    RRSets = rrs_to_rrsets(RR),
    [
        sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, Opts)
     || RRSet <- RRSets
    ].

?DOC(#{equiv => sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, [])}).
-spec sign_rrset([dns:rr(), ...], dns:dname(), keytag(), sigalg(), key()) ->
    dns:rr().
sign_rrset(RRSet, SignerName, KeyTag, Alg, Key) ->
    sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, #{}).

?DOC("Signs a list of `t:dns:rr/0` of the same class and type.").
-spec sign_rrset([dns:rr(), ...], dns:dname(), keytag(), sigalg(), key(), sign_rr_opts()) ->
    dns:rr().
sign_rrset(
    [#dns_rr{name = Name, class = Class, ttl = TTL} | _] = RRs,
    SignersName,
    KeyTag,
    Alg,
    Key,
    Opts
) when is_integer(Alg) ->
    Now = erlang:system_time(second),
    Incept = maps:get(inception, Opts, Now),
    %% 1 year
    Expire = maps:get(expiration, Opts, Now + ?SECS_IN_YEAR),
    {Data0, BaseSigInput} = build_sig_input(
        SignersName,
        KeyTag,
        Alg,
        Incept,
        Expire,
        RRs
    ),
    Signature = sign(Alg, BaseSigInput, Key),
    Data = Data0#dns_rrdata_rrsig{signature = Signature},
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RRSIG,
        class = Class,
        ttl = TTL,
        data = Data
    }.

-spec sign(sigalg(), binary(), key()) -> binary().
sign(Alg, BaseSigInput, Key) when Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA ->
    Asn1Sig = crypto:sign(dss, sha, BaseSigInput, Key),
    {R, S} = decode_asn1_dss_sig(Asn1Sig),
    [P, _Q, _G, _Y] = Key,
    T = (byte_size(P) - 64) div 8,
    <<T, R:20/unit:8, S:20/unit:8>>;
sign(Alg, BaseSigInput, Key) when
    Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    crypto:sign(
        rsa,
        none,
        BaseSigInput,
        Key,
        [{rsa_padding, rsa_pkcs1_padding}]
    ).

?DOC("Provides primitive verification of an RR set.").
-spec verify_rrsig(dns:rr(), [dns:rr()], [dns:rr()], verify_rrsig_opts()) -> boolean().
verify_rrsig(#dns_rr{type = ?DNS_TYPE_RRSIG, data = Data}, RRs, RRDNSKey, Opts) ->
    Now = maps:get(now, Opts, erlang:system_time(second)),
    #dns_rrdata_rrsig{
        original_ttl = OTTL,
        keytag = SigKeyTag,
        alg = SigAlg,
        inception = Incept,
        expiration = Expire,
        signers_name = SignersName,
        signature = Signature
    } = Data,
    Keys0 = [
        {KeyTag, Alg, PubKey}
     || #dns_rr{
            name = Name,
            type = ?DNS_TYPE_DNSKEY,
            data = #dns_rrdata_dnskey{
                protocol = 3,
                alg = Alg,
                keytag = KeyTag,
                public_key = PubKey
            }
        } <- RRDNSKey,
        Alg =:= SigAlg,
        normalise_dname(Name) =:= normalise_dname(SignersName)
    ],
    Keys =
        case lists:keytake(SigKeyTag, 1, Keys0) of
            false -> Keys0;
            {value, Match, RemKeys} -> [Match | RemKeys]
        end,
    case Now of
        Now when Incept > Now -> false;
        Now when Expire < Now -> false;
        Now ->
            {_SigTuple, SigInput} = build_sig_input(
                SignersName,
                SigKeyTag,
                SigAlg,
                Incept,
                Expire,
                RRs,
                OTTL
            ),
            lists:any(fun({_KeyTag, Alg, Key}) -> verify(Alg, Key, Signature, SigInput) end, Keys)
    end.

-spec verify(sigalg(), key(), binary(), binary()) -> boolean().
verify(Alg, Key, Signature, SigInput) when
    Alg =:= ?DNS_ALG_DSA orelse
        Alg =:= ?DNS_ALG_NSEC3DSA
->
    <<_T, R:20/unit:8, S:20/unit:8>> = Signature,
    AsnSig = encode_asn1_dss_sig(R, S),
    AsnSigSize = byte_size(AsnSig),
    AsnBin = <<AsnSigSize:32, AsnSig/binary>>,
    crypto:verify(dss, sha, SigInput, AsnBin, Key);
verify(Alg, Key, Signature, SigInput) when
    Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    try
        crypto:verify(
            rsa,
            none,
            SigInput,
            Signature,
            Key,
            [{rsa_padding, rsa_pkcs1_padding}]
        )
    catch
        error:decrypt_failed -> false
    end.

-spec build_sig_input(binary(), integer(), dns:alg(), integer(), integer(), [dns:rr(), ...]) ->
    {dns:rrdata_rrsig(), binary()}.
build_sig_input(
    SignersName,
    KeyTag,
    Alg,
    Incept,
    Expire,
    [#dns_rr{ttl = TTL} | _] = RRs
) ->
    build_sig_input(SignersName, KeyTag, Alg, Incept, Expire, RRs, TTL).

-spec build_sig_input(
    binary(), integer(), dns:alg(), integer(), integer(), [dns:rr(), ...], non_neg_integer()
) ->
    {dns:rrdata_rrsig(), binary()}.
build_sig_input(
    SignersName,
    KeyTag,
    Alg,
    Incept,
    Expire,
    [
        #dns_rr{
            name = Name,
            class = Class,
            type = Type,
            ttl = TTL
        }
        | _
    ] = RRs,
    TTL
) when is_integer(Alg) ->
    Datas = lists:sort([canonical_rrdata_bin(RR) || RR <- RRs]),
    NameBin = dns_encode:encode_dname(dns:dname_to_lower(Name)),
    RecordBase = <<NameBin/binary, Type:16, Class:16, TTL:32>>,
    RRSetBin = [
        <<RecordBase/binary, (byte_size(Data)):16, Data/binary>>
     || Data <- Datas
    ],
    RRSigData = #dns_rrdata_rrsig{
        type_covered = Type,
        alg = Alg,
        labels = count_labels(Name),
        original_ttl = TTL,
        inception = Incept,
        expiration = Expire,
        keytag = KeyTag,
        signers_name = SignersName
    },
    RRSigRDataBin = rrsig_to_digestable(RRSigData),
    SigInput0 = [RRSigRDataBin, RRSetBin],
    SigInput = preprocess_sig_input(Alg, SigInput0),
    {RRSigData, SigInput}.

-spec preprocess_sig_input(sigalg(), [binary() | [binary()]]) -> binary().
preprocess_sig_input(Alg, SigInput) when Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA ->
    NewSigInput = iolist_to_binary(SigInput),
    NewSigInputSize = byte_size(NewSigInput),
    <<NewSigInputSize:32, NewSigInput/binary>>;
preprocess_sig_input(Alg, SigInput) when
    Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    {Prefix, HashType} = choose_sha_prefix_and_type(Alg),
    Hash = crypto:hash(HashType, SigInput),
    <<Prefix/binary, Hash/binary>>;
preprocess_sig_input(?DNS_ALG_ECDSAP256SHA256, SigInput) ->
    crypto:hash(sha256, SigInput).

-spec choose_sha_prefix_and_type(sigalg()) -> {binary(), sha | sha256 | sha512}.
choose_sha_prefix_and_type(?DNS_ALG_RSASHA1) ->
    {?RSASHA1_PREFIX, sha};
choose_sha_prefix_and_type(?DNS_ALG_NSEC3RSASHA1) ->
    {?RSASHA1_PREFIX, sha};
choose_sha_prefix_and_type(?DNS_ALG_RSASHA256) ->
    {?RSASHA256_PREFIX, sha256};
choose_sha_prefix_and_type(?DNS_ALG_RSASHA512) ->
    {?RSASHA512_PREFIX, sha512}.

?DOC("Generates and appends a DNS Key records key tag.").
-spec add_keytag_to_dnskey(dns:rr()) -> dns:rr().
add_keytag_to_dnskey(
    #dns_rr{
        type = ?DNS_TYPE_DNSKEY,
        data = #dns_rrdata_dnskey{} = Data
    } = RR
) ->
    KeyBin = dns_encode:encode_rrdata(in, Data),
    NewData = dns_decode:decode_rrdata(KeyBin, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY),
    RR#dns_rr{data = NewData}.

-spec add_keytag_to_cdnskey(dns:rr()) -> dns:rr().
add_keytag_to_cdnskey(
    #dns_rr{
        type = ?DNS_TYPE_CDNSKEY,
        data = #dns_rrdata_cdnskey{} = Data
    } = RR
) ->
    KeyBin = dns_encode:encode_rrdata(in, Data),
    NewData = dns_decode:decode_rrdata(KeyBin, ?DNS_CLASS_IN, ?DNS_TYPE_CDNSKEY),
    RR#dns_rr{data = NewData}.

-spec rrsig_to_digestable(dns:rrdata_rrsig()) -> binary().
rrsig_to_digestable(#dns_rrdata_rrsig{} = Data) ->
    dns_encode:encode_rrdata(?DNS_CLASS_IN, Data#dns_rrdata_rrsig{signature = <<>>}).

-spec canonical_rrdata_bin(dns:rr()) -> binary().
canonical_rrdata_bin(#dns_rr{class = Class, data = Data0}) ->
    dns_encode:encode_rrdata(Class, canonical_rrdata_form(Data0)).

?DOC("Converts a resource record data record to DNSSEC canonical form.").
-spec canonical_rrdata_form(dns:rrdata()) -> dns:rrdata().
canonical_rrdata_form(#dns_rrdata_afsdb{hostname = Hostname} = Data) ->
    Data#dns_rrdata_afsdb{hostname = dns:dname_to_lower(Hostname)};
canonical_rrdata_form(#dns_rrdata_cname{dname = DName} = Data) ->
    Data#dns_rrdata_cname{dname = dns:dname_to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_dname{dname = DName} = Data) ->
    Data#dns_rrdata_dname{dname = dns:dname_to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_kx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_kx{exchange = dns:dname_to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_mb{madname = MaDname} = Data) ->
    Data#dns_rrdata_mb{madname = dns:dname_to_lower(MaDname)};
canonical_rrdata_form(#dns_rrdata_mg{madname = MaDname} = Data) ->
    Data#dns_rrdata_mg{madname = dns:dname_to_lower(MaDname)};
canonical_rrdata_form(
    #dns_rrdata_minfo{
        rmailbx = RmailBx,
        emailbx = EmailBx
    } = Data
) ->
    Data#dns_rrdata_minfo{
        rmailbx = dns:dname_to_lower(RmailBx),
        emailbx = dns:dname_to_lower(EmailBx)
    };
canonical_rrdata_form(#dns_rrdata_mr{newname = NewName} = Data) ->
    Data#dns_rrdata_mr{newname = dns:dname_to_lower(NewName)};
canonical_rrdata_form(#dns_rrdata_mx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_mx{exchange = dns:dname_to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_naptr{replacement = Replacement} = Data) ->
    Data#dns_rrdata_naptr{replacement = dns:dname_to_lower(Replacement)};
canonical_rrdata_form(#dns_rrdata_ns{dname = DName} = Data) ->
    Data#dns_rrdata_ns{dname = dns:dname_to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_nsec{next_dname = NextDname} = Data) ->
    Data#dns_rrdata_nsec{next_dname = dns:dname_to_lower(NextDname)};
canonical_rrdata_form(#dns_rrdata_nxt{dname = DName} = Data) ->
    Data#dns_rrdata_nxt{dname = dns:dname_to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_ptr{dname = DName} = Data) ->
    Data#dns_rrdata_ptr{dname = dns:dname_to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_rp{mbox = Mbox, txt = Txt} = Data) ->
    Data#dns_rrdata_rp{
        mbox = dns:dname_to_lower(Mbox),
        txt = dns:dname_to_lower(Txt)
    };
canonical_rrdata_form(#dns_rrdata_rrsig{signers_name = SignersName} = Data) ->
    Data#dns_rrdata_rrsig{signers_name = dns:dname_to_lower(SignersName)};
canonical_rrdata_form(#dns_rrdata_rt{host = Host} = Data) ->
    Data#dns_rrdata_rt{host = dns:dname_to_lower(Host)};
canonical_rrdata_form(#dns_rrdata_soa{mname = Mname, rname = Rname} = Data) ->
    Data#dns_rrdata_soa{
        mname = dns:dname_to_lower(Mname),
        rname = dns:dname_to_lower(Rname)
    };
canonical_rrdata_form(#dns_rrdata_srv{target = Target} = Data) ->
    Data#dns_rrdata_srv{target = dns:dname_to_lower(Target)};
canonical_rrdata_form(X) ->
    X.

-spec name_ancestors(iodata(), iodata()) -> binary() | [binary()].
name_ancestors(Name, ZoneName) ->
    NameLwr = dns:dname_to_lower(iolist_to_binary(Name)),
    ZoneNameLwr = dns:dname_to_lower(iolist_to_binary(ZoneName)),
    gen_name_ancestors(NameLwr, ZoneNameLwr).

-spec gen_name_ancestors(binary() | [binary()], binary() | [binary(), ...]) ->
    binary() | [binary()].
gen_name_ancestors(ZoneName, ZoneName) when is_binary(ZoneName) -> [];
gen_name_ancestors(Name, ZoneName) when
    is_binary(Name) andalso
        is_binary(ZoneName) andalso
        (byte_size(Name) > byte_size(ZoneName) + 1)
->
    Offset = byte_size(Name) - byte_size(ZoneName) - 1,
    case Name of
        <<RelName:Offset/binary, $., ZoneName/binary>> ->
            case dns:dname_to_labels(RelName) of
                [_] ->
                    [];
                [_ | Labels0] ->
                    [FirstLabel | Labels] = lists:reverse(Labels0),
                    gen_name_ancestors(Labels, [<<FirstLabel/binary, $., ZoneName/binary>>])
            end;
        _ ->
            erlang:error(name_mismatch)
    end;
gen_name_ancestors([], Anc) ->
    Anc;
gen_name_ancestors([Label | Labels], [Parent | _] = Asc) ->
    NewName = <<Label/binary, $., Parent/binary>>,
    gen_name_ancestors(Labels, [NewName | Asc]).

-spec name_order([dns:rr(), ...]) -> [dns:rr(), ...].
name_order(RRs) when is_list(RRs) ->
    lists:sort(fun name_order/2, RRs).

-spec name_order(_, _) -> boolean().
name_order(X, X) ->
    true;
name_order(#dns_rr{name = X}, #dns_rr{name = X}) ->
    true;
name_order(#dns_rr{name = A}, #dns_rr{name = B}) ->
    LabelsA = lists:reverse(normalise_dname_to_labels(A)),
    LabelsB = lists:reverse(normalise_dname_to_labels(B)),
    name_order(LabelsA, LabelsB);
name_order([X | A], [X | B]) ->
    name_order(A, B);
name_order([], [_ | _]) ->
    true;
name_order([_ | _], []) ->
    false;
name_order([X | _], [Y | _]) ->
    X < Y.

-spec count_labels(binary()) -> non_neg_integer().
count_labels(Name) ->
    Labels = normalise_dname_to_labels(Name),
    do_count_labels(Labels).

-spec do_count_labels([binary()]) -> non_neg_integer().
do_count_labels([<<"*">> | Labels]) ->
    length(Labels);
do_count_labels(List) when is_list(List) ->
    length(List).

-spec normalise_dname(iodata()) -> binary().
normalise_dname(Name) ->
    dns:dname_to_lower(iolist_to_binary(Name)).

-spec normalise_dname_to_labels(binary()) -> [binary()].
normalise_dname_to_labels(Name) ->
    dns:dname_to_labels(normalise_dname(Name)).

-spec decode_asn1_dss_sig(binary()) -> {integer(), integer()}.
decode_asn1_dss_sig(Bin) when is_binary(Bin) ->
    {ok, #'DSS-Sig'{r = R, s = S}} = 'DNS-ASN1':decode('DSS-Sig', Bin),
    {R, S}.

-spec encode_asn1_dss_sig(non_neg_integer(), non_neg_integer()) -> binary().
encode_asn1_dss_sig(R, S) when is_integer(R) andalso is_integer(S) ->
    Rec = #'DSS-Sig'{r = R, s = S},
    {ok, List} = 'DNS-ASN1':encode('DSS-Sig', Rec),
    iolist_to_binary(List).
