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
-module(dns_sec).
-moduledoc """
The `dns_sec` module exports functions used for generating NSEC/NSEC3 records,
signing and verifying RRSIGs, and adding keytags to DNSKEY records.

For example, the `sign_rr/6` function can be given a collection of resource records,
the signer name, keytag, signing algorithm, private key, and a collection of options
and it will return a list of RRSIG records. Supported signing algorithms include
DSA, RSA (SHA1/SHA256/SHA512), ECDSA (P-256/P-384), Ed25519, Ed448, and ML-DSA-44.

ML-DSA-44 (algorithm 18) follows draft-westerbaan-dnssec-mldsa-04, which may still change.
It needs OTP 28.1+ built against OpenSSL 3.5+; elsewhere, signing raises
`{unsupported_algorithm, 18}` and verifying returns `false`. The private key is the 32-byte
seed or the 2560-byte expanded key. Signatures are hedged, so they differ from the draft's
deterministic example but verify the same.
""".

%% API
-export([gen_nsec/1, gen_nsec/3, gen_nsec/4]).
-export([gen_nsec3/1, gen_nsec3/2]).
-export([sign_rr/5, sign_rr/6]).
-export([sign_rrset/5, sign_rrset/6]).
-export([verify_rrsig/4]).
-export([add_keytag_to_dnskey/1, add_keytag_to_cdnskey/1]).
-export([dnskey_public_key/2]).
-export([canonical_rrdata_form/1]).
-export([ih/4]).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("dns_sec_algs.hrl").

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
    key/0,
    ds/0,
    dnskey/0,
    rrsig/0,
    nsec/0,
    nsec3/0
]).

-doc "DS (Delegation Signer) resource record data.".
-type ds() :: #dns_rrdata_ds{}.
-doc "DNSKEY resource record data.".
-type dnskey() :: #dns_rrdata_dnskey{}.
-doc "RRSIG resource record data.".
-type rrsig() :: #dns_rrdata_rrsig{}.
-doc "NSEC resource record data.".
-type nsec() :: #dns_rrdata_nsec{}.
-doc "NSEC3 resource record data.".
-type nsec3() :: #dns_rrdata_nsec3{}.

-doc """
DNSSEC signing algorithm identifier.

Unlike `t:dns:alg/0`, this type is restricted to algorithms valid for zone signing.
""".
-type sigalg() ::
    ?DNS_ALG_DSA
    | ?DNS_ALG_NSEC3DSA
    | ?DNS_ALG_RSASHA1
    | ?DNS_ALG_NSEC3RSASHA1
    | ?DNS_ALG_RSASHA256
    | ?DNS_ALG_RSASHA512
    | ?DNS_ALG_ECDSAP256SHA256
    | ?DNS_ALG_ECDSAP384SHA384
    | ?DNS_ALG_ED25519
    | ?DNS_ALG_ED448
    | ?DNS_ALG_MLDSA44.
-doc "NSEC3 hash algorithm identifier (currently only SHA-1).".
-type nsec3_hashalg() :: ?DNSSEC_NSEC3_ALG_SHA1.
-doc "Custom hash function for use with `ih/4`.".
-type nsec3_hashalg_fun() :: fun((iodata()) -> binary()).
-doc "NSEC3 salt value.".
-type nsec3_salt() :: binary().
-doc "NSEC3 iteration count.".
-type nsec3_iterations() :: non_neg_integer().
-doc "Options for `gen_nsec/4`.".
-type gen_nsec_opts() :: #{base_types => [dns:type()]}.
-doc "Options for `gen_nsec3/2`.".
-type gen_nsec3_opts() :: gen_nsec_opts().
-doc "DNSKEY key tag (RFC 4034 Appendix B).".
-type keytag() :: integer().
-doc """
A private key to sign with.

An RSA key is `[E, N, D]`, or the whole list `crypto:generate_key/2` gives, which lets crypto sign
by the CRT, and a DSA key `[P, Q, G, X]`, each number as its big-endian bytes; a number given as an
integer raises `{badarg, number_not_bytes}`. An ECDSA key is its private scalar, an EdDSA key its
private key, and an ML-DSA-44 key its 32-byte seed or 2560-byte expanded key. The public key a
DNSKEY carries is its RDATA's key field, which `dnskey_public_key/2` makes.
""".
-type key() :: [binary()] | binary().
-doc "Options for `sign_rr/6` and `sign_rrset/6`.".
-type sign_rr_opts() :: #{inception => dns:unix_time(), expiration => dns:unix_time()}.
-doc "Options for `verify_rrsig/4`.".
-type verify_rrsig_opts() :: #{now => dns:unix_time()}.

%% RFC4034§2.1.1: bit 7 of a DNSKEY's flags, set on a zone key
-define(DNSKEY_FLAG_ZONE, 16#0100).

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

-doc """
Generate NSEC records from a list of `t:dns:rr/0`.

The list must contain a SOA `t:dns:rr/0` which is used to determine zone name and TTL.
""".
-spec gen_nsec([dns:rr()]) -> [dns:rr()].
gen_nsec(RR) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RR) of
        false ->
            erlang:error(badarg);
        #dns_rr{name = ZoneName} = Soa ->
            TTL = minimum_soa_ttl(Soa),
            gen_nsec(ZoneName, RR, TTL)
    end.

-doc #{equiv => gen_nsec(ZoneName, RR, TTL, #{})}.
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl()) -> [dns:rr()].
gen_nsec(ZoneName, RR, TTL) ->
    gen_nsec(ZoneName, RR, TTL, #{}).

-doc "Generate NSEC records.".
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl(), gen_nsec_opts()) -> [dns:rr()].
gen_nsec(ZoneNameM, RR, TTL, Opts) ->
    ZoneName = dns_domain:to_lower(ZoneNameM),
    BaseTypes = maps:get(base_types, Opts, [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]),
    Map = build_rrmap_gbt(RR, BaseTypes),
    Unsorted = [
        #dns_rr{
            name = Name,
            class = Class,
            type = ?DNS_TYPE_NSEC,
            ttl = TTL,
            data = #dns_rrdata_nsec{next_dname = Name, types = Types}
        }
     || {Name, Class} := Types <- Map
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

-doc #{equiv => gen_nsec3(RRs, #{})}.
-spec gen_nsec3([dns:rr()]) -> [dns:rr()].
gen_nsec3(RRs) ->
    gen_nsec3(RRs, #{}).

-doc """
Generate NSEC3 records from a list of `t:dns:rr/0`.

The list must contain a SOA `t:dns:rr/0` to source the zone name and
TTL from as well as as an NSEC3Param `t:dns:rr/0` to source the
hash algorithm, iterations and salt from.
""".
-spec gen_nsec3([dns:rr()], gen_nsec3_opts()) -> [dns:rr()].
gen_nsec3(RRs, Opts) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RRs) of
        false ->
            erlang:error(badarg);
        #dns_rr{name = ZoneName} = Soa ->
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
                    TTL = minimum_soa_ttl(Soa),
                    gen_nsec3(RRs, ZoneName, HashAlg, Salt, Iter, TTL, Class, Opts)
            end
    end.

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
    Unsorted = maps:fold(
        fun
            ({Name, SClass}, Types, Acc) when SClass =:= Class ->
                DName = dns_domain:to_wire(Name),
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
            (_, _, Acc) ->
                Acc
        end,
        [],
        Map
    ),
    Sorted = [RR || {_, RR} <- lists:keysort(1, Unsorted)],
    add_next_hash(Sorted).

-spec minimum_soa_ttl(dns:rr()) -> dns:ttl().
minimum_soa_ttl(#dns_rr{type = ?DNS_TYPE_SOA, ttl = Rec, data = #dns_rrdata_soa{minimum = Min}}) ->
    erlang:min(Min, Rec).

-doc "NSEC3 iterative hash function.".
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
    RR#dns_rr{name = dns_domain:to_lower(Name)}.

-type rrtype_map() :: #{{dns:dname(), dns:class()} => [integer()]}.

-spec build_rrmap([dns:rr()], [integer()], dns:dname()) -> rrtype_map().
build_rrmap(RR, BaseTypes, ZoneName) ->
    Base = build_rrmap_gbt(RR, BaseTypes),
    build_rrmap_nonterm(ZoneName, maps:keys(Base), Base).

-spec build_rrmap_nonterm(dns:dname(), [{dns:dname(), dns:class()} | binary()], rrtype_map()) ->
    rrtype_map().
build_rrmap_nonterm(_, [], Map) ->
    Map;
build_rrmap_nonterm(ZoneName, [{Name, Class} | Rest], Map) when is_binary(ZoneName) ->
    NameAncs = name_ancestors(Name, ZoneName),
    NewMap = add_nonterm_ancestors(Class, NameAncs, Map),
    build_rrmap_nonterm(ZoneName, Rest, NewMap).

-spec add_nonterm_ancestors(dns:class(), [dns:dname()], rrtype_map()) -> rrtype_map().
add_nonterm_ancestors(_, [], Map) ->
    Map;
add_nonterm_ancestors(Class, [Name | Rest], Map) ->
    Key = {Name, Class},
    NewMap = maps:update_with(Key, fun(V) -> V end, [], Map),
    add_nonterm_ancestors(Class, Rest, NewMap).

-spec build_rrmap_gbt([dns:rr()], [dns:type()]) -> rrtype_map().
build_rrmap_gbt(RR, BaseTypes) ->
    build_rrmap_gbt(RR, BaseTypes, #{}).

-spec build_rrmap_gbt([dns:rr()], [dns:type()], rrtype_map()) -> rrtype_map().
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

%% An RRset's owner name in canonical form, its class and its type
-type tree_key() :: {binary(), dns:class(), dns:type()}.

-spec rrs_to_rrsets([dns:rr()]) -> [[dns:rr()]].
rrs_to_rrsets(RR) when is_list(RR) ->
    rrs_to_rrsets(RR, #{}, #{}).

%% Records group by owner name as sign_rrset/6 compares them, so that one written with and one
%% without a final dot are one RRset. Each RRset keeps the lowercased owner of its first record.
-spec rrs_to_rrsets(
    [dns:rr()], #{tree_key() => dns:ttl()}, #{tree_key() => {dns:dname(), [dns:rrdata()]}}
) ->
    [[dns:rr()]].
rrs_to_rrsets([], TTLMap, RRSets) ->
    [finalise_rrs_to_rrsets(TTLMap, Key, Name, Datas) || Key := {Name, Datas} <- RRSets];
rrs_to_rrsets([#dns_rr{} = RR | RRs], TTLMap, RRSets) ->
    #dns_rr{
        name = Name,
        class = Class,
        type = Type,
        ttl = TTL,
        data = Data
    } = normalise_rr(RR),
    Key = {canonical_owner(Name), Class, Type},
    NewTTLMap = maps:update_with(Key, fun(OldTTL) -> max(OldTTL, TTL) end, TTL, TTLMap),
    NewRRSets = maps:update_with(
        Key, fun({Owner, OldData}) -> {Owner, [Data | OldData]} end, {Name, [Data]}, RRSets
    ),
    rrs_to_rrsets(RRs, NewTTLMap, NewRRSets).

-spec finalise_rrs_to_rrsets(
    #{tree_key() => dns:ttl()}, tree_key(), dns:dname(), [dns:rrdata()]
) ->
    [dns:rr()].
finalise_rrs_to_rrsets(TTLMap, {_Owner, Class, Type} = Key, Name, Datas) ->
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

-doc #{equiv => sign_rr(RR, SignerName, KeyTag, Alg, Key, [])}.
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key) ->
    sign_rr(RR, SignerName, KeyTag, Alg, Key, #{}).

-doc """
Signs each RRset in a list of `t:dns:rr/0`, as `sign_rrset/6` does.

Records form one RRset when their owner names, classes and types are equal, owner names compared
as `sign_rrset/6` does, so that case and a final dot don't matter. RRSIG records are left out, as
RFC 4035 §2.2 never signs an RRSIG RRset.
""".
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key(), sign_rr_opts()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key, Opts) when is_map(Opts) ->
    RRSets = rrs_to_rrsets([Record || Record <- RR, not is_rrsig(Record)]),
    [
        sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, Opts)
     || RRSet <- RRSets
    ].

-doc #{equiv => sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, [])}.
-spec sign_rrset([dns:rr(), ...], dns:dname(), keytag(), sigalg(), key()) ->
    dns:rr().
sign_rrset(RRSet, SignerName, KeyTag, Alg, Key) ->
    sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, #{}).

-doc """
Signs a list of `t:dns:rr/0` of the same class and type.

Raises:

- `{badarg, rrsig_rrset}` for an RRSIG RRset, which RFC 4035 §2.2 never signs;
- `{badarg, mixed_rrset}` for records of more than one RRset, of another owner name, class or type
  than the first's. Owner names compare as names, so case and a final dot don't matter.
""".
-spec sign_rrset([dns:rr(), ...], dns:dname(), keytag(), sigalg(), key(), sign_rr_opts()) ->
    dns:rr().
sign_rrset(
    [#dns_rr{name = Name, class = Class, type = Type, ttl = TTL} | _] = RRs,
    SignersName,
    KeyTag,
    Alg,
    Key,
    Opts
) when is_integer(Alg) ->
    Type =/= ?DNS_TYPE_RRSIG orelse erlang:error({badarg, rrsig_rrset}),
    %% RFC4034§3.1.8.1: the records are signed as one RRset, under the first's owner, class and
    %% type, so a record of another RRset would make an RRSIG that never verifies
    Owner = canonical_owner(Name),
    lists:all(fun(RR) -> in_rrset(RR, Owner, Class, Type) end, RRs) orelse
        erlang:error({badarg, mixed_rrset}),
    Now = erlang:system_time(second),
    Incept = maps:get(inception, Opts, Now),
    %% 1 year
    Expire = maps:get(expiration, Opts, Now + ?SECS_IN_YEAR),
    {Data0, BaseSigInput} = build_sig_input(RRs, SignersName, KeyTag, Alg, Incept, Expire),
    Signature = sign(Alg, BaseSigInput, Key),
    Data = Data0#dns_rrdata_rrsig{signature = Signature},
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RRSIG,
        class = Class,
        ttl = TTL,
        data = Data
    }.

-spec in_rrset(dns:rr(), binary(), dns:class(), dns:type()) -> boolean().
in_rrset(#dns_rr{name = Name, class = Class, type = Type}, Owner, Class, Type) ->
    canonical_owner(Name) =:= Owner;
in_rrset(#dns_rr{}, _Owner, _Class, _Type) ->
    false.

%% RFC4034§6.2: the owner in canonical form, its wire form with letters in lowercase, so that names
%% written in another case or with a final dot compare equal
-spec canonical_owner(dns:dname()) -> binary().
canonical_owner(Name) ->
    dns_domain:to_lower(dns_domain:to_wire(Name)).

-spec is_rrsig(dns:rr()) -> boolean().
is_rrsig(#dns_rr{type = Type}) -> Type =:= ?DNS_TYPE_RRSIG.

-spec sign(dns:uint8(), binary(), key()) -> binary().
sign(Alg, BaseSigInput, Key) when ?IS_DSA_ALG(Alg) ->
    %% RFC2536§3: the signature starts with the key's T, the first octet of the key field that
    %% [P, Q, G, X] lays out as [P, Q, G, Y] does, as X < Q; laying it out raises {badarg, Why}
    %% for a key no DNSKEY can carry, or one given as integers
    <<T, _/binary>> = dns_dnskey:field(Alg, Key),
    DerSig = crypto:sign(dss, sha, BaseSigInput, Key),
    #'Dss-Sig-Value'{r = R, s = S} = public_key:der_decode('Dss-Sig-Value', DerSig),
    <<T, R:20/unit:8, S:20/unit:8>>;
sign(Alg, BaseSigInput, Key) when ?IS_RSA_ALG(Alg) ->
    %% crypto takes integers too, converting them on every call
    is_list(Key) andalso lists:all(fun erlang:is_binary/1, Key) orelse
        error({badarg, number_not_bytes}),
    crypto:sign(
        rsa,
        none,
        BaseSigInput,
        Key,
        [{rsa_padding, rsa_pkcs1_padding}]
    );
sign(?DNS_ALG_ECDSAP256SHA256, BaseSigInput, Key) ->
    DerSig = crypto:sign(ecdsa, sha256, BaseSigInput, [Key, secp256r1]),
    %% RFC6605: keys must be r||s of 32 octets each
    ecdsa_der_to_wire(DerSig, 32);
sign(?DNS_ALG_ECDSAP384SHA384, BaseSigInput, Key) ->
    DerSig = crypto:sign(ecdsa, sha384, BaseSigInput, [Key, secp384r1]),
    %% RFC6605: keys must be r||s of 48 octets each
    ecdsa_der_to_wire(DerSig, 48);
sign(?DNS_ALG_ED25519, BaseSigInput, Key) ->
    crypto:sign(eddsa, none, BaseSigInput, [Key, ed25519]);
sign(?DNS_ALG_ED448, BaseSigInput, Key) ->
    crypto:sign(eddsa, none, BaseSigInput, [Key, ed448]);
sign(?DNS_ALG_MLDSA44, BaseSigInput, Key) ->
    mldsa44_sign(BaseSigInput, Key);
%% function_clause would put the key in the stacktrace, raise a custom error instead
sign(Alg, _BaseSigInput, _Key) ->
    error({unsupported_algorithm, Alg}).

-doc """
Provides primitive verification of an RR set.

Only the DNSKEYs the RRSIG names verify it (RFC 4035 §5.3.1): zone keys, with the Zone Key flag
set (RFC 4034 §2.1.1), of protocol 3 and of the RRSIG's class and algorithm, owned by its signer,
whose key tag is the RRSIG's. Names compare in any case and with or without a final dot, and a
key tag is computed from the DNSKEY's RDATA, whatever its `keytag` field holds.

Returns `false` when none of those verifies it, when the time is outside the RRSIG's validity
period, and when its algorithm is one this module does not implement. Raises
`{badarg, public_key_not_binary}` when a DNSKEY of the RRSIG's algorithm and signer has a key that
is not a binary, as RSA and DSA keys were before 6.0.0, whether another one verifies it or not.
""".
-spec verify_rrsig(dns:rr(), [dns:rr()], [dns:rr()], verify_rrsig_opts()) -> boolean().
verify_rrsig(#dns_rr{type = ?DNS_TYPE_RRSIG, class = Class, data = Data}, RRs, RRDNSKey, Opts) ->
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
    %% RFC4035§5.3.1: the RRSIG's signer, algorithm and key tag name the DNSKEY, which is a zone
    %% key (RFC4034§2.1.1) in the zone's apex DNSKEY RRset, so of the RRSIG's class. The key tag
    %% is the key's own, computed from its RDATA. A key of the RRSIG's algorithm and signer that
    %% is not a binary raises before its class, flags or key tag are looked at, as documented
    Keys = [
        Key
     || #dns_rr{
            name = Name,
            class = KeyClass,
            type = ?DNS_TYPE_DNSKEY,
            data = #dns_rrdata_dnskey{
                flags = Flags,
                protocol = 3,
                alg = Alg,
                public_key = PubKey
            }
        } <- RRDNSKey,
        Alg =:= SigAlg,
        is_same_name(Name, SignersName),
        Key <- [dns_dnskey:public_key(PubKey)],
        KeyClass =:= Class,
        Flags band ?DNSKEY_FLAG_ZONE =/= 0,
        dns_dnskey:key_tag(<<Flags:16, 3, Alg, Key/binary>>) =:= SigKeyTag
    ],
    case Now of
        Now when Now < Incept; Expire < Now -> false;
        Now ->
            {_SigTuple, SigInput} = build_sig_input(
                RRs,
                SignersName,
                SigKeyTag,
                SigAlg,
                Incept,
                Expire,
                OTTL
            ),
            lists:any(fun(Key) -> verify(SigAlg, Key, Signature, SigInput) end, Keys)
    end.

%% Whether two names are one, in any case and with or without a final dot, as a zone file's names
%% have it and the wire's do not. A name that is none, such as one with an empty label, is only
%% the name written alike
-spec is_same_name(dns:dname(), dns:dname()) -> boolean().
is_same_name(NameA, NameB) ->
    dns_domain:are_equal(NameA, NameB) orelse
        try
            canonical_owner(NameA) =:= canonical_owner(NameB)
        catch
            error:{invalid_dname, empty_label} -> false;
            error:{label_too_long, _} -> false;
            error:name_too_long -> false
        end.

%% The key is the DNSKEY's RDATA key field. RSA and DSA keys are split into the
%% numbers crypto takes, as their big-endian bytes, and one laid out as no DNSKEY
%% may carry it verifies nothing
-spec verify(dns:uint8(), binary(), binary(), binary()) -> boolean().
verify(Alg, Key, Signature, SigInput) when ?IS_DSA_ALG(Alg) orelse ?IS_RSA_ALG(Alg) ->
    case dns_dnskey:numbers(Alg, Key) of
        invalid -> false;
        Numbers -> verify_numbers(Alg, Numbers, Signature, SigInput)
    end;
verify(?DNS_ALG_ECDSAP256SHA256, Key, Signature, SigInput) ->
    DerSig = ecdsa_wire_to_der(Signature, 32),
    crypto:verify(ecdsa, sha256, SigInput, DerSig, [<<4, Key/binary>>, secp256r1]);
verify(?DNS_ALG_ECDSAP384SHA384, Key, Signature, SigInput) ->
    DerSig = ecdsa_wire_to_der(Signature, 48),
    crypto:verify(ecdsa, sha384, SigInput, DerSig, [<<4, Key/binary>>, secp384r1]);
verify(?DNS_ALG_ED25519, Key, Signature, SigInput) ->
    crypto:verify(eddsa, none, SigInput, Signature, [Key, ed25519]);
verify(?DNS_ALG_ED448, Key, Signature, SigInput) ->
    crypto:verify(eddsa, none, SigInput, Signature, [Key, ed448]);
%% Other sizes go to the catch-all, as crypto raises for a wrong-size key
verify(?DNS_ALG_MLDSA44, <<_:1312/binary>> = Key, <<_:2420/binary>> = Signature, SigInput) ->
    mldsa44_verify(Key, Signature, SigInput);
%% An algorithm this module does not implement, which an RRSIG off the wire can carry
%% function_clause would put the key in the stacktrace, return `false` specifically
verify(_Alg, _Key, _Signature, _SigInput) ->
    false.

%% An RSA or DSA key's numbers, as dns_dnskey:numbers/2 splits them from its field
-spec verify_numbers(dns:uint8(), [binary()], binary(), binary()) -> boolean().
verify_numbers(Alg, PublicKey, Signature, SigInput) when ?IS_DSA_ALG(Alg) ->
    <<_T, R:20/unit:8, S:20/unit:8>> = Signature,
    AsnSig = public_key:der_encode('Dss-Sig-Value', #'Dss-Sig-Value'{r = R, s = S}),
    crypto:verify(dss, sha, SigInput, AsnSig, PublicKey);
verify_numbers(_RsaAlg, PublicKey, Signature, SigInput) ->
    try
        crypto:verify(rsa, none, SigInput, Signature, PublicKey, [{rsa_padding, rsa_pkcs1_padding}])
    catch
        error:decrypt_failed -> false
    end.

%% Pure ML-DSA with an empty context; OTP 27's crypto specs lack mldsa44
-dialyzer({nowarn_function, [mldsa44_sign/2, mldsa44_verify/3]}).
-spec mldsa44_sign(binary(), key()) -> binary().
mldsa44_sign(SigInput, Key) ->
    case has_mldsa44() of
        true -> crypto:sign(mldsa44, none, SigInput, mldsa44_private_key(Key));
        false -> error({unsupported_algorithm, ?DNS_ALG_MLDSA44})
    end.

%% crypto wants the private key tagged
-spec mldsa44_private_key(key()) -> {seed | expandedkey, key()}.
mldsa44_private_key(<<_:32/binary>> = Seed) ->
    {seed, Seed};
mldsa44_private_key(Key) ->
    {expandedkey, Key}.

-spec mldsa44_verify(binary(), binary(), binary()) -> boolean().
mldsa44_verify(Key, Signature, SigInput) ->
    has_mldsa44() andalso crypto:verify(mldsa44, none, SigInput, Signature, Key).

%% OTP 28.1+ built against OpenSSL 3.5+
-spec has_mldsa44() -> boolean().
has_mldsa44() ->
    lists:member(mldsa44, crypto:supports(public_keys)).

-spec build_sig_input([dns:rr(), ...], dns:dname(), keytag(), dns:alg(), integer(), integer()) ->
    {dns:rrdata_rrsig(), binary()}.
build_sig_input(
    [#dns_rr{ttl = TTL} | _] = RRs,
    SignersName,
    KeyTag,
    Alg,
    Incept,
    Expire
) ->
    build_sig_input(RRs, SignersName, KeyTag, Alg, Incept, Expire, TTL).

-spec build_sig_input(
    [dns:rr(), ...], dns:dname(), keytag(), dns:alg(), integer(), integer(), non_neg_integer()
) ->
    {dns:rrdata_rrsig(), binary()}.
build_sig_input(
    [#dns_rr{name = Name, class = Class, type = Type} | _] = RRs,
    SignersName,
    KeyTag,
    Alg,
    Incept,
    Expire,
    TTL
) when is_integer(Alg) ->
    LName = dns_domain:to_lower(Name),
    %% RFC4034§6.3: in canonical order, and a duplicate record once, as validators take it
    Datas = lists:usort([canonical_rrdata_bin(RR) || RR <- RRs]),
    LLabels = dns_domain:split(LName),
    NameBin = dns_domain:to_wire(LName),
    %% RFC4034§6.2: every record with the original TTL, whatever TTL it arrived with, as
    %% one from a cache arrives counted down
    RecordBase = <<NameBin/binary, Type:16, Class:16, TTL:32>>,
    RRSetBin = [<<RecordBase/binary, (byte_size(Data)):16, Data/binary>> || Data <- Datas],
    RRSigData = #dns_rrdata_rrsig{
        type_covered = Type,
        alg = Alg,
        labels = count_labels(LLabels),
        original_ttl = TTL,
        inception = Incept,
        expiration = Expire,
        keytag = KeyTag,
        %% RFC4034§3.1.8.1, RFC6840§5.1: the signer's name is signed in canonical
        %% form, lowercased, and so it is written in the RRSIG too
        signers_name = dns_domain:to_lower(SignersName)
    },
    RRSigRDataBin = rrsig_to_digestable(RRSigData),
    SigInput0 = [RRSigRDataBin | RRSetBin],
    SigInput = preprocess_sig_input(Alg, SigInput0),
    {RRSigData, SigInput}.

-spec preprocess_sig_input(dns:uint8(), [binary()]) -> binary().
%% RFC2536§3: crypto:sign/4 and crypto:verify/5 hash the data for DSA themselves
preprocess_sig_input(Alg, SigInput) when ?IS_DSA_ALG(Alg) ->
    iolist_to_binary(SigInput);
preprocess_sig_input(Alg, SigInput) when ?IS_RSA_ALG(Alg) ->
    {Prefix, HashType} = choose_sha_prefix_and_type(Alg),
    Hash = crypto:hash(HashType, SigInput),
    <<Prefix/binary, Hash/binary>>;
%% RFC6605§4: crypto:sign/4 and crypto:verify/5 hash the data for ECDSA themselves
preprocess_sig_input(?DNS_ALG_ECDSAP256SHA256, SigInput) ->
    iolist_to_binary(SigInput);
preprocess_sig_input(?DNS_ALG_ECDSAP384SHA384, SigInput) ->
    iolist_to_binary(SigInput);
preprocess_sig_input(Alg, SigInput) when Alg =:= ?DNS_ALG_ED25519 orelse Alg =:= ?DNS_ALG_ED448 ->
    iolist_to_binary(SigInput);
%% Unhashed, as for EdDSA
preprocess_sig_input(?DNS_ALG_MLDSA44, SigInput) ->
    iolist_to_binary(SigInput);
%% An algorithm this module does not implement, which verify/4 refuses and sign/3 raises for
preprocess_sig_input(_Alg, SigInput) ->
    iolist_to_binary(SigInput).

-spec choose_sha_prefix_and_type(sigalg()) -> {binary(), sha | sha256 | sha512}.
choose_sha_prefix_and_type(?DNS_ALG_RSASHA1) ->
    {?RSASHA1_PREFIX, sha};
choose_sha_prefix_and_type(?DNS_ALG_NSEC3RSASHA1) ->
    {?RSASHA1_PREFIX, sha};
choose_sha_prefix_and_type(?DNS_ALG_RSASHA256) ->
    {?RSASHA256_PREFIX, sha256};
choose_sha_prefix_and_type(?DNS_ALG_RSASHA512) ->
    {?RSASHA512_PREFIX, sha512}.

-doc "Generates and appends a DNS Key records key tag.".
-spec add_keytag_to_dnskey(dns:rr()) -> dns:rr().
add_keytag_to_dnskey(
    #dns_rr{type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{} = Data} = RR
) ->
    add_keytag_to_key_rr(RR, Data, ?DNS_TYPE_DNSKEY).

-doc "Generates and appends a CDNSKEY records key tag.".
-spec add_keytag_to_cdnskey(dns:rr()) -> dns:rr().
add_keytag_to_cdnskey(
    #dns_rr{type = ?DNS_TYPE_CDNSKEY, data = #dns_rrdata_cdnskey{} = Data} = RR
) ->
    add_keytag_to_key_rr(RR, Data, ?DNS_TYPE_CDNSKEY).

-doc """
Returns the public key field of a DNSKEY's RDATA for a public key.

An RSA key `[E, N]` is laid out as RFC 3110 §2 has it, and a DSA key
`[P, Q, G, Y]` as RFC 2536 §2 has it, each number as its big-endian bytes, as
`crypto:generate_key/2` gives an RSA key's. An ECDSA key, the point that
`crypto:generate_key(ecdh, Curve)` gives, loses the octet 4 in front that marks it
uncompressed (RFC 6605 §4), and an EdDSA or ML-DSA-44 key, as
`crypto:generate_key/2` gives it, is as it is.

Raises `{unsupported_algorithm, Alg}` for an algorithm without a key layout here,
and `{badarg, Why}` for a key the algorithm's DNSKEY cannot carry. `Why` names
the rule the key breaks and, for RSA and DSA keys, the size in bits of the
number that breaks it, but never one of the key's numbers:

- `number_not_bytes`: an RSA or DSA key's number given as anything but its
  bytes, such as an integer.
- `{rsa_exponent_bits, Bits}`: an RSA exponent that is empty or over 4096 bits
  long (RFC 3110 §2).
- `{rsa_modulus_bits, Bits}`: an RSA modulus that is not 512 to 4096 bits long,
  or 1024 to 4096 for RSA/SHA-512 (RFC 3110 §3, RFC 5702 §2).
- `{dsa_q_bits, Bits}`: a DSA Q that is not 160 bits long (RFC 2536 §2).
- `{dsa_p_bits, Bits}`: a DSA P that is not 512 + 64T bits long for a T of 0 to 8.
- `dsa_number_longer_than_p`: a DSA G or Y longer than P.
- `key_shape`: a key of another shape than the algorithm's: another count of
  numbers, an ECDSA point without the octet 4 in front, or an EdDSA or ML-DSA-44
  key of another length.

`verify_rrsig/4` verifies with no RSA or DSA key that this function would not
make, and `dns_json:from_map/1` and `dns_zone` refuse a DNSKEY or CDNSKEY with
one.
""".
-spec dnskey_public_key(sigalg(), [binary()] | binary()) -> binary().
dnskey_public_key(Alg, Key) ->
    dns_dnskey:field(Alg, Key).

-spec add_keytag_to_key_rr(dns:rr(), dns:rrdata(), dns:type()) -> dns:rr().
add_keytag_to_key_rr(RR, Data, Type) ->
    KeyBin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
    NewData = dns_decode:decode_rrdata(KeyBin, ?DNS_CLASS_IN, Type),
    RR#dns_rr{data = NewData}.

-spec rrsig_to_digestable(dns:rrdata_rrsig()) -> binary().
rrsig_to_digestable(#dns_rrdata_rrsig{} = Data) ->
    dns_encode:encode_rrdata(?DNS_CLASS_IN, Data#dns_rrdata_rrsig{signature = <<>>}).

-spec canonical_rrdata_bin(dns:rr()) -> binary().
canonical_rrdata_bin(#dns_rr{class = Class, data = Data0}) ->
    dns_encode:encode_rrdata(Class, canonical_rrdata_form(Data0)).

-doc "Converts a resource record data record to DNSSEC canonical form.".
-spec canonical_rrdata_form(dns:rrdata()) -> dns:rrdata().
%% RFC4034§6.2: the names in the RDATA of the types listed there are lowercased.
%% RFC3597§7 closes that list to the types published before it, so later types,
%% such as DSYNC, IPSECKEY, SVCB and HTTPS, keep the case of their names, and
%% RFC6840§5.1 takes NSEC off it.
canonical_rrdata_form(#dns_rrdata_afsdb{hostname = Hostname} = Data) ->
    Data#dns_rrdata_afsdb{hostname = dns_domain:to_lower(Hostname)};
canonical_rrdata_form(#dns_rrdata_cname{dname = DName} = Data) ->
    Data#dns_rrdata_cname{dname = dns_domain:to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_dname{dname = DName} = Data) ->
    Data#dns_rrdata_dname{dname = dns_domain:to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_kx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_kx{exchange = dns_domain:to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_mb{madname = MaDname} = Data) ->
    Data#dns_rrdata_mb{madname = dns_domain:to_lower(MaDname)};
canonical_rrdata_form(#dns_rrdata_mg{madname = MaDname} = Data) ->
    Data#dns_rrdata_mg{madname = dns_domain:to_lower(MaDname)};
canonical_rrdata_form(#dns_rrdata_minfo{rmailbx = RmailBx, emailbx = EmailBx} = Data) ->
    Data#dns_rrdata_minfo{
        rmailbx = dns_domain:to_lower(RmailBx),
        emailbx = dns_domain:to_lower(EmailBx)
    };
canonical_rrdata_form(#dns_rrdata_mr{newname = NewName} = Data) ->
    Data#dns_rrdata_mr{newname = dns_domain:to_lower(NewName)};
canonical_rrdata_form(#dns_rrdata_mx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_mx{exchange = dns_domain:to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_naptr{replacement = Replacement} = Data) ->
    Data#dns_rrdata_naptr{replacement = dns_domain:to_lower(Replacement)};
canonical_rrdata_form(#dns_rrdata_ns{dname = DName} = Data) ->
    Data#dns_rrdata_ns{dname = dns_domain:to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_nxt{dname = DName} = Data) ->
    Data#dns_rrdata_nxt{dname = dns_domain:to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_ptr{dname = DName} = Data) ->
    Data#dns_rrdata_ptr{dname = dns_domain:to_lower(DName)};
canonical_rrdata_form(#dns_rrdata_rp{mbox = Mbox, txt = Txt} = Data) ->
    Data#dns_rrdata_rp{
        mbox = dns_domain:to_lower(Mbox),
        txt = dns_domain:to_lower(Txt)
    };
canonical_rrdata_form(#dns_rrdata_rrsig{signers_name = SignersName} = Data) ->
    Data#dns_rrdata_rrsig{signers_name = dns_domain:to_lower(SignersName)};
%% RFC4034§6.2: PX and SIG are among the types whose RDATA names are lowercased
canonical_rrdata_form(#dns_rrdata_px{map822 = Map822, mapx400 = MapX400} = Data) ->
    Data#dns_rrdata_px{
        map822 = dns_domain:to_lower(Map822), mapx400 = dns_domain:to_lower(MapX400)
    };
canonical_rrdata_form(#dns_rrdata_sig{signers_name = SignersName} = Data) ->
    Data#dns_rrdata_sig{signers_name = dns_domain:to_lower(SignersName)};
canonical_rrdata_form(#dns_rrdata_rt{host = Host} = Data) ->
    Data#dns_rrdata_rt{host = dns_domain:to_lower(Host)};
canonical_rrdata_form(#dns_rrdata_soa{mname = Mname, rname = Rname} = Data) ->
    Data#dns_rrdata_soa{
        mname = dns_domain:to_lower(Mname),
        rname = dns_domain:to_lower(Rname)
    };
canonical_rrdata_form(#dns_rrdata_srv{target = Target} = Data) ->
    Data#dns_rrdata_srv{target = dns_domain:to_lower(Target)};
canonical_rrdata_form(X) ->
    X.

-spec name_ancestors(dns:dname(), dns:dname()) -> [binary()].
name_ancestors(Name, ZoneName) ->
    NameLwr = dns_domain:to_lower(Name),
    ZoneNameLwr = dns_domain:to_lower(ZoneName),
    gen_name_ancestors(NameLwr, ZoneNameLwr).

-spec gen_name_ancestors(binary(), binary()) -> [binary()].
gen_name_ancestors(ZoneName, ZoneName) ->
    [];
gen_name_ancestors(Name, ZoneName) when byte_size(Name) > byte_size(ZoneName) + 1 ->
    Offset = byte_size(Name) - byte_size(ZoneName) - 1,
    case Name of
        <<RelName:Offset/binary, $., ZoneName/binary>> ->
            case dns_domain:split(RelName) of
                [_] ->
                    [];
                [_ | Labels0] ->
                    [FirstLabel | Labels] = lists:reverse(Labels0),
                    gen_name_ancestors_labels(Labels, [<<FirstLabel/binary, $., ZoneName/binary>>])
            end;
        _ ->
            erlang:error(name_mismatch)
    end.

gen_name_ancestors_labels([], Anc) ->
    Anc;
gen_name_ancestors_labels([Label | Labels], [Parent | _] = Asc) ->
    NewName = <<Label/binary, $., Parent/binary>>,
    gen_name_ancestors_labels(Labels, [NewName | Asc]).

-spec name_order([dns:rr(), ...]) -> [dns:rr(), ...].
name_order(RRs) when is_list(RRs) ->
    lists:sort(fun name_order/2, RRs).

-spec name_order(_, _) -> boolean().
name_order(X, X) ->
    true;
name_order(#dns_rr{name = X}, #dns_rr{name = X}) ->
    true;
name_order(#dns_rr{name = A}, #dns_rr{name = B}) ->
    lists:reverse(dns_domain:split(A)) =< lists:reverse(dns_domain:split(B)).

-spec count_labels([binary()]) -> non_neg_integer().
count_labels([~"*" | Labels]) ->
    length(Labels);
count_labels(List) when is_list(List) ->
    length(List).

%% RFC 6605 §4: ECDSA signatures on the wire are r || s, each padded to FieldSize bytes.
%% crypto:sign returns DER-encoded ASN.1; crypto:verify expects DER-encoded ASN.1.
-spec ecdsa_der_to_wire(binary(), pos_integer()) -> binary().
ecdsa_der_to_wire(DerSig, FieldSize) ->
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    RBin = pad_unsigned(binary:encode_unsigned(R), FieldSize),
    SBin = pad_unsigned(binary:encode_unsigned(S), FieldSize),
    <<RBin/binary, SBin/binary>>.

-spec ecdsa_wire_to_der(binary(), pos_integer()) -> binary().
ecdsa_wire_to_der(WireSig, FieldSize) ->
    <<RBin:FieldSize/binary, SBin:FieldSize/binary>> = WireSig,
    R = binary:decode_unsigned(RBin),
    S = binary:decode_unsigned(SBin),
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}).

-spec pad_unsigned(binary(), pos_integer()) -> binary().
pad_unsigned(Bin, Size) when byte_size(Bin) >= Size ->
    Bin;
pad_unsigned(Bin, Size) ->
    Pad = Size - byte_size(Bin),
    <<0:(Pad * 8), Bin/binary>>.
