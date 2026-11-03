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
-moduledoc """
The `dnssec` module exports functions used for generating NSEC/NSEC3 records,
signing and verifying RRSIGs, and adding keytags to DNSKEY records.

For example, the `sign_rr/6` function can be given a collection of resource records,
the signer name, keytag, signing algorithm, private key, and a collection of options
and it will return a list of RRSIG records. Supported signing algorithms include
DSA, RSA (SHA1/SHA256/SHA512), ECDSA (P-256/P-384), Ed25519, and Ed448.
""".

%% API
-export([gen_nsec/1, gen_nsec/3, gen_nsec/4]).
-export([gen_nsec3/1, gen_nsec3/2]).
-export([sign_rr/5, sign_rr/6]).
-export([sign_rrset/5, sign_rrset/6]).
-export([verify_rrsig/4]).
-export([add_keytag_to_dnskey/1, add_keytag_to_cdnskey/1]).
-export([canonical_rrdata_form/1]).
-export([ih/4]).

-ifdef(TEST).
-export([refused_as_false/1]).
-endif.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("public_key/include/public_key.hrl").

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
    | ?DNS_ALG_ED448.
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
Cryptographic key material for signing or verification.

RSA and DSA keys are lists of integers, `[E, N, D]` or `[P, Q, G, X]` to sign
and `[E, M]` or `[P, Q, G, Y]` to verify, which is how the wire decoder gives a
DNSKEY's key. Each integer can also be given as its big-endian bytes, as
`crypto:generate_key/2` gives an RSA key. A DNSKEY parsed from a zone file
keeps the RDATA's key bytes, which verify as well. Other keys are binaries.
Though its record field's type is `iodata()`, a DNSKEY's key in a list is read
as those numbers, not as pieces of its bytes: two binaries are an RSA key's
`[E, M]`, so a key given as its bytes must be one binary.
""".
-type key() :: [non_neg_integer() | binary()] | binary().
-doc "Options for `sign_rr/6` and `sign_rrset/6`.".
-type sign_rr_opts() :: #{inception => dns:unix_time(), expiration => dns:unix_time()}.
-doc "Options for `verify_rrsig/4`.".
-type verify_rrsig_opts() :: #{now => dns:unix_time()}.

-define(SECS_IN_YEAR, (365 * 24 * 60 * 60)).

%% RFC3110§3: the DigestInfo of a SHA-1 hash, which RSA/SHA-1 signs
-define(SHA1_DIGESTINFO,
    <<16#30, 16#21, 16#30, 16#09, 16#06, 16#05, 16#2B, 16#0E, 16#03, 16#02, 16#1A, 16#05, 16#00,
        16#04, 16#14>>
).

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
     || {_Key, Class} := {Name, Types} <- Map
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
            ({_Key, SClass}, {Name, Types}, Acc) when SClass =:= Class ->
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

%% A name as a key that is the same however it is written, in any case and with
%% or without its final dot, as RFC4034§6.2 compares names: records under one
%% owner are one RRset, and an owner gets one NSEC or NSEC3, whichever way each
%% record writes it
-spec name_key(dns:dname()) -> dns:dname().
name_key(Name) ->
    dns_domain:join(dns_domain:split(dns_domain:to_lower(Name))).

%% Each owner, by its name_key/1, with the name it was first given, lowercased,
%% and its types
-type rrtype_map() :: #{{dns:dname(), dns:class()} => {dns:dname(), [integer()]}}.

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
    NewMap = maps:update_with(Key, fun(V) -> V end, {Name, []}, Map),
    add_nonterm_ancestors(Class, Rest, NewMap).

-spec build_rrmap_gbt([dns:rr()], [dns:type()]) -> rrtype_map().
build_rrmap_gbt(RR, BaseTypes) ->
    build_rrmap_gbt(RR, BaseTypes, #{}).

-spec build_rrmap_gbt([dns:rr()], [dns:type()], rrtype_map()) -> rrtype_map().
build_rrmap_gbt([], _BaseTypes, Map) ->
    Map;
build_rrmap_gbt([#dns_rr{} = RR | Rest], BaseTypes, Map) ->
    #dns_rr{name = Name, class = Class, type = Type} = normalise_rr(RR),
    Key = {name_key(Name), Class},
    NewMap = maps:update_with(
        Key,
        fun({First, Types}) ->
            case lists:member(Type, Types) of
                true -> {First, Types};
                false -> {First, [Type | Types]}
            end
        end,
        {Name, [Type | BaseTypes]},
        Map
    ),
    build_rrmap_gbt(Rest, BaseTypes, NewMap).

-type tree_key() :: {dns:dname(), dns:class(), dns:type()}.

-spec rrs_to_rrsets([dns:rr()]) -> [[dns:rr()]].
rrs_to_rrsets(RR) when is_list(RR) ->
    rrs_to_rrsets(RR, #{}, #{}).

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
    %% The RRset takes the owner name its first record was given, lowercased
    Key = {name_key(Name), Class, Type},
    NewTTLMap = maps:update_with(Key, fun(OldTTL) -> max(OldTTL, TTL) end, TTL, TTLMap),
    NewRRSets = maps:update_with(
        Key, fun({First, OldData}) -> {First, [Data | OldData]} end, {Name, [Data]}, RRSets
    ),
    rrs_to_rrsets(RRs, NewTTLMap, NewRRSets).

-spec finalise_rrs_to_rrsets(
    #{tree_key() => dns:ttl()}, tree_key(), dns:dname(), [dns:rrdata()]
) ->
    [dns:rr()].
finalise_rrs_to_rrsets(TTLMap, {_Key, Class, Type} = Key, Name, Datas) ->
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
Signs each RRset in a list of `t:dns:rr/0`, raising as `sign_rrset/6` does.

Records whose owner names differ only in case or in a final dot are one RRset,
signed under the owner name of its first record in lowercase. RRSIG records are
left out, as RFC 4035 §2.2 never signs them.
""".
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key(), sign_rr_opts()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key, Opts) when is_map(Opts) ->
    Signable = [Record || #dns_rr{type = Type} = Record <- RR, Type =/= ?DNS_TYPE_RRSIG],
    [
        sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, Opts)
     || RRSet <- rrs_to_rrsets(Signable)
    ].

-doc #{equiv => sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, [])}.
-spec sign_rrset([dns:rr(), ...], dns:dname(), keytag(), sigalg(), key()) ->
    dns:rr().
sign_rrset(RRSet, SignerName, KeyTag, Alg, Key) ->
    sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, #{}).

-doc """
Signs one RRset: a list of `t:dns:rr/0` of one owner, class and type.

Owner names that differ only in case or in a final dot are one owner. Raises
`badarg` for records of more than one RRset, and for an RRSIG RRset, which
RFC 4035 §2.2 never signs. Raises `{unsupported_algorithm, Alg}` for an
algorithm this module does not implement, and `{unsupported_key, Alg}` for a
DSA key that RFC 2536 cannot carry: one whose Q is over 160 bits, or whose P or
G is over 1024 bits. It still signs with DSA (3 and 6) and RSA/SHA-1 (5 and 7),
which RFC 9904 and RFC 9905 forbid for new signatures.
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
    Owner = dns_domain:split(Name),
    %% RFC4034§3.1.8.1: the records are signed as one RRset, with the first's
    %% owner, class and type, so a record of another RRset would make an RRSIG
    %% that never verifies. RFC4035§2.2: an RRSIG RRset is never signed
    Type =/= ?DNS_TYPE_RRSIG andalso
        lists:all(fun(RR) -> in_rrset(RR, Name, Owner, Class, Type) end, RRs) orelse
        error(badarg),
    Now = erlang:system_time(second),
    Incept = maps:get(inception, Opts, Now),
    %% 1 year
    Expire = maps:get(expiration, Opts, Now + ?SECS_IN_YEAR),
    Data0 = #dns_rrdata_rrsig{
        type_covered = Type,
        alg = Alg,
        labels = count_labels(Owner),
        original_ttl = TTL,
        inception = Incept,
        expiration = Expire,
        keytag = KeyTag,
        %% RFC4034§3.1.8.1, RFC6840§5.1: the signer's name is signed in canonical
        %% form, lowercased, and so it is written in the RRSIG too
        signers_name = dns_domain:to_lower(SignersName)
    },
    Data = Data0#dns_rrdata_rrsig{signature = sign(Alg, signed_data(Data0, RRs), Key)},
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RRSIG,
        class = Class,
        ttl = TTL,
        data = Data
    }.

-spec sign(dns:uint8(), iodata(), key()) -> binary().
sign(Alg, BaseSigInput, Key) when Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA ->
    [P, Q, G, _X] = Integers = [key_integer(Field) || Field <- Key],
    %% RFC2536§2, §3: R and S, which are below Q, take 20 octets each, and T, 0 to
    %% 8, makes P, G and Y 64 + 8T octets: a wider Q or P cannot be carried
    (Q < 1 bsl 160 andalso P < 1 bsl 1024 andalso G < 1 bsl 1024) orelse
        error({unsupported_key, Alg}),
    DerSig = crypto:sign(dss, sha, BaseSigInput, Integers),
    #'Dss-Sig-Value'{r = R, s = S} = public_key:der_decode('Dss-Sig-Value', DerSig),
    %% RFC2536§3: T is the DNSKEY's. Its Y = G^X mod P is below P, so P and G
    %% alone fix the width the DNSKEY's encoding takes T from
    T = dns_encode:dsa_t([P, G]),
    <<T, R:20/unit:8, S:20/unit:8>>;
sign(Alg, BaseSigInput, Key) when
    Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    {Hash, Msg} = rsa_message(Alg, BaseSigInput),
    crypto:sign(rsa, Hash, Msg, key_binaries(Key), [{rsa_padding, rsa_pkcs1_padding}]);
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
sign(Alg, _BaseSigInput, _Key) ->
    error({unsupported_algorithm, Alg}).

-doc """
Verifies an RRset against one of its RRSIGs, as RFC 4035 §5.3 has a validator do.

Returns `true` if all of these hold:

- Every record of the RRset has the RRSIG's owner and class and the type it
  covers.
- The RRSIG's signer can be the zone the RRset is in, as BIND checks it: for an
  NS, SOA or DNSKEY RRset its owner, for an NSEC3 RRset its owner's parent, for
  a DS RRset a zone above its owner, and for any other the owner or one of its
  ancestors.
- Its labels field counts no more labels than the owner has and no fewer than
  the signer has.
- The time `now` in `Opts`, by default the current time, is within its validity
  period, compared in serial number arithmetic (RFC 4034 §3.1.5).
- Its signature verifies with one of the DNSKEYs it names: a zone key, with the
  Zone Key flag set, of the RRSIG's class, at the RRSIG's signer's name, with
  the RRSIG's algorithm and key tag. The key tag is computed from the DNSKEY's
  RDATA (RFC 4034 Appendix B), whatever its `keytag` field holds.

Otherwise it returns `false`, as it does for an algorithm this module does not
implement or the local crypto cannot verify, for a key or signature whose size
is wrong for its algorithm, and for one crypto refuses.

It verifies with every algorithm it implements, including DSA (3 and 6), which
RFC 9904 forbids validators to implement, and RSA/SHA-1 (5 and 7), which RFC 9905
has validating resolvers treat as unsupported. Which algorithms to accept is the
caller's policy: an RRset signed only with ones it does not accept is insecure,
not bogus (RFC 4035 §5.2).

An RRset a wildcard was expanded into verifies with the wildcard's RRSIG, which
only proves that the wildcard's RRset was signed. Such an RRSIG's labels field
counts fewer labels than its owner has, not counting a leading `*`, and before
it accepts the answer the caller must prove that no closer name exists
(RFC 4035 §5.3.4).

Whether the DNSKEYs are to be trusted is for the caller to decide: a key is used
as it is, and some keys verify what their owner never signed, as an all-zero
Ed448 key verifies an all-zero signature over any data.

Key tags are not unique, and whoever makes a zone can give many of its keys the
same one, so an RRSIG can name many DNSKEYs, each of which is tried in turn
(KeyTrap, CVE-2023-50387). A caller that verifies data it does not trust should
limit the number of DNSKEYs it passes.
""".
-spec verify_rrsig(dns:rr(), [dns:rr()], [dns:rr()], verify_rrsig_opts()) -> boolean().
verify_rrsig(
    #dns_rr{type = ?DNS_TYPE_RRSIG, class = Class, data = #dns_rrdata_rrsig{} = Data} = RRSig,
    RRs,
    RRDNSKey,
    Opts
) ->
    Now = maps:get(now, Opts, erlang:system_time(second)),
    #dns_rrdata_rrsig{
        keytag = SigKeyTag,
        alg = SigAlg,
        inception = Incept,
        expiration = Expire,
        signers_name = SignersName,
        signature = Signature
    } = Data,
    Signer = name_labels(SignersName),
    %% The validity period and the RRset are checked before the keys, whose key
    %% tags cost an encoding each
    case in_validity_period(Incept, Expire, Now) andalso fits_rrset(RRSig, Signer, RRs) of
        true ->
            %% RFC4035§5.3.1: the RRSIG's signer, algorithm and key tag name the
            %% DNSKEY, which must be a zone key, with bit 7 of its flags set
            %% (RFC4034§2.1.1), in the zone's apex DNSKEY RRset, so of the RRSIG's
            %% class. The names compare as names: a zone file's keep their final
            %% dot, the wire's not. Only the keys the RRSIG names are tried, never
            %% every key of the zone, though key tags collide and these can be many
            Keys = [
                PubKey
             || #dns_rr{
                    name = Name,
                    class = KeyClass,
                    type = ?DNS_TYPE_DNSKEY,
                    data = #dns_rrdata_dnskey{
                        flags = Flags, protocol = 3, alg = Alg, public_key = PubKey
                    }
                } = DNSKey <- RRDNSKey,
                KeyClass =:= Class,
                Flags band 16#0100 =/= 0,
                Alg =:= SigAlg,
                is_name(Name, Signer),
                key_tag(DNSKey) =:= SigKeyTag
            ],
            verify_with_keys(SigAlg, Keys, Signature, Data, RRs);
        false ->
            false
    end;
%% An RRSIG whose RDATA the decoder could not read, which it keeps as bytes
verify_rrsig(#dns_rr{type = ?DNS_TYPE_RRSIG}, _RRs, _RRDNSKey, _Opts) ->
    false.

-spec verify_with_keys(dns:uint8(), [key()], binary(), dns:rrdata_rrsig(), [dns:rr(), ...]) ->
    boolean().
verify_with_keys(_SigAlg, [], _Signature, _Data, _RRs) ->
    false;
verify_with_keys(SigAlg, Keys, Signature, Data, RRs) ->
    SignedData = signed_data(Data, RRs),
    lists:any(fun(Key) -> verify_with_key(SigAlg, Key, Signature, SignedData) end, Keys).

%% RFC4034§3.1.5: inception and expiration are 32-bit serial numbers, which the
%% time is compared with in serial number arithmetic (RFC1982): a validity period
%% can span the 32-bit wrap, and the time can be past 2106. The inception must
%% not be after the expiration, which a period of 2^31 seconds or more also is
-spec in_validity_period(non_neg_integer(), non_neg_integer(), integer()) -> boolean().
in_validity_period(Inception, Expiration, Now) ->
    serial_at_most(Inception, Expiration) andalso serial_at_most(Inception, Now) andalso
        serial_at_most(Now, Expiration).

%% RFC1982§3.2: whether A is B or before it, as 32-bit serial numbers
-spec serial_at_most(integer(), integer()) -> boolean().
serial_at_most(A, B) ->
    (B - A) band 16#FFFFFFFF < 16#80000000.

%% RFC4035§5.3.1: every record of the RRset has the RRSIG's owner and class and
%% the type it covers, the labels field counts no more labels than the owner
%% has, and the signer is the RRset's zone. The zone cut is not known here, so
%% the signer must be a zone the RRset can be in, and the labels field count no
%% fewer labels than the signer has, so that a wildcard it names (RFC4035§5.3.2)
%% is in the signer's zone too
-spec fits_rrset(dns:rr(), dns:labels() | invalid, [dns:rr()]) -> boolean().
fits_rrset(_RRSig, invalid, _RRs) ->
    false;
fits_rrset(_RRSig, _Signer, []) ->
    false;
fits_rrset(
    #dns_rr{
        name = SigOwner,
        class = Class,
        data = #dns_rrdata_rrsig{type_covered = Type, labels = Labels}
    },
    Signer,
    RRs
) ->
    Owner = name_labels(SigOwner),
    InRRset = fun(RR) -> in_rrset(RR, SigOwner, Owner, Class, Type) end,
    Owner =/= invalid andalso lists:all(InRRset, RRs) andalso
        Labels =< count_labels(Owner) andalso
        length(Signer) =< Labels andalso
        can_hold(Signer, Type, Owner).

%% Whether a record is of the RRset of an owner, class and type, the owner given
%% as written and as labels. A record whose owner is written alike is, and any
%% other owner compares as a name: in any case, with or without its final dot
-spec in_rrset(dns:rr(), dns:dname(), dns:labels() | invalid, dns:class(), dns:type()) ->
    boolean().
in_rrset(#dns_rr{name = Name, class = Class, type = Type}, Owner, Labels, Class, Type) ->
    Name =:= Owner orelse is_name(Name, Labels);
in_rrset(#dns_rr{}, _Owner, _Labels, _Class, _Type) ->
    false.

%% Whether a zone can hold an RRset of the type at the owner, as BIND checks it.
%% NS, SOA and DNSKEY RRsets are at the apex, and NSEC3 RRsets one label under
%% it (RFC5155§3). A DS RRset is in the zone above the delegation (RFC4034§5),
%% never in the zone it delegates to. Any other RRset is at the apex or under it.
-spec can_hold(dns:labels(), dns:type(), dns:labels()) -> boolean().
can_hold(Zone, Type, Owner) when
    Type =:= ?DNS_TYPE_NS orelse Type =:= ?DNS_TYPE_SOA orelse Type =:= ?DNS_TYPE_DNSKEY
->
    dns_domain:are_equal_labels(Owner, Zone);
can_hold(Zone, ?DNS_TYPE_NSEC3, [_Hash | Parent]) ->
    dns_domain:are_equal_labels(Parent, Zone);
can_hold(_Zone, ?DNS_TYPE_NSEC3, []) ->
    false;
can_hold(Zone, ?DNS_TYPE_DS, Owner) ->
    length(Zone) < length(Owner) andalso is_at_or_under(Owner, Zone);
can_hold(Zone, _Type, Owner) ->
    is_at_or_under(Owner, Zone).

-spec verify_with_key(dns:uint8(), key(), binary(), iodata()) -> boolean().
verify_with_key(Alg, Key, Signature, SigInput) ->
    refused_as_false(fun() -> verify(Alg, Key, Signature, SigInput) end).

%% The key and the signature come off the wire, so what crypto cannot verify
%% does not verify: key material it refuses, such as an ECDSA key that is no
%% point on its curve (badarg), an algorithm it lacks (notsup), or one its policy
%% refuses (error), as RHEL 9's default policy refuses DSA's SHA-1. Any error
%% that is not crypto's is raised.
-spec refused_as_false(fun(() -> boolean())) -> boolean().
refused_as_false(Verify) ->
    try
        Verify()
    catch
        error:{Error, {_File, _Line}, _Reason} when
            Error =:= badarg; Error =:= notsup; Error =:= error
        ->
            false
    end.

%% A key or signature of the wrong shape for its algorithm, or an algorithm this
%% module does not implement, verifies nothing
-spec verify(dns:uint8(), key(), binary(), iodata()) -> boolean().
verify(Alg, Key, <<_T, R:20/unit:8, S:20/unit:8>>, SigInput) when
    Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA
->
    case dsa_public_key(Key) of
        [_P, _Q, _G, _Y] = PublicKey ->
            AsnSig = public_key:der_encode('Dss-Sig-Value', #'Dss-Sig-Value'{r = R, s = S}),
            crypto:verify(dss, sha, SigInput, AsnSig, key_binaries(PublicKey));
        _ ->
            false
    end;
verify(Alg, Key, Signature, SigInput) when
    Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    case rsa_public_key(Key) of
        [_E, _M] = PublicKey ->
            [_, Modulus] = Binaries = key_binaries(PublicKey),
            {Hash, Msg} = rsa_message(Alg, SigInput),
            Opts = [{rsa_padding, rsa_pkcs1_padding}],
            %% RFC8017§8.2.2: the signature is as long as the modulus. crypto checks
            %% that when it hashes, but not for SHA-1, whose DigestInfo is built here
            byte_size(Signature) =:= byte_size(Modulus) andalso
                crypto:verify(rsa, Hash, Msg, Signature, Binaries, Opts);
        _ ->
            false
    end;
verify(?DNS_ALG_ECDSAP256SHA256, <<_:64/binary>> = Key, <<_:64/binary>> = Signature, SigInput) ->
    DerSig = ecdsa_wire_to_der(Signature, 32),
    crypto:verify(ecdsa, sha256, SigInput, DerSig, [<<4, Key/binary>>, secp256r1]);
verify(?DNS_ALG_ECDSAP384SHA384, <<_:96/binary>> = Key, <<_:96/binary>> = Signature, SigInput) ->
    DerSig = ecdsa_wire_to_der(Signature, 48),
    crypto:verify(ecdsa, sha384, SigInput, DerSig, [<<4, Key/binary>>, secp384r1]);
verify(?DNS_ALG_ED25519, <<_:32/binary>> = Key, <<_:64/binary>> = Signature, SigInput) ->
    crypto:verify(eddsa, none, SigInput, Signature, [Key, ed25519]);
verify(?DNS_ALG_ED448, <<_:57/binary>> = Key, <<_:114/binary>> = Signature, SigInput) ->
    crypto:verify(eddsa, none, SigInput, Signature, [Key, ed448]);
verify(_Alg, _Key, _Signature, _SigInput) ->
    false.

%% RFC4034§3.1.8.1: the RRSIG RDATA without its signature, then the RRset in
%% canonical form and order, each record once (RFC4034§6.2, §6.3). RFC4035§5.3.2:
%% each record goes in with the RRSIG's original TTL, whatever TTL it arrived
%% with, as one from a cache arrives decremented, and with the owner the RRSIG's
%% labels field gives it.
-spec signed_data(dns:rrdata_rrsig(), [dns:rr(), ...]) -> iodata().
signed_data(
    #dns_rrdata_rrsig{labels = Labels, original_ttl = TTL} = RRSig,
    [#dns_rr{name = Name, class = Class, type = Type} | _] = RRs
) ->
    LName = dns_domain:to_lower(Name),
    Owner = signed_owner(LName, Labels),
    OwnerBin = dns_domain:to_wire(Owner),
    RecordBase = <<OwnerBin/binary, Type:16, Class:16, TTL:32>>,
    Datas = lists:usort([canonical_rrdata_bin(RR) || RR <- RRs]),
    RRSetBin = [<<RecordBase/binary, (byte_size(Data)):16, Data/binary>> || Data <- Datas],
    [rrsig_to_digestable(RRSig) | RRSetBin].

%% RFC4035§5.3.2: an RRset a wildcard was expanded into is signed as the
%% wildcard, "*" and the last Labels labels of its owner
-spec signed_owner(dns:dname(), dns:uint8()) -> dns:dname().
signed_owner(Name, Labels) ->
    case dns_domain:split(Name) of
        Split when Labels < length(Split) ->
            dns_domain:join([~"*" | lists:nthtail(length(Split) - Labels, Split)]);
        _ ->
            Name
    end.

%% RFC3110§3, RFC5702§3: RSASSA-PKCS1-v1_5, whose DigestInfo crypto builds from
%% the hash it is given. An OpenSSL whose policy refuses SHA-1 signatures, as
%% RHEL 9's default does, then refuses RSA/SHA-1, which validators must still
%% implement (RFC9905), so for SHA-1 the DigestInfo is built here.
-spec rsa_message(dns:uint8(), iodata()) -> {none | sha256 | sha512, iodata()}.
rsa_message(Alg, Data) when Alg =:= ?DNS_ALG_RSASHA1 orelse Alg =:= ?DNS_ALG_NSEC3RSASHA1 ->
    {none, [?SHA1_DIGESTINFO, crypto:hash(sha, Data)]};
rsa_message(?DNS_ALG_RSASHA256, Data) ->
    {sha256, Data};
rsa_message(?DNS_ALG_RSASHA512, Data) ->
    {sha512, Data}.

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

-spec add_keytag_to_key_rr(dns:rr(), dns:rrdata(), dns:type()) -> dns:rr().
add_keytag_to_key_rr(RR, Data, Type) ->
    KeyBin = dns_encode:encode_rrdata(?DNS_CLASS_IN, Data),
    NewData = dns_decode:decode_rrdata(KeyBin, ?DNS_CLASS_IN, Type),
    RR#dns_rr{data = NewData}.

%% RFC4034 Appendix B: a DNSKEY's key tag, computed from its RDATA, as its keytag
%% field may be unset or out of date in a DNSKEY built by hand. A key that does
%% not encode, such as one given as iodata, has none. The RDATA is not decoded,
%% which would only turn an RSA or DSA key into integers to throw away
-spec key_tag(dns:rr()) -> dns:uint16() | undefined.
key_tag(#dns_rr{data = #dns_rrdata_dnskey{} = Data}) ->
    try dns_encode:encode_rrdata(?DNS_CLASS_IN, Data) of
        RData -> dns_decode:bin_to_key_tag(RData)
    catch
        error:_ -> undefined
    end.

-spec rrsig_to_digestable(dns:rrdata_rrsig()) -> binary().
rrsig_to_digestable(#dns_rrdata_rrsig{} = Data) ->
    %% RFC4034§6.2, RFC6840§5.1: in canonical form, the signer's name lowercased
    Canonical = canonical_rrdata_form(Data#dns_rrdata_rrsig{signature = <<>>}),
    dns_encode:encode_rrdata(?DNS_CLASS_IN, Canonical).

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

%% The names between a name and its zone, each by its name_key/1, which both are
%% compared by, so that the zone's name can be written as the records' are not
-spec name_ancestors(dns:dname(), dns:dname()) -> [binary()].
name_ancestors(Name, ZoneName) ->
    gen_name_ancestors(name_key(Name), name_key(ZoneName)).

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
                    %% split/1 unescapes the labels, so a dot in one is escaped again
                    [FirstLabel | Labels] = [
                        dns_domain:escape_label(Label)
                     || Label <- lists:reverse(Labels0)
                    ],
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

%% A name's labels, or invalid for a name no decoder or zone file gives: one with
%% an empty label, a label over 63 octets, or over 255 octets in all (RFC1035§2.3.4)
-spec name_labels(dns:dname()) -> dns:labels() | invalid.
name_labels(Name) ->
    try dns_domain:split(Name) of
        Labels ->
            case lists:sum([1 + byte_size(Label) || Label <- Labels]) < 255 of
                true -> Labels;
                false -> invalid
            end
    catch
        error:{invalid_dname, empty_label} -> invalid;
        error:{label_too_long, _} -> invalid
    end.

%% Whether a name is the one given as labels, which no invalid name is
-spec is_name(dns:dname(), dns:labels() | invalid) -> boolean().
is_name(_Name, invalid) ->
    false;
is_name(Name, Labels) ->
    case name_labels(Name) of
        invalid -> false;
        NameLabels -> dns_domain:are_equal_labels(NameLabels, Labels)
    end.

%% Whether a name is Zone or a name under it, both given as labels
-spec is_at_or_under(dns:labels(), dns:labels()) -> boolean().
is_at_or_under(Labels, Zone) ->
    Depth = length(Labels) - length(Zone),
    Depth >= 0 andalso dns_domain:are_equal_labels(lists:nthtail(Depth, Labels), Zone).

%% A DNSKEY decoded from the wire holds an RSA or DSA key as integers, and one
%% parsed from a zone file its RDATA bytes, which are read as the decoder reads
%% them. Bytes that do not parse stay a binary, which verifies nothing.
-spec rsa_public_key(key()) -> key().
rsa_public_key(Key) when is_binary(Key) -> dns_decode:rsa_public_key(Key);
rsa_public_key(Key) -> Key.

%% RFC2536§2: P, G and Y take 64 + 8T octets each. The decoder keeps the bytes of
%% a key whose T is wider than they need, only so that it encodes back
%% unchanged, so they are read here whatever T is
-spec dsa_public_key(key()) -> key().
dsa_public_key(<<T, Q:20/unit:8, PGY/binary>>) when
    T =< 8, byte_size(PGY) =:= 3 * (64 + 8 * T)
->
    S = 64 + 8 * T,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = PGY,
    [P, Q, G, Y];
dsa_public_key(Key) ->
    Key.

%% crypto takes a key's integers all as integers or all as binaries, and raises
%% badarith on a mix. It turns integers into binaries in time quadratic in their
%% length, which for an RSA modulus of 64 KB is over 100 ms, so it gets binaries.
-spec key_binaries([non_neg_integer() | binary()]) -> [binary()].
key_binaries(Key) ->
    [unsigned_binary(Field) || Field <- Key].

%% An integer of a key, given as an integer or as its big-endian bytes
-spec key_integer(non_neg_integer() | binary()) -> non_neg_integer().
key_integer(Field) when is_integer(Field) -> Field;
key_integer(Field) when is_binary(Field) -> binary:decode_unsigned(Field).

%% An integer of a key, given as an integer or as its big-endian bytes, as its
%% bytes without leading zeros
-spec unsigned_binary(non_neg_integer() | binary()) -> binary().
unsigned_binary(Field) when is_integer(Field) -> binary:encode_unsigned(Field);
unsigned_binary(<<0, Rest/binary>>) -> unsigned_binary(Rest);
unsigned_binary(Field) when is_binary(Field) -> Field.

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
