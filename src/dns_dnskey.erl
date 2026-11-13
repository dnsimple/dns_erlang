-module(dns_dnskey).
-moduledoc false.

%% The key field of a DNSKEY's or CDNSKEY's RDATA, which field/2 lays out for
%% dns_sec:dnskey_public_key/2: an RSA key's by RFC 3110 and RFC 5702, and a DSA
%% key's by RFC 2536. numbers/2 splits an RSA or DSA key field back into its
%% numbers for dns_sec:verify_rrsig/4 by the same rules, so that it verifies with
%% no key field that dnskey_public_key/2 would not make. And a record loaded from
%% JSON or a zone file is refused when fits/2 is false, so that no such key loads
%% either. key_tag/1 computes the key tag of a DNSKEY's or CDNSKEY's RDATA.

-include_lib("dns_erlang/include/dns.hrl").
-include("dns_sec_algs.hrl").

-export([field/2, numbers/2, fits/2, public_key/1, key_tag/1]).

%% The rule a key breaks, with the size in bits of the number that breaks it. It
%% never holds one of the key's numbers, as DSA signing lays out its private key
%% here too
-type why() ::
    number_not_bytes
    | key_shape
    | dsa_number_longer_than_p
    | {rsa_exponent_bits | rsa_modulus_bits | dsa_q_bits | dsa_p_bits, non_neg_integer()}.

%% A DNSKEY's or CDNSKEY's public_key, its RDATA's key field. One that is not a
%% binary, as RSA and DSA keys were before 6.0.0, raises
%% {badarg, public_key_not_binary}
-spec public_key(dynamic()) -> binary().
public_key(Key) when is_binary(Key) ->
    Key;
public_key(_Key) ->
    error({badarg, public_key_not_binary}).

%% RFC4034 Appendix B, from a DNSKEY's or CDNSKEY's RDATA. Algorithm 1, RSA/MD5, takes it from the
%% end of the modulus instead, which ends the RDATA: its third- and second-to-last octets, as
%% erratum 193 corrects Appendix B.1.
-spec key_tag(<<_:32, _:_*8>>) -> dns:uint16().
key_tag(<<_:24, ?DNS_ALG_RSAMD5_NUMBER, _/binary>> = RData) ->
    Skip = byte_size(RData) - 3,
    <<_:Skip/binary, KeyTag:16, _:8>> = RData,
    KeyTag;
key_tag(RData) when is_binary(RData) ->
    key_tag_sum(RData, 0).

-spec key_tag_sum(binary(), non_neg_integer()) -> dns:uint16().
key_tag_sum(<<>>, AC) ->
    (AC + ((AC bsr 16) band 16#FFFF)) band 16#FFFF;
key_tag_sum(<<A:16, B:16, C:16, D:16, Rest/binary>>, AC) ->
    key_tag_sum(Rest, AC + A + B + C + D);
key_tag_sum(<<X:16, Rest/binary>>, AC) ->
    key_tag_sum(Rest, AC + X);
key_tag_sum(<<X:8>>, AC) ->
    key_tag_sum(<<>>, AC + (X bsl 8)).

%% The key field of a public key, as dns_sec:dnskey_public_key/2 documents it, and
%% with its errors: an RSA key [E, N] or a DSA key [P, Q, G, Y], each number as its
%% big-endian bytes, leading zeros allowed; an ECDSA point with the octet 4 in
%% front that marks it uncompressed, which RFC6605§4 leaves out; and an EdDSA or
%% ML-DSA-44 key as it is
-spec field(dns:uint8(), [binary()] | binary()) -> binary().
field(Alg, [E0, N0]) when ?IS_RSA_ALG(Alg) ->
    %% RFC3110§2: the exponent's length in one octet, or for one over 255 octets
    %% in a zero octet and two more, then the exponent and the modulus, neither
    %% with leading zero octets, of the sizes rsa_key_fits/3 allows
    E = unsigned_bytes(E0),
    N = unsigned_bytes(N0),
    case rsa_key_fits(Alg, E, N) of
        ok when byte_size(E) =< 255 -> <<(byte_size(E)), E/binary, N/binary>>;
        ok -> <<0, (byte_size(E)):16, E/binary, N/binary>>;
        Why -> error({badarg, Why})
    end;
field(Alg, [_, _, _, _] = Numbers) when ?IS_DSA_ALG(Alg) ->
    %% RFC2536§2: T, then Q in 20 octets, and P, G and Y in 64 + 8T each, with the
    %% T that dsa_t/4 gives
    [P, Q, G, Y] = [unsigned_bytes(Number) || Number <- Numbers],
    case dsa_t(P, Q, G, Y) of
        T when is_integer(T) ->
            Size = 64 + 8 * T,
            GField = pad(G, Size),
            YField = pad(Y, Size),
            <<T, Q/binary, P/binary, GField/binary, YField/binary>>;
        Why ->
            error({badarg, Why})
    end;
field(?DNS_ALG_ECDSAP256SHA256, <<4, Point:64/binary>>) ->
    Point;
field(?DNS_ALG_ECDSAP384SHA384, <<4, Point:96/binary>>) ->
    Point;
field(?DNS_ALG_ED25519, <<_:32/binary>> = Key) ->
    Key;
field(?DNS_ALG_ED448, <<_:57/binary>> = Key) ->
    Key;
field(?DNS_ALG_MLDSA44, <<_:1312/binary>> = Key) ->
    Key;
field(Alg, _Key) when
    ?IS_RSA_ALG(Alg);
    ?IS_DSA_ALG(Alg);
    Alg =:= ?DNS_ALG_ECDSAP256SHA256;
    Alg =:= ?DNS_ALG_ECDSAP384SHA384;
    Alg =:= ?DNS_ALG_ED25519;
    Alg =:= ?DNS_ALG_ED448;
    Alg =:= ?DNS_ALG_MLDSA44
->
    error({badarg, key_shape});
field(Alg, _Key) ->
    error({unsupported_algorithm, Alg}).

%% The numbers of an RSA key [E, N] or a DSA key [P, Q, G, Y] in a key field, as
%% their big-endian bytes, or invalid for a field that field/2 would not lay out
-spec numbers(dns:uint8(), binary()) -> [binary()] | invalid.
numbers(Alg, Field) when ?IS_RSA_ALG(Alg) ->
    rsa_numbers(Alg, Field);
numbers(Alg, Field) when ?IS_DSA_ALG(Alg) ->
    dsa_numbers(Field).

%% Whether a DNSKEY or CDNSKEY may carry the key: for an RSA or DSA algorithm only
%% a field that field/2 would lay out. Keys of other algorithms are not looked at
%% here, nor keys that are not binaries, which the encoder refuses.
-spec fits(dynamic(), dynamic()) -> boolean().
fits(Alg, Key) when (?IS_RSA_ALG(Alg) orelse ?IS_DSA_ALG(Alg)) andalso is_binary(Key) ->
    numbers(Alg, Key) =/= invalid;
fits(_Alg, _Key) ->
    true.

-spec rsa_numbers(dns:uint8(), binary()) -> [binary()] | invalid.
rsa_numbers(Alg, <<0, Len:16, E:Len/binary, N/binary>>) when Len > 255 ->
    rsa_numbers(Alg, E, N);
rsa_numbers(Alg, <<Len, E:Len/binary, N/binary>>) when Len > 0 ->
    rsa_numbers(Alg, E, N);
rsa_numbers(_Alg, _Field) ->
    invalid.

-spec rsa_numbers(dns:uint8(), binary(), binary()) -> [binary()] | invalid.
rsa_numbers(Alg, <<EFirst, _/binary>> = E, <<NFirst, _/binary>> = N) when
    EFirst > 0, NFirst > 0
->
    case rsa_key_fits(Alg, E, N) of
        ok -> [E, N];
        _ -> invalid
    end;
rsa_numbers(_Alg, _E, _N) ->
    invalid.

%% RFC3110§2, §3, RFC5702§2: an RSA key's exponent is 1 to 4096 bits long, and its
%% modulus 512 to 4096 bits, or 1024 to 4096 for RSA/SHA-512
-spec rsa_key_fits(dns:uint8(), binary(), binary()) -> ok | why().
rsa_key_fits(Alg, E, N) ->
    MinBits =
        case Alg of
            ?DNS_ALG_RSASHA512 -> 1024;
            _ -> 512
        end,
    case {bit_length(E), bit_length(N)} of
        {EBits, _} when EBits =:= 0; EBits > 4096 -> {rsa_exponent_bits, EBits};
        {_, NBits} when NBits < MinBits; NBits > 4096 -> {rsa_modulus_bits, NBits};
        _ -> ok
    end.

%% The bits of a number given as its big-endian bytes
-spec bit_length(binary()) -> non_neg_integer().
bit_length(<<0, Rest/binary>>) ->
    bit_length(Rest);
bit_length(<<First, Rest/binary>>) ->
    8 * byte_size(Rest) + byte_bits(First);
bit_length(<<>>) ->
    0.

-spec byte_bits(byte()) -> 0..8.
byte_bits(0) ->
    0;
byte_bits(Byte) ->
    1 + byte_bits(Byte bsr 1).

-spec dsa_numbers(binary()) -> [binary()] | invalid.
dsa_numbers(
    <<T, Q:20/binary, P:(64 + 8 * T)/binary, G:(64 + 8 * T)/binary, Y:(64 + 8 * T)/binary>>
) when T =< 8 ->
    case dsa_t(P, Q, G, Y) of
        T -> [P, Q, G, Y];
        _ -> invalid
    end;
dsa_numbers(_Field) ->
    invalid.

%% RFC2536§2: the T of a DSA key, or the rule it breaks. Its Q is 160 bits long,
%% 2^159 < Q < 2^160, and its P is 512 + 64T bits long for a T of 0 to 8,
%% 2^(511+64T) < P < 2^(512+64T), so that both have their top bit set in their
%% fields. G and Y fit in the 64 + 8T octets of P. Only the sizes of P and Q are
%% told, as a DNSKEY shows them anyway; Y's is not, as X stands for it in signing
-spec dsa_t(binary(), binary(), binary(), binary()) -> 0..8 | why().
dsa_t(P, Q, G, Y) ->
    PBits = bit_length(P),
    case {bit_length(Q), max(bit_length(G), bit_length(Y))} of
        {QBits, _} when QBits =/= 160 -> {dsa_q_bits, QBits};
        _ when PBits < 512; PBits > 1024; PBits rem 64 =/= 0 -> {dsa_p_bits, PBits};
        {_, Longest} when Longest > PBits -> dsa_number_longer_than_p;
        _ -> (PBits - 512) div 64
    end.

%% A number given as its big-endian bytes, leading zeros left out. Anything else,
%% an integer included, raises {badarg, number_not_bytes}
-spec unsigned_bytes(dynamic()) -> binary().
unsigned_bytes(<<0, Rest/binary>>) ->
    unsigned_bytes(Rest);
unsigned_bytes(Number) when is_binary(Number) ->
    Number;
unsigned_bytes(_Number) ->
    error({badarg, number_not_bytes}).

%% A number in a field of Size octets, which it fits
-spec pad(binary(), pos_integer()) -> binary().
pad(Number, Size) ->
    <<0:((Size - byte_size(Number)) * 8), Number/binary>>.
