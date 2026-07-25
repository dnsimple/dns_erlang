%% Wire-format properties for RDATA, the ground the suite left uncovered:
%% prop_wire_roundtrip in dns_domain_SUITE covers only domain names, and the
%% encode/decode properties in dns_zone_prop cover the presentation format, so
%% nothing checked that RDATA survives a trip through the wire codec.
%%
%% The input is rdata bytes, not records, because that is what exposes a decoder
%% that quietly discards part of its input or mints a record the encoder cannot
%% handle. Of the wire bugs the audit turned up, these catch the URI targets
%% decoding used to rewrite, the DSA key whose fields were written too narrow, and
%% the KX record that crashed encode_rrdata/2.
%%
%% Two limits are worth knowing, so nobody reads a pass here as more than it is.
%% An error made symmetrically in both directions is invisible: LOC's reference
%% point was off by one in encode and decode alike, so every round-trip
%% succeeded -- only a known-answer vector catches that, which is why
%% loc_wire_reference_point exists. And rdata seeded by encoding a record cannot
%% catch the encoder dropping information, since the seed is already missing it;
%% handbuilt_rdata/0 spells such cases out on the wire instead.
-module(dns_wire_prop).
-compile([export_all, nowarn_export_all]).

-include_lib("proper/include/proper.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%% ============================================================================
%% Properties
%% ============================================================================

%% encode(decode(B)) =:= B. The wire form is authoritative: whatever we hand back
%% must be what arrived, since dnssec builds signature input by re-encoding
%% decoded records, so any rewrite here changes the bytes an RRSIG covers.
prop_rrdata_wire_fidelity() ->
    ?FORALL(
        {Type, Bin},
        rdata_case(),
        case decode(Type, Bin) of
            skip ->
                true;
            {typed, Data} ->
                case encode(Type, Data) of
                    {error, _} -> false;
                    Bin -> true;
                    Re -> permitted_normalisation(Type, Bin, Re)
                end
        end
    ).

%% Re-encoding must not destroy information: the re-encoded form has to decode
%% again, to the same value. This is what the DSA key bug violated -- it wrote
%% fields too narrow for their values, and the result decoded to nothing at all.
prop_rrdata_reencode_preserves_value() ->
    ?FORALL(
        {Type, Bin},
        rdata_case(),
        case decode(Type, Bin) of
            skip ->
                true;
            {typed, Data} ->
                case encode(Type, Data) of
                    {error, _} -> false;
                    Re -> decode(Type, Re) =:= {typed, Data}
                end
        end
    ).

%% Whatever normalising a decode does, it must converge after one pass, so that
%% a record does not keep drifting each time it is relayed.
prop_rrdata_reencode_idempotent() ->
    ?FORALL(
        {Type, Bin},
        rdata_case(),
        case decode(Type, Bin) of
            skip ->
                true;
            {typed, Data} ->
                case encode(Type, Data) of
                    {error, _} ->
                        false;
                    Once ->
                        case decode(Type, Once) of
                            {typed, Data2} -> encode(Type, Data2) =:= Once;
                            _ -> false
                        end
                end
        end
    ).

%% dns_encode:encode_rrdata/2 is exported and passes no compression map, and
%% dnssec builds canonical RDATA through it, so it has to handle every record the
%% codec can produce. A KX record crashed it with badmap, because that clause
%% reached for the compressing path directly instead of the wrapper that tolerates
%% a missing map -- invisible when encoding a whole message, where a map exists.
prop_rrdata_encode_never_raises() ->
    ?FORALL(
        Data,
        rrdata(),
        case encode(ignored, Data) of
            {error, _} -> false;
            Bin -> is_binary(Bin)
        end
    ).

%% ============================================================================
%% Permitted differences
%% ============================================================================

%% RFC5155§3.1.2: the NSEC3 flags octet defines only Opt-Out; the remaining bits
%% are reserved and MUST be ignored on receipt, so they are not carried in the
%% record and cannot be reproduced. Pinned exactly: nothing but those bits moves.
permitted_normalisation(?DNS_TYPE_NSEC3, <<HashAlg, Flags, Rest/binary>>, Re) ->
    Re =:= <<HashAlg, (Flags band 2#1), Rest/binary>> orelse
        dropped_empty_bitmap_block(?DNS_TYPE_NSEC3, <<HashAlg, Flags, Rest/binary>>, Re);
%% RFC4034§4.1.2: "Blocks with no types present MUST NOT be included", so a block
%% carrying no types is dropped rather than echoed back.
permitted_normalisation(Type, Bin, Re) when
    ?DNS_TYPE_NSEC =:= Type; ?DNS_TYPE_CSYNC =:= Type
->
    dropped_empty_bitmap_block(Type, Bin, Re);
%% RFC2535§5.2: the NXT bitmap is "no longer than necessary", so octets past the
%% highest type present must not be on the wire and are trimmed rather than echoed.
permitted_normalisation(?DNS_TYPE_NXT, Bin, Re) ->
    byte_size(Re) < byte_size(Bin) andalso nxt_types_of(Bin) =:= nxt_types_of(Re);
%% RFC1876§2: a LOC precision octet is a base times ten to an exponent, so base 0
%% means zero whatever the exponent -- 0x01 and 0x00 both encode zero, and 0x00 is
%% the canonical spelling. Deliberately narrow: a whitelist of "anything that
%% preserves the decoded value" would also have waved through the URI targets that
%% decoding used to rewrite, since those too decode alike either way.
permitted_normalisation(
    ?DNS_TYPE_LOC, <<V, S1, H1, T1, Rest/binary>>, <<V, S2, H2, T2, Rest/binary>>
) ->
    redundant_zero(S1, S2) andalso redundant_zero(H1, H2) andalso redundant_zero(T1, T2);
permitted_normalisation(_Type, _Bin, _Re) ->
    false.

redundant_zero(Octet, Octet) -> true;
redundant_zero(In, Out) -> In band 16#F0 =:= 0 andalso Out =:= 16#00.

nxt_types_of(Bin) ->
    case decode(?DNS_TYPE_NXT, Bin) of
        {typed, #dns_rrdata_nxt{types = T}} -> T;
        Other -> Other
    end.

%% Dropping empty blocks can only shorten the rdata, and must leave the covered
%% types untouched -- which rules out a corrupted bitmap masquerading as one.
dropped_empty_bitmap_block(Type, Bin, Re) ->
    byte_size(Re) < byte_size(Bin) andalso types_of(Type, Bin) =:= types_of(Type, Re).

types_of(Type, Bin) ->
    case decode(Type, Bin) of
        {typed, #dns_rrdata_nsec{types = T}} -> T;
        {typed, #dns_rrdata_nsec3{types = T}} -> T;
        {typed, #dns_rrdata_csync{types = T}} -> T;
        Other -> Other
    end.

%% ============================================================================
%% Helpers
%% ============================================================================

%% `skip` covers the two cases with nothing to assert: rdata the decoder rejects,
%% and rdata it keeps opaque (RFC3597), which is symmetric by construction.
decode(Type, Bin) ->
    try dns_decode:decode_rrdata(<<>>, ?DNS_CLASS_IN, Type, Bin) of
        Data when is_binary(Data) -> skip;
        Data -> {typed, Data}
    catch
        _:_ -> skip
    end.

encode(_Type, Data) ->
    try
        dns_encode:encode_rrdata(?DNS_CLASS_IN, Data)
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

%% ============================================================================
%% Generators
%% ============================================================================

%% Random bytes alone are useless here: they reach a structured decoder's pattern
%% almost never (measured over 10k draws -- TXT 0.4%, HINFO 0.06%, SOA 0%), so a
%% property fed only random bytes passes without testing anything. Seed instead
%% with rdata built by encoding a generated record, and mutate that, which lands
%% inside the decoders and still reaches their error paths.
rdata_case() ->
    frequency([
        {4, valid_rdata()},
        {4, mutated_rdata()},
        {3, handbuilt_rdata()},
        {1, random_rdata()}
    ]).

%% Encoding goes through the protected wrapper: an encoder that raises here would
%% otherwise kill the whole run during generation instead of failing a property,
%% which is how the KX crash first showed up. prop_rrdata_encode_never_raises/0
%% below is what actually holds it to account.
valid_rdata() ->
    ?LET(Data, rrdata(), {type_of(Data), safe_encode(Data)}).

safe_encode(Data) ->
    case encode(ignored, Data) of
        {error, _} -> <<>>;
        Bin -> Bin
    end.

mutated_rdata() ->
    ?LET(
        {{Type, Bin}, Mutation}, {valid_rdata(), mutation()}, {Type, apply_mutation(Mutation, Bin)}
    ).

random_rdata() ->
    ?LET({Type, Len}, {decodable_type(), integer(0, 48)}, {Type, binary(Len)}).

%% Built as bytes, never by encoding a record. Seeding only from the encoder
%% cannot catch the encoder dropping information: the seed would already be
%% missing it and would round-trip happily. The empty <character-string> the
%% encoder used to discard is exactly that case, so it has to be spelled on the
%% wire here.
handbuilt_rdata() ->
    oneof([
        ?LET({Type, Strings}, {charstring_type(), wire_charstrings()}, {Type, Strings}),
        %% HINFO is two character-strings, either of which may be empty
        ?LET(
            {A, B},
            {wire_charstring(), wire_charstring()},
            {?DNS_TYPE_HINFO, <<A/binary, B/binary>>}
        )
    ]).

charstring_type() ->
    oneof([?DNS_TYPE_TXT, ?DNS_TYPE_SPF, ?DNS_TYPE_RESINFO, ?DNS_TYPE_WALLET]).

wire_charstrings() ->
    ?LET(L, ?SUCHTHAT(L0, list(wire_charstring()), [] =/= L0), iolist_to_binary(L)).

wire_charstring() ->
    ?LET(B, bin(0, 6), <<(byte_size(B)), B/binary>>).

%% Every type dns_decode:decode_rrdata/4 has a clause for. Only random_rdata/0
%% needs this; the record generators carry their own types via type_of/1.
decodable_type() ->
    oneof([
        ?DNS_TYPE_A,
        ?DNS_TYPE_AAAA,
        ?DNS_TYPE_AFSDB,
        ?DNS_TYPE_CAA,
        ?DNS_TYPE_CDNSKEY,
        ?DNS_TYPE_CDS,
        ?DNS_TYPE_CERT,
        ?DNS_TYPE_CNAME,
        ?DNS_TYPE_CSYNC,
        ?DNS_TYPE_DHCID,
        ?DNS_TYPE_DLV,
        ?DNS_TYPE_DNAME,
        ?DNS_TYPE_DNSKEY,
        ?DNS_TYPE_DS,
        ?DNS_TYPE_DSYNC,
        ?DNS_TYPE_EUI48,
        ?DNS_TYPE_EUI64,
        ?DNS_TYPE_HINFO,
        ?DNS_TYPE_HTTPS,
        ?DNS_TYPE_IPSECKEY,
        ?DNS_TYPE_KEY,
        ?DNS_TYPE_KX,
        ?DNS_TYPE_LOC,
        ?DNS_TYPE_MB,
        ?DNS_TYPE_MG,
        ?DNS_TYPE_MINFO,
        ?DNS_TYPE_MR,
        ?DNS_TYPE_MX,
        ?DNS_TYPE_NAPTR,
        ?DNS_TYPE_NS,
        ?DNS_TYPE_NSEC,
        ?DNS_TYPE_NSEC3,
        ?DNS_TYPE_NSEC3PARAM,
        ?DNS_TYPE_NXT,
        ?DNS_TYPE_OPENPGPKEY,
        ?DNS_TYPE_PTR,
        ?DNS_TYPE_RESINFO,
        ?DNS_TYPE_RP,
        ?DNS_TYPE_RRSIG,
        ?DNS_TYPE_RT,
        ?DNS_TYPE_SMIMEA,
        ?DNS_TYPE_SOA,
        ?DNS_TYPE_SPF,
        ?DNS_TYPE_SRV,
        ?DNS_TYPE_SSHFP,
        ?DNS_TYPE_SVCB,
        ?DNS_TYPE_TLSA,
        ?DNS_TYPE_TSIG,
        ?DNS_TYPE_TXT,
        ?DNS_TYPE_URI,
        ?DNS_TYPE_WALLET,
        ?DNS_TYPE_ZONEMD
    ]).

mutation() ->
    oneof([{flip, integer(0, 47), integer(0, 255)}, {truncate, integer(1, 8)}, {append, binary(2)}]).

apply_mutation({flip, At, Byte}, Bin) when At < byte_size(Bin) ->
    <<Head:At/binary, _, Tail/binary>> = Bin,
    <<Head/binary, Byte, Tail/binary>>;
apply_mutation({truncate, N}, Bin) when N < byte_size(Bin) ->
    binary:part(Bin, 0, byte_size(Bin) - N);
apply_mutation({append, Extra}, Bin) ->
    <<Bin/binary, Extra/binary>>;
apply_mutation(_, Bin) ->
    Bin.

%% ============================================================================
%% Record generators
%% ============================================================================

rrdata() ->
    oneof([
        #dns_rrdata_a{ip = ip4()},
        #dns_rrdata_aaaa{ip = ip6()},
        ?LET({S, H}, {u16(), dname()}, #dns_rrdata_afsdb{subtype = S, hostname = H}),
        ?LET(
            {F, T, V},
            {u8(), bin(1, 15), bin(0, 20)},
            #dns_rrdata_caa{flags = F, tag = T, value = V}
        ),
        ?LET(
            {T, K, A, C},
            {u16(), u16(), u8(), bin(0, 20)},
            #dns_rrdata_cert{type = T, keytag = K, alg = A, cert = C}
        ),
        ?LET(N, dname(), #dns_rrdata_cname{dname = N}),
        ?LET(
            {S, F, T},
            {u32(), u16(), types()},
            #dns_rrdata_csync{soa_serial = S, flags = F, types = T}
        ),
        ?LET(B, bin(1, 20), #dns_rrdata_dhcid{data = B}),
        ?LET(N, dname(), #dns_rrdata_dname{dname = N}),
        ?LET(
            {K, A, D, Dg},
            {u16(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_ds{keytag = K, alg = A, digest_type = D, digest = Dg}
        ),
        ?LET(
            {K, A, D, Dg},
            {u16(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_cds{keytag = K, alg = A, digest_type = D, digest = Dg}
        ),
        ?LET(
            {K, A, D, Dg},
            {u16(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_dlv{keytag = K, alg = A, digest_type = D, digest = Dg}
        ),
        ?LET(
            {F, P, A, K},
            {u16(), u8(), u8(), bin(1, 24)},
            #dns_rrdata_dnskey{flags = F, protocol = P, alg = A, public_key = K}
        ),
        ?LET(
            {F, P, A, K},
            {u16(), u8(), u8(), bin(1, 24)},
            #dns_rrdata_cdnskey{flags = F, protocol = P, alg = A, public_key = K}
        ),
        ?LET(
            {R, S, P, T},
            {u16(), u8(), u16(), dname()},
            #dns_rrdata_dsync{rrtype = R, scheme = S, port = P, target = T}
        ),
        ?LET(B, bin(6, 6), #dns_rrdata_eui48{address = B}),
        ?LET(B, bin(8, 8), #dns_rrdata_eui64{address = B}),
        ?LET({C, O}, {bin(0, 20), bin(0, 20)}, #dns_rrdata_hinfo{cpu = C, os = O}),
        ?LET({P, T}, {u16(), dname()}, #dns_rrdata_https{
            svc_priority = P,
            target_name = T,
            svc_params = #{}
        }),
        ?LET(
            {P, A, K},
            {u8(), u8(), bin(1, 20)},
            #dns_rrdata_ipseckey{precedence = P, alg = A, gateway = <<>>, public_key = K}
        ),
        ?LET(
            {Ty, X, NT, Sg, P, A, K},
            {integer(0, 3), integer(0, 1), integer(0, 3), integer(0, 15), u8(), u8(), bin(1, 20)},
            #dns_rrdata_key{
                type = Ty,
                xt = X,
                name_type = NT,
                sig = Sg,
                protocol = P,
                alg = A,
                public_key = K
            }
        ),
        ?LET({P, E}, {u16(), dname()}, #dns_rrdata_kx{preference = P, exchange = E}),
        ?LET(
            {Sz, H, V, La, Lo, Al},
            {
                loc_precision(),
                loc_precision(),
                loc_precision(),
                loc_coord(),
                loc_coord(),
                integer(-100000, 100000)
            },
            #dns_rrdata_loc{size = Sz, horiz = H, vert = V, lat = La, lon = Lo, alt = Al}
        ),
        ?LET(N, dname(), #dns_rrdata_mb{madname = N}),
        ?LET(N, dname(), #dns_rrdata_mg{madname = N}),
        ?LET({R, E}, {dname(), dname()}, #dns_rrdata_minfo{rmailbx = R, emailbx = E}),
        ?LET(N, dname(), #dns_rrdata_mr{newname = N}),
        ?LET({P, E}, {u16(), dname()}, #dns_rrdata_mx{preference = P, exchange = E}),
        ?LET(
            {O, P, F, S, R, Rp},
            {u16(), u16(), bin(0, 4), bin(0, 8), ascii(0, 12), dname()},
            #dns_rrdata_naptr{
                order = O,
                preference = P,
                flags = F,
                services = S,
                regexp = R,
                replacement = Rp
            }
        ),
        ?LET(N, dname(), #dns_rrdata_ns{dname = N}),
        ?LET({N, T}, {dname(), types()}, #dns_rrdata_nsec{next_dname = N, types = T}),
        ?LET(
            {A, O, I, S, H, T},
            {u8(), boolean(), u16(), bin(0, 8), bin(1, 20), types()},
            #dns_rrdata_nsec3{
                hash_alg = A,
                opt_out = O,
                iterations = I,
                salt = S,
                hash = H,
                types = T
            }
        ),
        ?LET(
            {A, F, I, S},
            {u8(), u8(), u16(), bin(0, 8)},
            #dns_rrdata_nsec3param{hash_alg = A, flags = F, iterations = I, salt = S}
        ),
        ?LET({N, T}, {dname(), nxt_types()}, #dns_rrdata_nxt{dname = N, types = T}),
        ?LET(B, bin(1, 20), #dns_rrdata_openpgpkey{data = B}),
        ?LET(N, dname(), #dns_rrdata_ptr{dname = N}),
        ?LET(S, charstrings(), #dns_rrdata_resinfo{data = S}),
        ?LET({M, T}, {dname(), dname()}, #dns_rrdata_rp{mbox = M, txt = T}),
        ?LET(
            {Tc, A, L, Ot, Ex, In, K, Sn, Sg},
            {u16(), u8(), u8(), u32(), u32(), u32(), u16(), dname(), bin(1, 20)},
            #dns_rrdata_rrsig{
                type_covered = Tc,
                alg = A,
                labels = L,
                original_ttl = Ot,
                expiration = Ex,
                inception = In,
                keytag = K,
                signers_name = Sn,
                signature = Sg
            }
        ),
        ?LET({P, H}, {u16(), dname()}, #dns_rrdata_rt{preference = P, host = H}),
        ?LET(
            {U, S, M, C},
            {u8(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_smimea{usage = U, selector = S, matching_type = M, certificate = C}
        ),
        ?LET(
            {U, S, M, C},
            {u8(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_tlsa{usage = U, selector = S, matching_type = M, certificate = C}
        ),
        ?LET(
            {Mn, Rn, Se, Rf, Rt, Ex, Mi},
            {dname(), dname(), u32(), u32(), u32(), u32(), u32()},
            #dns_rrdata_soa{
                mname = Mn,
                rname = Rn,
                serial = Se,
                refresh = Rf,
                retry = Rt,
                expire = Ex,
                minimum = Mi
            }
        ),
        ?LET(S, charstrings(), #dns_rrdata_spf{spf = S}),
        ?LET(
            {P, W, Po, T},
            {u16(), u16(), u16(), dname()},
            #dns_rrdata_srv{priority = P, weight = W, port = Po, target = T}
        ),
        ?LET(
            {A, F, Fp},
            {u8(), u8(), bin(1, 20)},
            #dns_rrdata_sshfp{alg = A, fp_type = F, fp = Fp}
        ),
        ?LET({P, T}, {u16(), dname()}, #dns_rrdata_svcb{
            svc_priority = P,
            target_name = T,
            svc_params = #{}
        }),
        ?LET(
            {A, Ti, F, M, Mi, E, O},
            {dname(), u48(), u16(), bin(0, 32), u16(), u16(), bin(0, 4)},
            #dns_rrdata_tsig{
                alg = A,
                time = Ti,
                fudge = F,
                mac = M,
                msgid = Mi,
                err = E,
                other = O
            }
        ),
        ?LET(S, charstrings(), #dns_rrdata_txt{txt = S}),
        ?LET({P, W, T}, {u16(), u16(), uri()}, #dns_rrdata_uri{
            priority = P,
            weight = W,
            target = T
        }),
        ?LET(S, charstrings(), #dns_rrdata_wallet{data = S}),
        ?LET(
            {Se, Sc, A, H},
            {u32(), u8(), u8(), bin(1, 20)},
            #dns_rrdata_zonemd{serial = Se, scheme = Sc, algorithm = A, hash = H}
        )
    ]).

%% ============================================================================
%% Field generators
%% ============================================================================

u8() -> integer(0, 255).
u16() -> integer(0, 65535).
u32() -> integer(0, 4294967295).
u48() -> integer(0, 281474976710655).

bin(Min, Max) -> ?LET(N, integer(Min, Max), binary(N)).
ascii(Min, Max) ->
    ?LET(N, integer(Min, Max), ?LET(L, vector(N, integer($a, $z)), list_to_binary(L))).

ip4() -> {u8(), u8(), u8(), u8()}.
ip6() -> {u16(), u16(), u16(), u16(), u16(), u16(), u16(), u16()}.

dname() -> dns_prop_generator:valid_dname().

%% At least one non-empty string, plus empty ones, which is the case the encoder
%% used to drop; nothing over 255 bytes, which the encoder legitimately splits.
charstrings() ->
    ?LET({Head, Rest}, {bin(1, 12), list(bin(0, 12))}, [Head | Rest]).

types() -> ?LET(L, list(u16()), lists:usort(L)).
%% RFC2535§5.2 gives NXT a windowless bitmap, so only low type numbers fit
nxt_types() -> ?LET(L, list(integer(0, 127)), lists:usort(L)).

%% RFC1876§2: base * 10^exp with both in 0..9, the only exactly representable values
loc_precision() -> ?LET({B, E}, {integer(0, 9), integer(0, 9)}, B * pow10(E)).
loc_coord() -> integer(-2147483648, 2147483647).

pow10(E) -> pow10(E, 1).
pow10(0, Acc) -> Acc;
pow10(E, Acc) -> pow10(E - 1, Acc * 10).

%% Targets that survive uri_string:normalize/1's validity check
uri() ->
    ?LET(
        {Scheme, Host, Path},
        {oneof([<<"http">>, <<"https">>, <<"ftp">>]), ascii(1, 8), ascii(0, 8)},
        <<Scheme/binary, "://", Host/binary, "/", Path/binary>>
    ).

%% ============================================================================
%% Type mapping
%% ============================================================================

%% Spelled out rather than derived from the record tag, so a record generated
%% without a matching entry fails to compile instead of being silently mistyped.
-spec type_of(dns:rrdata()) -> dns:type().
type_of(#dns_rrdata_a{}) -> ?DNS_TYPE_A;
type_of(#dns_rrdata_aaaa{}) -> ?DNS_TYPE_AAAA;
type_of(#dns_rrdata_afsdb{}) -> ?DNS_TYPE_AFSDB;
type_of(#dns_rrdata_caa{}) -> ?DNS_TYPE_CAA;
type_of(#dns_rrdata_cdnskey{}) -> ?DNS_TYPE_CDNSKEY;
type_of(#dns_rrdata_cds{}) -> ?DNS_TYPE_CDS;
type_of(#dns_rrdata_cert{}) -> ?DNS_TYPE_CERT;
type_of(#dns_rrdata_cname{}) -> ?DNS_TYPE_CNAME;
type_of(#dns_rrdata_csync{}) -> ?DNS_TYPE_CSYNC;
type_of(#dns_rrdata_dhcid{}) -> ?DNS_TYPE_DHCID;
type_of(#dns_rrdata_dlv{}) -> ?DNS_TYPE_DLV;
type_of(#dns_rrdata_dname{}) -> ?DNS_TYPE_DNAME;
type_of(#dns_rrdata_dnskey{}) -> ?DNS_TYPE_DNSKEY;
type_of(#dns_rrdata_ds{}) -> ?DNS_TYPE_DS;
type_of(#dns_rrdata_dsync{}) -> ?DNS_TYPE_DSYNC;
type_of(#dns_rrdata_eui48{}) -> ?DNS_TYPE_EUI48;
type_of(#dns_rrdata_eui64{}) -> ?DNS_TYPE_EUI64;
type_of(#dns_rrdata_hinfo{}) -> ?DNS_TYPE_HINFO;
type_of(#dns_rrdata_https{}) -> ?DNS_TYPE_HTTPS;
type_of(#dns_rrdata_ipseckey{}) -> ?DNS_TYPE_IPSECKEY;
type_of(#dns_rrdata_key{}) -> ?DNS_TYPE_KEY;
type_of(#dns_rrdata_kx{}) -> ?DNS_TYPE_KX;
type_of(#dns_rrdata_loc{}) -> ?DNS_TYPE_LOC;
type_of(#dns_rrdata_mb{}) -> ?DNS_TYPE_MB;
type_of(#dns_rrdata_mg{}) -> ?DNS_TYPE_MG;
type_of(#dns_rrdata_minfo{}) -> ?DNS_TYPE_MINFO;
type_of(#dns_rrdata_mr{}) -> ?DNS_TYPE_MR;
type_of(#dns_rrdata_mx{}) -> ?DNS_TYPE_MX;
type_of(#dns_rrdata_naptr{}) -> ?DNS_TYPE_NAPTR;
type_of(#dns_rrdata_ns{}) -> ?DNS_TYPE_NS;
type_of(#dns_rrdata_nsec{}) -> ?DNS_TYPE_NSEC;
type_of(#dns_rrdata_nsec3{}) -> ?DNS_TYPE_NSEC3;
type_of(#dns_rrdata_nsec3param{}) -> ?DNS_TYPE_NSEC3PARAM;
type_of(#dns_rrdata_nxt{}) -> ?DNS_TYPE_NXT;
type_of(#dns_rrdata_openpgpkey{}) -> ?DNS_TYPE_OPENPGPKEY;
type_of(#dns_rrdata_ptr{}) -> ?DNS_TYPE_PTR;
type_of(#dns_rrdata_resinfo{}) -> ?DNS_TYPE_RESINFO;
type_of(#dns_rrdata_rp{}) -> ?DNS_TYPE_RP;
type_of(#dns_rrdata_rrsig{}) -> ?DNS_TYPE_RRSIG;
type_of(#dns_rrdata_rt{}) -> ?DNS_TYPE_RT;
type_of(#dns_rrdata_smimea{}) -> ?DNS_TYPE_SMIMEA;
type_of(#dns_rrdata_soa{}) -> ?DNS_TYPE_SOA;
type_of(#dns_rrdata_spf{}) -> ?DNS_TYPE_SPF;
type_of(#dns_rrdata_srv{}) -> ?DNS_TYPE_SRV;
type_of(#dns_rrdata_sshfp{}) -> ?DNS_TYPE_SSHFP;
type_of(#dns_rrdata_svcb{}) -> ?DNS_TYPE_SVCB;
type_of(#dns_rrdata_tlsa{}) -> ?DNS_TYPE_TLSA;
type_of(#dns_rrdata_tsig{}) -> ?DNS_TYPE_TSIG;
type_of(#dns_rrdata_txt{}) -> ?DNS_TYPE_TXT;
type_of(#dns_rrdata_uri{}) -> ?DNS_TYPE_URI;
type_of(#dns_rrdata_wallet{}) -> ?DNS_TYPE_WALLET;
type_of(#dns_rrdata_zonemd{}) -> ?DNS_TYPE_ZONEMD.
