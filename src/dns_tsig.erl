-module(dns_tsig).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-export([verify_tsig/3, verify_tsig/4]).
-export([add_tsig/5, add_tsig/6]).
-export([encode_message_tsig_add/6, encode_message_tsig_size/3]).

-define(DEFAULT_TSIG_FUDGE, 5 * 60).

%% equiv verify_tsig(MsgBin, Name, Secret, #{})
-spec verify_tsig(dns:message_bin(), dns:dname(), binary()) ->
    {ok, dns:tsig_mac()} | {error, dns:tsig_error()}.
verify_tsig(MsgBin, Name, Secret) ->
    verify_tsig(MsgBin, Name, Secret, #{}).

%% Verifies a TSIG message signature.
-spec verify_tsig(dns:message_bin(), dns:dname(), binary(), dns:tsig_opts()) ->
    {ok, dns:tsig_mac()} | {error, dns:tsig_error()}.
verify_tsig(MsgBin, Name, Secret, Options) ->
    {UnsignedMsgBin, #dns_rr{name = TName, data = TData}} = strip_tsig(MsgBin),
    case dns_domain:are_equal(Name, TName) of
        true ->
            do_verify_tsig(UnsignedMsgBin, TData, Name, Secret, Options);
        false ->
            {error, ?DNS_TSIGERR_BADKEY}
    end.

do_verify_tsig(UnsignedMsgBin, TData, Name, Secret, Options) ->
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = CFudge,
        mac = CMAC,
        err = Err,
        other = Other
    } = TData,
    Now = maps:get(time, Options, erlang:system_time(second)),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    EncodedName = dns_domain:to_wire(Name),
    Options1 = Options#{fudge => CFudge, errcode => Err},
    case gen_tsig_mac(Alg, UnsignedMsgBin, EncodedName, Secret, Time, Other, Options1) of
        {ok, SMAC} ->
            case const_compare(CMAC, SMAC) of
                true ->
                    case (Time - Fudge) =< Now andalso Now =< (Time + Fudge) of
                        true ->
                            {ok, SMAC};
                        _ ->
                            {error, ?DNS_TSIGERR_BADTIME}
                    end;
                false ->
                    {error, ?DNS_TSIGERR_BADSIG}
            end;
        {error, Error} ->
            {error, Error}
    end.

%% Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
%% equiv add_tsig(Msg, Alg, Name, Secret, ErrCode, #{})
-spec add_tsig(dns:message(), dns:tsig_alg(), dns:dname(), binary(), dns:tsig_error()) ->
    dns:message().
add_tsig(Msg, Alg, Name, Secret, ErrCode) ->
    add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg}).

%% Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
-spec add_tsig(
    dns:message(), dns:tsig_alg(), dns:dname(), binary(), dns:tsig_error(), dns:encode_tsig_opts()
) ->
    dns:message().
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    MsgId = Msg#dns_message.id,
    MsgBin = dns_encode:encode(Msg),
    Time = maps:get(time, Options, erlang:system_time(second)),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    Other = maps:get(other, Options, <<>>),
    EncName = dns_domain:to_wire(Name),
    Options1 = Options#{errcode => ErrCode},
    {ok, MAC} = gen_tsig_mac(Alg, MsgBin, EncName, Secret, Time, Other, Options1),
    Data = #dns_rrdata_tsig{
        msgid = MsgId,
        alg = Alg,
        time = Time,
        fudge = Fudge,
        mac = MAC,
        err = ErrCode,
        other = Other
    },
    RR = #dns_rr{
        name = Name,
        class = ?DNS_CLASS_ANY,
        type = ?DNS_TYPE_TSIG,
        ttl = 0,
        data = Data
    },
    NewAdditional = Msg#dns_message.additional ++ [RR],
    NewADC = Msg#dns_message.adc + 1,
    Msg#dns_message{adc = NewADC, additional = NewAdditional}.

-spec strip_tsig(dns:message_bin()) -> {dns:message_bin(), dns:rr()}.
strip_tsig(
    <<_Id:16, _QR:1, _OC:4, _AA:1, _TC:1, _RD:1, _RA:1, _PR:1, _Z:2, _RC:4, _QC:16, _ANC:16,
        _AUC:16, ADC:16, _HRB/binary>>
) when
    ADC =:= 0
->
    error(no_tsig);
strip_tsig(
    <<_Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, PR:1, Z:2, RC:4, QC:16, ANC:16, AUC:16, ADC:16,
        HRB/binary>> = MsgBin
) ->
    UnsignedADC = ADC - 1,
    {_Questions, QRB} = dns_decode:decode_message_questions(MsgBin, HRB, QC),
    {_Answers, TSIGBin} = dns_decode:decode_message_body(MsgBin, QRB, ANC + AUC + UnsignedADC),
    case dns_decode:decode_message_additional(MsgBin, TSIGBin, 1) of
        {[#dns_rr{data = #dns_rrdata_tsig{msgid = NewId}} = TSigRR], <<>>} ->
            MsgBodyLen = byte_size(HRB) - byte_size(TSIGBin),
            {UnsignedBodyBin, TSIGBin} = split_binary(HRB, MsgBodyLen),
            UnsignedMsgBin =
                <<NewId:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, PR:1, Z:2, RC:4, QC:16, ANC:16,
                    AUC:16, UnsignedADC:16, UnsignedBodyBin/binary>>,
            {UnsignedMsgBin, TSigRR};
        {[#dns_rr{data = #dns_rrdata_tsig{}}], _} ->
            error(trailing_garbage);
        _ ->
            error(no_tsig)
    end.

-spec encode_message_tsig_size(binary(), dns:message_bin(), bitstring()) -> pos_integer().
encode_message_tsig_size(EncodedName, Alg, Other) ->
    NameSize = byte_size(EncodedName),
    AlgSize = byte_size(dns_domain:to_wire(Alg)),
    MACSize =
        case Alg of
            ?DNS_TSIG_ALG_MD5 -> 16;
            ?DNS_TSIG_ALG_SHA1 -> 20;
            ?DNS_TSIG_ALG_SHA224 -> 28;
            ?DNS_TSIG_ALG_SHA256 -> 32;
            ?DNS_TSIG_ALG_SHA384 -> 48;
            ?DNS_TSIG_ALG_SHA512 -> 64
        end,
    OtherSize = byte_size(Other),
    DataSize = AlgSize + 16 + MACSize + OtherSize,
    NameSize + 10 + DataSize.

-spec encode_message_tsig_add(
    dns:message_id(),
    binary(),
    dns:message_bin(),
    binary(),
    dns:encode_tsig_opts(),
    dns:message_bin()
) -> {dns:message_bin(), binary()}.
encode_message_tsig_add(
    MsgId,
    EncodedName,
    LowerAlg,
    Other,
    Options,
    <<OrigMsgId:16, Head:8/binary, ADC:16, Body/binary>> = MsgBin
) ->
    Secret = maps:get(secret, Options, <<>>),
    Time = maps:get(time, Options, erlang:system_time(second)),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    Err = maps:get(errcode, Options, ?DNS_TSIGERR_NOERROR),
    case gen_tsig_mac(LowerAlg, MsgBin, EncodedName, Secret, Time, Other, Options) of
        {ok, MAC} ->
            MS = byte_size(MAC),
            OLen = byte_size(Other),
            AlgBin = dns_domain:to_wire(LowerAlg),
            TSIGData =
                <<AlgBin/binary, Time:48, Fudge:16, MS:16, MAC:MS/binary, OrigMsgId:16, Err:16,
                    OLen:16, Other:OLen/binary>>,
            TSIGDataSize = byte_size(TSIGData),
            TSigRR =
                <<EncodedName/binary, ?DNS_TYPE_TSIG:16, ?DNS_CLASS_ANY:16, 0:32, TSIGDataSize:16,
                    TSIGData/binary>>,
            MsgBin0 = <<MsgId:16, Head/binary, (ADC + 1):16, Body/binary, TSigRR/binary>>,
            {MsgBin0, MAC};
        {error, _} ->
            erlang:error(badarg)
    end.

-spec gen_tsig_mac(
    dns:tsig_alg(),
    dns:message_bin(),
    dns:dname(),
    binary(),
    dns:unix_time(),
    binary(),
    dns:encode_tsig_opts()
) ->
    {ok, binary()} | {error, 17}.
gen_tsig_mac(Alg, Msg, NameBin, Secret, Time, Other, Options) ->
    MAC = maps:get(mac, Options, <<>>),
    Tail = maps:get(tail, Options, false),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    Err = maps:get(errcode, Options, ?DNS_TSIGERR_NOERROR),
    AlgBin = dns_domain:to_wire(Alg),
    OLen = byte_size(Other),
    PMAC =
        case MAC of
            <<>> -> MAC;
            _ -> <<(byte_size(MAC)):16, MAC/binary>>
        end,
    Data =
        case Tail of
            true ->
                [PMAC, Msg, <<Time:48>>, <<Fudge:16>>];
            false ->
                [
                    PMAC,
                    Msg,
                    NameBin,
                    <<?DNS_CLASS_ANY:16>>,
                    <<0:32>>,
                    AlgBin,
                    <<Time:48>>,
                    <<Fudge:16>>,
                    <<Err:16>>,
                    <<OLen:16>>,
                    Other
                ]
        end,
    case hmac(Alg, Secret, Data) of
        {ok, _MAC} = Result -> Result;
        {error, bad_alg} -> {error, ?DNS_TSIGERR_BADKEY}
    end.

-spec hmac(binary(), binary(), [bitstring(), ...]) -> {ok, binary()} | {error, bad_alg}.
hmac(TypeBin, Key, Data) ->
    case hmac_type(TypeBin) of
        undefined -> {error, bad_alg};
        TypeAtom -> {ok, crypto:mac(hmac, TypeAtom, Key, Data)}
    end.

-spec hmac_type(binary()) ->
    md5 | sha | sha224 | sha256 | sha384 | sha512 | undefined.
hmac_type(?DNS_TSIG_ALG_MD5) ->
    md5;
hmac_type(?DNS_TSIG_ALG_SHA1) ->
    sha;
hmac_type(?DNS_TSIG_ALG_SHA224) ->
    sha224;
hmac_type(?DNS_TSIG_ALG_SHA256) ->
    sha256;
hmac_type(?DNS_TSIG_ALG_SHA384) ->
    sha384;
hmac_type(?DNS_TSIG_ALG_SHA512) ->
    sha512;
hmac_type(Alg) ->
    case dns_domain:to_lower(Alg) of
        Alg -> undefined;
        AlgLower -> hmac_type(AlgLower)
    end.

%% Compares two equal sized binaries over their entire length.
%%      Returns immediately if sizes do not match.
-spec const_compare(dns:dname(), dns:dname()) -> boolean().
const_compare(A, B) when is_binary(A) andalso is_binary(B) andalso byte_size(A) =:= byte_size(B) ->
    const_compare(A, B, 0);
const_compare(A, B) when is_binary(A) andalso is_binary(B) ->
    false.

-spec const_compare(binary(), binary(), byte()) -> boolean().
const_compare(<<>>, <<>>, Result) ->
    0 =:= Result;
const_compare(<<C1, A/binary>>, <<C2, B/binary>>, Result) ->
    const_compare(A, B, Result bor (C1 bxor C2)).
