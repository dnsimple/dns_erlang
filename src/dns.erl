%% -------------------------------------------------------------------
%%
%% Copyright (c) 2010 Andrew Tunnell-Jones. All Rights Reserved.
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
-module(dns).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
The `dns` module is the primary entry point for the functionality in this library.
The module exports various types used in type specs, such as `t:message/0`, which indicates
a `#dns_message{}` record, `t:query/0` which represents a single `#dns_query{}` record,
`t:questions/0`, which represents a list of queries, etc.

It also exports functions for encoding and decoding messages,
TSIG supporting functions, and various utility functions for comparing domain names, converting
domain names into different cases, converting to and from label lists, etc.
""").

-export([decode_message/1, encode_message/1, encode_message/2]).
-export([verify_tsig/3, verify_tsig/4]).
-export([add_tsig/5, add_tsig/6]).
-export([compare_dname/2, escape_label/1]).
-export([dname_to_upper/1, dname_to_lower/1]).
-export([dname_to_labels/1, labels_to_dname/1]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-export([gen_tsig_mac/7]).

-include("dns.hrl").

%% 2^31 - 1, the largest signed 32-bit integer value
-define(MAX_INT32, ((1 bsl 31) - 1)).
-define(DEFAULT_TSIG_FUDGE, 5 * 60).

%% Types
?DOC("Unsigned 2-bits integer").
-type uint2() :: 0..1.
?DOC("Unsigned 4-bits integer").
-type uint4() :: 0..15.
?DOC("Unsigned 8-bits integer").
-type uint8() :: 0..((1 bsl 8) - 1).
?DOC("Unsigned 16-bits integer").
-type uint16() :: 0..((1 bsl 16) - 1).
?DOC("Unsigned 32-bits integer").
-type uint32() :: 0..((1 bsl 32) - 1).
?DOC("Unsigned 48-bits integer").
-type uint48() :: 0..((1 bsl 48) - 1).
?DOC("Unsigned 64-bits integer").
-type uint64() :: 0..((1 bsl 64) - 1).
-export_type([uint2/0, uint4/0, uint8/0, uint16/0, uint32/0, uint48/0, uint64/0]).

-export_type([
    message/0,
    message_id/0,
    message_bin/0,
    opcode/0,
    rcode/0,
    query/0,
    questions/0,
    rr/0,
    optrr/0,
    answers/0,
    authority/0,
    additional/0,
    dname/0,
    class/0,
    type/0,
    ttl/0,
    alg/0,
    label/0,
    tsig_mac/0,
    tsig_error/0,
    decode_error/0,
    ercode/0,
    eoptcode/0,
    llqopcode/0,
    llqerrcode/0,
    tsig_opt/0,
    encode_message_opt/0,
    rrdata/0,
    tsig_alg/0,
    optrr_elem/0,
    records/0,
    unix_time/0
]).
-export_type([
    opt_nsid/0,
    opt_ul/0,
    opt_ecs/0,
    opt_llq/0,
    opt_owner/0,
    opt_unknown/0,
    rrdata_rrsig/0,
    svcb_svc_params/0
]).
-export_type([
    encode_message_opts/0,
    encode_tsig_opts/0,
    tsig_opts/0
]).

-type decode_error() :: formerr | truncated | trailing_garbage.
-type message_bin() :: <<_:64, _:_*8>>.
-type message_id() :: uint16().
-type opcode() :: uint4().
-type rcode() :: uint4().
-type questions() :: [query()].
-type records() :: additional() | answers() | authority() | questions().
-type optrr_elem() :: opt_nsid() | opt_ul() | opt_unknown() | opt_ecs() | opt_llq() | opt_owner().

-type message() :: #dns_message{}.
-type query() :: #dns_query{}.
-type rr() :: #dns_rr{}.
-type optrr() :: #dns_optrr{}.
-type opt_nsid() :: #dns_opt_nsid{}.
-type opt_ul() :: #dns_opt_ul{}.
-type opt_ecs() :: #dns_opt_ecs{}.
-type opt_llq() :: #dns_opt_llq{}.
-type opt_owner() :: #dns_opt_owner{}.
-type opt_unknown() :: #dns_opt_unknown{}.
-type rrdata_rrsig() :: #dns_rrdata_rrsig{}.

-type svcb_svc_params() :: #{
    1..6 => none | char() | binary()
}.

-type answers() :: [rr()].
-type authority() :: [rr()].
-type additional() :: [optrr() | rr()].
-type dname() :: binary().
-type label() :: binary().
-type class() :: uint16().
-type type() :: uint16().
-type ttl() :: 0..?MAX_INT32.
-type rrdata() ::
    binary()
    | #dns_rrdata_a{}
    | #dns_rrdata_aaaa{}
    | #dns_rrdata_afsdb{}
    | #dns_rrdata_caa{}
    | #dns_rrdata_cdnskey{}
    | #dns_rrdata_cds{}
    | #dns_rrdata_cert{}
    | #dns_rrdata_cname{}
    | #dns_rrdata_dhcid{}
    | #dns_rrdata_dlv{}
    | #dns_rrdata_dname{}
    | #dns_rrdata_dnskey{}
    | #dns_rrdata_ds{}
    | #dns_rrdata_hinfo{}
    | #dns_rrdata_ipseckey{}
    | #dns_rrdata_key{}
    | #dns_rrdata_kx{}
    | #dns_rrdata_loc{}
    | #dns_rrdata_mb{}
    | #dns_rrdata_mg{}
    | #dns_rrdata_minfo{}
    | #dns_rrdata_mr{}
    | #dns_rrdata_mx{}
    | #dns_rrdata_naptr{}
    | #dns_rrdata_ns{}
    | #dns_rrdata_nsec{}
    | #dns_rrdata_nsec3{}
    | #dns_rrdata_nsec3param{}
    | #dns_rrdata_nxt{}
    | #dns_rrdata_ptr{}
    | #dns_rrdata_rp{}
    | #dns_rrdata_rrsig{}
    | #dns_rrdata_rt{}
    | #dns_rrdata_soa{}
    | #dns_rrdata_spf{}
    | #dns_rrdata_srv{}
    | #dns_rrdata_svcb{}
    | #dns_rrdata_sshfp{}
    | #dns_rrdata_tsig{}
    | #dns_rrdata_txt{}.
-type encode_message_opt() ::
    {max_size, 512..65535}
    | {tc_mode, default | axfr | llq_event}
    | {tsig, [encode_message_tsig_opt()]}.
-type encode_message_tsig_opt() ::
    {msgid, message_id()}
    | {alg, tsig_alg()}
    | {name, dname()}
    | {secret, binary()}
    | {errcode, tsig_error()}
    | {other, binary()}
    | tsig_opt().
-type unix_time() :: 0..4294967295.
-type tsig_mac() :: binary().
-type tsig_error() :: 0 | 16..18.
-type tsig_opt() ::
    {time, unix_time()}
    | {fudge, non_neg_integer()}
    | {mac, tsig_mac()}
    | {tail, boolean()}.
-type tsig_alg() :: binary().
-type alg() ::
    ?DNS_ALG_DSA
    | ?DNS_ALG_NSEC3DSA
    | ?DNS_ALG_RSASHA1
    | ?DNS_ALG_NSEC3RSASHA1
    | ?DNS_ALG_RSASHA256
    | ?DNS_ALG_RSASHA512.
-type eoptcode() :: 0..65535.
-type ercode() :: 0 | 16.
-type llqerrcode() :: 0..6.
-type llqopcode() :: 1..3.

-type encode_message_opts() :: #{
    max_size => 512..65535,
    tc_mode => default | axfr | llq_event,
    tsig => encode_tsig_opts()
}.

-type encode_tsig_opts() :: #{
    name := dname(),
    alg := tsig_alg(),
    msgid => message_id(),
    secret => binary(),
    errcode => tsig_error(),
    other => binary(),
    time => unix_time(),
    fudge => non_neg_integer(),
    mac => tsig_mac(),
    tail => boolean()
}.

-type tsig_opts() :: #{
    time => unix_time(),
    fudge => non_neg_integer(),
    mac => tsig_mac(),
    tail => boolean(),
    atom() => _
}.

%%%===================================================================
%%% Message body functions
%%%===================================================================

?DOC("Decode a binary DNS message.").
-spec decode_message(message_bin()) ->
    {decode_error(), message() | undefined, binary()} | message().
decode_message(MsgBin) ->
    dns_decode:decode(MsgBin).

?DOC("Encode a dns_message record.").
-spec encode_message(message()) -> message_bin().
encode_message(Msg) ->
    dns_encode:encode(Msg).

%% @doc Encode a dns_message record - will truncate the message as needed.
-spec encode_message(message(), encode_message_opts()) ->
    {false, message_bin()}
    | {false, message_bin(), tsig_mac()}
    | {true, message_bin(), message()}
    | {true, message_bin(), tsig_mac(), message()}.
encode_message(Msg, Opts) ->
    dns_encode:encode(Msg, Opts).

%% @doc Returns a random integer suitable for use as DNS message identifier.
-spec random_id() -> message_id().
random_id() ->
    rand:uniform(65535).

%%%===================================================================
%%% TSIG functions
%%%===================================================================

%% @equiv verify_tsig(MsgBin, Name, Secret, [])
-spec verify_tsig(message_bin(), dname(), binary()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret) ->
    verify_tsig(MsgBin, Name, Secret, #{}).

%% @doc Verifies a TSIG message signature.
-spec verify_tsig(message_bin(), dname(), binary(), tsig_opts()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret, Options) ->
    {UnsignedMsgBin, #dns_rr{name = TName, data = TData}} = strip_tsig(MsgBin),
    case compare_dname(Name, TName) of
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
    EncodedName = dns_encode:encode_dname(Name),
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

%% @doc Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
%% @equiv add_tsig(Msg, Alg, Name, Secret, ErrCode, [])
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode) ->
    add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg}).

%% @doc Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error(), encode_tsig_opts()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    MsgId = Msg#dns_message.id,
    MsgBin = encode_message(Msg),
    Time = maps:get(time, Options, erlang:system_time(second)),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    Other = maps:get(other, Options, <<>>),
    EncName = dns_encode:encode_dname(Name),
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

-spec strip_tsig(message_bin()) -> {message_bin(), rr()}.
strip_tsig(
    <<_Id:16, _QR:1, _OC:4, _AA:1, _TC:1, _RD:1, _RA:1, _PR:1, _Z:2, _RC:4, _QC:16, _ANC:16,
        _AUC:16, ADC:16, _HRB/binary>>
) when
    ADC =:= 0
->
    throw(no_tsig);
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
            throw(trailing_garbage);
        _ ->
            throw(no_tsig)
    end.

-spec gen_tsig_mac(
    tsig_alg(), message_bin(), dname(), binary(), unix_time(), binary(), encode_tsig_opts()
) ->
    {ok, binary()} | {error, 17}.
gen_tsig_mac(Alg, Msg, NameBin, Secret, Time, Other, Options) ->
    MAC = maps:get(mac, Options, <<>>),
    Tail = maps:get(tail, Options, false),
    Fudge = maps:get(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    Err = maps:get(errcode, Options, ?DNS_TSIGERR_NOERROR),
    AlgBin = dns_encode:encode_dname(Alg),
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
    case dname_to_lower(Alg) of
        Alg -> undefined;
        AlgLower -> hmac_type(AlgLower)
    end.

%%%===================================================================
%%% Domain name functions
%%%===================================================================

%% @doc Splits a dname into a list of labels and removes unneeded escapes.
-spec dname_to_labels(dns:dname()) -> [dns:label()].
dname_to_labels(<<>>) ->
    [];
dname_to_labels(<<$.>>) ->
    [];
dname_to_labels(Name) ->
    do_dname_to_labels(<<>>, Name).

-spec do_dname_to_labels(binary(), binary()) -> [binary(), ...].
do_dname_to_labels(Label, <<>>) ->
    [Label];
do_dname_to_labels(Label, <<$.>>) ->
    [Label];
do_dname_to_labels(Label, <<$., Cs/binary>>) ->
    [Label | do_dname_to_labels(<<>>, Cs)];
do_dname_to_labels(Label, <<"\\.", Cs/binary>>) ->
    do_dname_to_labels(<<Label/binary, $.>>, Cs);
do_dname_to_labels(Label, <<C, Cs/binary>>) ->
    do_dname_to_labels(<<Label/binary, C>>, Cs).

%% @doc Compare two domain names insensitive of case.
-spec compare_dname(dname(), dname()) -> boolean().
compare_dname(Name, Name) ->
    true;
compare_dname(NameA, NameB) ->
    NameALwr = dname_to_lower(iolist_to_binary(NameA)),
    NameBLwr = dname_to_lower(iolist_to_binary(NameB)),
    NameALwr =:= NameBLwr.

%% @doc Escapes dots in a DNS label
-spec escape_label(label()) -> label().
escape_label(Label) when is_binary(Label) ->
    do_escape_label(<<>>, Label).

-spec do_escape_label(binary(), binary()) -> binary().
do_escape_label(Label, <<>>) ->
    Label;
do_escape_label(Cur, <<$., Rest/binary>>) ->
    do_escape_label(<<Cur/binary, "\\.">>, Rest);
do_escape_label(Cur, <<C, Rest/binary>>) ->
    do_escape_label(<<Cur/binary, C>>, Rest).

%% @private
%% @doc Joins a list of DNS labels, escaping where necessary.
-spec labels_to_dname([label()]) -> dname().
labels_to_dname(Labels) ->
    <<$., DName/binary>> = <<<<$., (escape_label(Label))/binary>> || Label <- Labels>>,
    DName.

-define(UP(X), (upper(X)):8).
%% @doc Returns provided name with case-insensitive characters in uppercase.
-spec dname_to_upper(dname()) -> dname().
dname_to_upper(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G), ?UP(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
dname_to_upper(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
dname_to_upper(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F)>> || <<A, B, C, D, E, F>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E)>> || <<A, B, C, D, E>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D)>> || <<A, B, C, D>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C)>> || <<A, B, C>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?UP(A), ?UP(B)>> || <<A, B>> <= Data>>;
dname_to_upper(Data) ->
    <<<<?UP(N)>> || <<N>> <= Data>>.

-define(LOW(X), (lower(X)):8).
%% @doc Returns provided name with case-insensitive characters in lowercase.
-spec dname_to_lower(dname()) -> dname().
dname_to_lower(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G), ?LOW(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
dname_to_lower(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
dname_to_lower(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F)>> || <<A, B, C, D, E, F>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E)>> || <<A, B, C, D, E>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D)>> || <<A, B, C, D>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C)>> || <<A, B, C>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?LOW(A), ?LOW(B)>> || <<A, B>> <= Data>>;
dname_to_lower(Data) ->
    <<<<?LOW(N)>> || <<N>> <= Data>>.

lower(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104,
            105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
            122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
            139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
            156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
            173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
            190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
            207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
            224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
            241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
    ).

upper(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
            81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131,
            132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
            149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
            166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
            183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
            217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            251, 252, 253, 254, 255}
    ).

%%%===================================================================
%%% Time functions
%%%===================================================================

%% @doc Return current unix time.
-spec unix_time() -> unix_time().
unix_time() ->
    unix_time(erlang:timestamp()).

%% @doc Return the unix time from a now or universal time.
-spec unix_time(erlang:timestamp() | calendar:datetime1970()) -> unix_time().
unix_time({_MegaSecs, _Secs, _MicroSecs} = NowTime) ->
    UniversalTime = calendar:now_to_universal_time(NowTime),
    unix_time(UniversalTime);
unix_time({{_, _, _}, {_, _, _}} = UniversalTime) ->
    % calendar:universal_time_to_system_time(UniversalTime),
    Epoch = {{1970, 1, 1}, {0, 0, 0}},
    (calendar:datetime_to_gregorian_seconds(UniversalTime) -
        calendar:datetime_to_gregorian_seconds(Epoch)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @doc Compares two equal sized binaries over their entire length.
%%      Returns immediately if sizes do not match.
-spec const_compare(dname(), dname()) -> boolean().
const_compare(A, B) when is_binary(A) andalso is_binary(B) andalso byte_size(A) =:= byte_size(B) ->
    const_compare(A, B, 0);
const_compare(A, B) when is_binary(A) andalso is_binary(B) ->
    false.

-spec const_compare(binary(), binary(), byte()) -> boolean().
const_compare(<<>>, <<>>, Result) ->
    0 =:= Result;
const_compare(<<C1, A/binary>>, <<C2, B/binary>>, Result) ->
    const_compare(A, B, Result bor (C1 bxor C2)).
