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
The module exports various types used in type specs, such as `message()`, which indicates
a `#dns_message{}` record, `query()` which represents a single `#dns_query{}` record,
`questions()`, which represents a list of queries, etc.

It also exports functions for encoding and decoding messages,
TSIG supporting functions, and various utility functions for comparing domain names, converting
domain names into different cases, converting to and from label lists, etc.
""").

-export([decode_message/1, encode_message/1, encode_message/2]).
-export([verify_tsig/3, verify_tsig/4]).
-export([add_tsig/5, add_tsig/6]).

-export([compare_dname/2]).
-export([dname_to_upper/1, dname_to_lower/1]).
-export([dname_to_labels/1, labels_to_dname/1, escape_label/1]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-export([
    class_name/1,
    type_name/1,
    rcode_name/1,
    opcode_name/1,
    tsigerr_name/1,
    ercode_name/1,
    eoptcode_name/1,
    llqopcode_name/1,
    llqerrcode_name/1,
    alg_name/1
]).

-export([const_compare/2]).

%% Private
-export([encode_rrdata/2, decode_rrdata/3]).
-export([encode_dname/1]).

-ifdef(TEST).
-export([encode_rrdata/4, decode_rrdata/4]).
-export([encode_svcb_svc_params/1, decode_svcb_svc_params/1]).
-export([encode_optrrdata/1, decode_optrrdata/1]).
-export([encode_dname/3, encode_dname/4, decode_dname/2]).
-endif.

-include("dns.hrl").

%% 2^31 - 1, the largest signed 32-bit integer value
-define(MAX_INT32, ((1 bsl 31) - 1)).

%% Types
-type uint2() :: 0..1.
-type uint4() :: 0..15.
-type uint8() :: 0..((1 bsl 8) - 1).
-type uint16() :: 0..((1 bsl 16) - 1).
-type uint32() :: 0..((1 bsl 32) - 1).
-type uint48() :: 0..((1 bsl 48) - 1).
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

-type decode_error() :: formerr | truncated | trailing_garbage.
-type message_bin() :: <<_:64, _:_*8>>.
-type message_id() :: uint16().
-type opcode() :: uint4().
-type rcode() :: uint4().
-type questions() :: [query()].

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
-type additional() :: [optrr() | [rr()]] | [rr()].
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

-define(DEFAULT_TSIG_FUDGE, 5 * 60).

%%%===================================================================
%%% Message body functions
%%%===================================================================

%% @doc Decode a binary DNS message.
-spec decode_message(message_bin()) ->
    {decode_error(), message() | undefined, binary()} | message().
decode_message(
    <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, 0:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
        ADC:16, Rest/binary>> = MsgBin
) ->
    try
        #dns_message{
            id = Id,
            qr = decode_bool(QR),
            oc = OC,
            aa = decode_bool(AA),
            tc = decode_bool(TC),
            rd = decode_bool(RD),
            ra = decode_bool(RA),
            ad = decode_bool(AD),
            cd = decode_bool(CD),
            rc = RC,
            qc = QC,
            anc = ANC,
            auc = AUC,
            adc = ADC
        }
    of
        #dns_message{} = Msg ->
            decode_message(questions, MsgBin, Rest, Msg)
    catch
        _ -> {formerr, undefined, MsgBin}
    end;
decode_message(<<_/binary>> = MsgBin) ->
    {formerr, undefined, MsgBin}.

-spec decode_message(
    additional | answers | authority | finished | questions, <<_:64, _:_*8>>, binary(), message()
) ->
    {atom(), message(), binary()} | message().
decode_message(questions, MsgBin, QBody, #dns_message{qc = QC} = Msg) ->
    case decode_message_questions(QBody, QC, MsgBin) of
        {Questions, Rest} ->
            NewMsg = Msg#dns_message{questions = Questions},
            decode_message(answers, MsgBin, Rest, NewMsg);
        {Error, Questions, Rest} ->
            NewMsg = Msg#dns_message{questions = Questions},
            {Error, NewMsg, Rest}
    end;
decode_message(
    Section,
    MsgBin,
    Body,
    #dns_message{anc = ANC, auc = AUC, adc = ADC} = Msg
) when
    Section =:= answers orelse
        Section =:= authority orelse
        Section =:= additional
->
    {C, Next} =
        case Section of
            answers -> {ANC, authority};
            authority -> {AUC, additional};
            additional -> {ADC, finished}
        end,
    case decode_message_body(Body, C, MsgBin) of
        {RR, Rest} ->
            NewMsg = add_rr_to_section(Section, Msg, RR),
            decode_message(Next, MsgBin, Rest, NewMsg);
        {Error, RR, Rest} ->
            NewMsg = add_rr_to_section(Section, Msg, RR),
            {Error, NewMsg, Rest}
    end;
decode_message(finished, _MsgBin, <<>>, #dns_message{} = Msg) ->
    Msg;
decode_message(finished, _MsgBin, Bin, #dns_message{} = Msg) when
    is_binary(Bin)
->
    {trailing_garbage, Msg, Bin}.

-spec decode_message_questions(binary(), char(), message_bin()) ->
    {questions(), binary()} | {decode_error(), questions(), binary()}.
decode_message_questions(DataBin, Count, MsgBin) ->
    decode_message_questions(DataBin, Count, MsgBin, []).

-spec decode_message_questions(binary(), char(), message_bin(), questions()) ->
    {questions(), binary()} | {decode_error(), questions(), binary()}.
decode_message_questions(DataBin, 0, _MsgBin, Qs) ->
    {lists:reverse(Qs), DataBin};
decode_message_questions(<<>>, _Count, _MsgBin, Qs) ->
    {truncated, lists:reverse(Qs), <<>>};
decode_message_questions(DataBin, Count, MsgBin, Qs) ->
    try decode_dname(DataBin, MsgBin) of
        {Name, <<Type:16, Class:16, RB/binary>>} ->
            Q = #dns_query{name = Name, type = Type, class = Class},
            decode_message_questions(RB, Count - 1, MsgBin, [Q | Qs]);
        {_Name, _Bin} ->
            {truncated, lists:reverse(Qs), DataBin}
    catch
        Error when is_atom(Error) ->
            {Error, lists:reverse(Qs), DataBin};
        _:_ ->
            {formerr, lists:reverse(Qs), DataBin}
    end.

-spec decode_message_body(binary(), integer(), <<_:64, _:_*8>>) ->
    {[{_, _, _, _, _, _}], binary()} | {atom(), [{_, _, _, _, _, _}], binary()}.
decode_message_body(DataBin, Count, MsgBin) ->
    decode_message_body(DataBin, Count, MsgBin, []).

-spec decode_message_body(binary(), integer(), <<_:64, _:_*8>>, [optrr() | rr()]) ->
    {[{_, _, _, _, _, _}], binary()} | {atom(), [{_, _, _, _, _, _}], binary()}.
decode_message_body(<<>>, _Count, _MsgBin, RRs) ->
    {lists:reverse(RRs), <<>>};
decode_message_body(DataBin, 0, _MsgBin, RRs) ->
    {lists:reverse(RRs), DataBin};
decode_message_body(DataBin, Count, MsgBin, RRs) ->
    try decode_dname(DataBin, MsgBin) of
        {<<>>,
            <<?DNS_TYPE_OPT:16/unsigned, UPS:16/unsigned, ExtRcode:8, Version:8, DNSSEC:1, _Z:15,
                EDataLen:16, EDataBin:EDataLen/binary, RemBin/binary>>} ->
            Data = decode_optrrdata(EDataBin),
            RR = #dns_optrr{
                udp_payload_size = UPS,
                ext_rcode = ExtRcode,
                version = Version,
                dnssec = decode_bool(DNSSEC),
                data = Data
            },
            decode_message_body(RemBin, Count - 1, MsgBin, [RR | RRs]);
        {Name,
            <<Type:16/unsigned, Class:16/unsigned, TTL:32/signed, Len:16, RdataBin:Len/binary,
                RemBin/binary>>} ->
            RR = #dns_rr{
                name = Name,
                type = Type,
                class = Class,
                ttl = TTL,
                data = decode_rrdata(Class, Type, RdataBin, MsgBin)
            },
            decode_message_body(RemBin, Count - 1, MsgBin, [RR | RRs]);
        {_Name, <<_Type:16/unsigned, _Class:16/unsigned, _TTL:32/signed, Len:16, Data/binary>>} when
            byte_size(Data) < Len
        ->
            {truncated, lists:reverse(RRs), DataBin}
    catch
        Error when is_atom(Error) ->
            {Error, lists:reverse(RRs), DataBin};
        _:_ ->
            {formerr, lists:reverse(RRs), DataBin}
    end.

-spec add_rr_to_section(additional | answers | authority, message(), [optrr() | rr()]) ->
    message().
add_rr_to_section(answers, #dns_message{} = Msg, RR) ->
    Msg#dns_message{answers = RR};
add_rr_to_section(authority, #dns_message{} = Msg, RR) ->
    Msg#dns_message{authority = RR};
add_rr_to_section(additional, #dns_message{} = Msg, RR) ->
    Msg#dns_message{additional = RR}.

%% @doc Encode a dns_message record.
-spec encode_message(message()) -> message_bin().
encode_message(
    #dns_message{
        questions = Questions,
        answers = Answers,
        authority = Authority,
        additional = Additional
    } = Msg
) ->
    Head = encode_message_head(Msg),
    Fun = fun(Rec, {CompMapTmp, BinTmp}) ->
        {CompMapTmp0, RecBin} =
            encode_message_rec(CompMapTmp, byte_size(BinTmp), Rec),
        {CompMapTmp0, <<BinTmp/binary, RecBin/binary>>}
    end,
    {CompMap0, QBin} = lists:foldl(Fun, {new_compmap(), Head}, Questions),
    {CompMap1, AnBin} = lists:foldl(Fun, {CompMap0, QBin}, Answers),
    {CompMap2, AuBin} = lists:foldl(Fun, {CompMap1, AnBin}, Authority),
    {_CompMap3, AdBin} = lists:foldl(Fun, {CompMap2, AuBin}, Additional),
    AdBin.

%% @doc Encode a dns_message record - will truncate the message as needed.
-spec encode_message(message(), [encode_message_opt()]) ->
    {false, message_bin()}
    | {true, message_bin(), message()}
    | {false, message_bin(), tsig_mac()}
    | {true, message_bin(), tsig_mac(), message()}.
encode_message(#dns_message{id = MsgId, additional = Additional} = Msg, Opts) ->
    EncodeFun = get_tc_mode_fun(Opts),
    MaxSize = get_max_size(Opts, Additional),
    case proplists:get_value(tsig, Opts) of
        undefined ->
            case EncodeFun(Msg, MaxSize) of
                {Bin, Leftover} -> {true, Bin, Leftover};
                Bin -> {false, Bin}
            end;
        TSIGOpts when is_list(TSIGOpts) ->
            OrigMsgId = proplists:get_value(msgid, TSIGOpts, MsgId),
            Alg = proplists:get_value(alg, TSIGOpts),
            Name = proplists:get_value(name, TSIGOpts),
            Secret = proplists:get_value(secret, TSIGOpts),
            Err = proplists:get_value(errcode, TSIGOpts, ?DNS_TSIGERR_NOERROR),
            Time = proplists:get_value(time, TSIGOpts, unix_time()),
            Fudge = proplists:get_value(fudge, TSIGOpts, ?DEFAULT_TSIG_FUDGE),
            PreviousMAC = proplists:get_value(mac, TSIGOpts, <<>>),
            Other = proplists:get_value(other, TSIGOpts, <<>>),
            Tail = proplists:get_bool(tail, TSIGOpts),
            TSIGSize = encode_message_tsig_size(Name, Alg, Other),
            Msg0 = Msg#dns_message{id = OrigMsgId},
            case EncodeFun(Msg0, MaxSize - TSIGSize) of
                {MsgBin, MsgLeftover} ->
                    MsgLeftover0 = MsgLeftover#dns_message{id = MsgId},
                    {MsgBin0, NewMAC} =
                        encode_message_tsig_add(
                            MsgId,
                            Name,
                            Alg,
                            Secret,
                            Time,
                            Fudge,
                            Err,
                            Other,
                            PreviousMAC,
                            Tail,
                            MsgBin
                        ),
                    {true, MsgBin0, NewMAC, MsgLeftover0};
                MsgBin ->
                    {MsgBin0, NewMAC} =
                        encode_message_tsig_add(
                            MsgId,
                            Name,
                            Alg,
                            Secret,
                            Time,
                            Fudge,
                            Err,
                            Other,
                            PreviousMAC,
                            Tail,
                            MsgBin
                        ),
                    {false, MsgBin0, NewMAC}
            end
    end.

-spec get_tc_mode_fun(proplists:proplist()) ->
    fun((message(), number()) -> message_bin() | {message_bin(), message()}).
get_tc_mode_fun(Opts) ->
    case proplists:get_value(tc_mode, Opts, default) of
        default ->
            fun encode_message_default/2;
        llq_event ->
            fun encode_message_llq/2;
        axfr ->
            fun encode_message_axfr/2;
        _ ->
            erlang:error(badarg)
    end.

-spec get_max_size(proplists:proplist(), _) -> 512..65535.
get_max_size(Opts, Additional) ->
    case {proplists:get_value(max_size, Opts), Additional} of
        {MaxSize, _} when
            is_integer(MaxSize) andalso 512 =< MaxSize andalso MaxSize =< 65535
        ->
            MaxSize;
        {undefined, [#dns_optrr{udp_payload_size = UPS}]} ->
            UPS;
        {undefined, []} ->
            512;
        _ ->
            erlang:error(badarg)
    end.

-spec encode_message_tsig_add(
    1..1114111,
    binary(),
    <<_:64, _:_*8>>,
    _,
    integer(),
    integer(),
    integer(),
    binary(),
    binary(),
    boolean(),
    <<_:64, _:_*8>>
) -> {<<_:32, _:_*8>>, binary()}.
encode_message_tsig_add(
    MsgId,
    Name,
    Alg,
    Secret,
    Time,
    Fudge,
    Err,
    Other,
    PMAC,
    Tail,
    <<OrigMsgId:16, Head:8/binary, ADC:16, Body/binary>> = MsgBin
) ->
    case
        gen_tsig_mac(
            Alg,
            MsgBin,
            Name,
            Secret,
            Time,
            Fudge,
            Err,
            Other,
            PMAC,
            Tail
        )
    of
        {ok, MAC} ->
            MS = byte_size(MAC),
            OLen = byte_size(Other),
            NameBin = encode_dname(Name),
            AlgBin = encode_dname(Alg),
            TSIGData =
                <<AlgBin/binary, Time:48, Fudge:16, MS:16, MAC:MS/binary, OrigMsgId:16, Err:16,
                    OLen:16, Other:OLen/binary>>,
            TSIGDataSize = byte_size(TSIGData),
            TSigRR =
                <<NameBin/binary, ?DNS_TYPE_TSIG:16, ?DNS_CLASS_ANY:16, 0:32, TSIGDataSize:16,
                    TSIGData/binary>>,
            MsgBin0 = <<MsgId:16, Head/binary, (ADC + 1):16, Body/binary, TSigRR/binary>>,
            {MsgBin0, MAC};
        {error, _} ->
            erlang:error(badarg)
    end.

-spec encode_message_tsig_size(binary(), <<_:64, _:_*8>>, bitstring()) -> pos_integer().
encode_message_tsig_size(Name, Alg, Other) ->
    NameSize = byte_size(encode_dname(Name)),
    AlgSize = byte_size(encode_dname(Alg)),
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

-spec encode_message_default(message(), number()) -> binary().
encode_message_default(#dns_message{tc = TC, additional = Additional} = Msg, MaxSize) ->
    BuildHead = fun(TCBool, EncQC, EncANC, EncAUC, EncADC) ->
        Msg0 = Msg#dns_message{
            qc = EncQC,
            anc = EncANC,
            auc = EncAUC,
            adc = EncADC,
            tc = TC orelse TCBool
        },
        encode_message_head(Msg0)
    end,
    {OptRRBin, Ad0} = encode_message_pop_optrr(Additional),
    Pos = 12,
    SpaceLeft = MaxSize - Pos,
    case encode_message_d_req(Pos, SpaceLeft, Msg) of
        {false, QC, ANC, AUC, Body} ->
            Head = BuildHead(true, QC, ANC, AUC, 0),
            <<Head/binary, Body/binary>>;
        {CompMap, QC, ANC, AUC, Body} ->
            BodySize = byte_size(Body),
            OptRRBinSize = byte_size(OptRRBin),
            Pos0 = BodySize + Pos,
            case SpaceLeft - BodySize of
                SpaceLeft0 when SpaceLeft0 < OptRRBinSize ->
                    Head = BuildHead(true, QC, ANC, AUC, 0),
                    <<Head/binary, Body/binary>>;
                SpaceLeft0 ->
                    Pos1 = Pos0 + OptRRBinSize,
                    SpaceLeft1 = SpaceLeft0 - OptRRBinSize,
                    OptC =
                        case OptRRBinSize of
                            0 -> 0;
                            _ -> 1
                        end,
                    case encode_message_d_opt(Pos1, SpaceLeft1, CompMap, Ad0) of
                        false ->
                            Head = BuildHead(false, QC, ANC, AUC, OptC),
                            <<Head/binary, Body/binary, OptRRBin/binary>>;
                        {ADC, AdBin} ->
                            Head = BuildHead(false, QC, ANC, AUC, OptC + ADC),
                            <<Head/binary, Body/binary, OptRRBin/binary, AdBin/binary>>
                    end
            end
    end.

-spec encode_message_d_req(12, number(), message()) -> {_, char(), char(), char(), bitstring()}.
encode_message_d_req(Pos, SpaceLeft, #dns_message{} = Msg) ->
    Msg0 = Msg#dns_message{qc = 0, anc = 0, auc = 0},
    encode_message_d_req(Pos, SpaceLeft, new_compmap(), <<>>, Msg0).

-spec encode_message_d_req(pos_integer(), number(), _, bitstring(), message()) ->
    {_, char(), char(), char(), bitstring()}.
encode_message_d_req(
    Pos,
    SpaceLeft,
    CompMap,
    Bin,
    #dns_message{qc = QC, anc = ANC, auc = AUC} = Msg
) ->
    case encode_message_pop(Msg) of
        {additional, _} ->
            {CompMap, QC, ANC, AUC, Bin};
        {Section, Recs} ->
            RecsLen = length(Recs),
            {CompMap0, NewBin, Recs0} = encode_message_rec_list(
                Pos,
                SpaceLeft,
                CompMap,
                Recs
            ),
            Recs0Len = length(Recs0),
            EncodedLen = RecsLen - Recs0Len,
            Msg0 = encode_message_put(Recs0, Section, Msg),
            Msg1 = encode_message_updatecount(EncodedLen, Section, Msg0),
            Bin0 = <<Bin/binary, NewBin/binary>>,
            case Recs0Len of
                0 ->
                    NewBinSize = byte_size(NewBin),
                    Pos0 = Pos + NewBinSize,
                    SpaceLeft0 = SpaceLeft - NewBinSize,
                    encode_message_d_req(
                        Pos0,
                        SpaceLeft0,
                        CompMap0,
                        Bin0,
                        Msg1
                    );
                _ ->
                    #dns_message{qc = QC0, anc = ANC0, auc = AUC0} = Msg1,
                    {false, QC0, ANC0, AUC0, Bin0}
            end
    end.

-spec encode_message_d_opt(pos_integer(), number(), _, [
    [{_, _, _, _, _, _}]
    | optrr()
    | rr()
]) -> false | {non_neg_integer(), bitstring()}.
encode_message_d_opt(Pos, SpaceLeft, CompMap, Recs) ->
    case encode_message_rec_list(Pos, SpaceLeft, CompMap, Recs) of
        {_, Bin, []} -> {length(Recs), Bin};
        _ -> false
    end.

-spec encode_message_axfr(message(), number()) -> binary() | {binary(), message()}.
encode_message_axfr(#dns_message{} = Msg, MaxSize) ->
    Pos = 12,
    SpaceLeft = MaxSize - Pos,
    encode_message_axfr(Pos, SpaceLeft, new_compmap(), <<>>, Msg).

-spec encode_message_axfr(pos_integer(), number(), _, binary(), message()) ->
    binary() | {binary(), message()}.
encode_message_axfr(Pos, SpaceLeft, CompMap, Bin, #dns_message{} = Msg) ->
    {Section, Recs} = encode_message_pop(Msg),
    RecsLen = length(Recs),
    {CompMap0, NewBin, Recs0} =
        encode_message_rec_list(Pos, SpaceLeft, CompMap, Recs),
    Recs0Len = length(Recs0),
    EncodedLen = RecsLen - Recs0Len,
    Msg0 = encode_message_put(Recs0, Section, Msg),
    Msg1 = encode_message_updatecount(EncodedLen, Section, Msg0),
    case Recs0Len of
        0 when Section =:= additional ->
            Head = encode_message_head(Msg1),
            <<Head/binary, Bin/binary, NewBin/binary>>;
        0 ->
            NewBinSize = byte_size(NewBin),
            Pos0 = Pos + NewBinSize,
            SpaceLeft0 = SpaceLeft - NewBinSize,
            Bin0 = <<Bin/binary, NewBin/binary>>,
            encode_message_axfr(Pos0, SpaceLeft0, CompMap0, Bin0, Msg1);
        _ ->
            Head = encode_message_head(Msg1),
            Msg2 = encode_message_a_setcounts(Msg1),
            {<<Head/binary, Bin/binary, NewBin/binary>>, Msg2}
    end.

-spec encode_message_pop(message()) ->
    {additional, dns:additional()}
    | {answers, dns:answers()}
    | {authority, dns:authority()}
    | {questions, [query()]}.
encode_message_pop(#dns_message{questions = [_ | _] = Recs}) -> {questions, Recs};
encode_message_pop(#dns_message{answers = [_ | _] = Recs}) -> {answers, Recs};
encode_message_pop(#dns_message{authority = [_ | _] = Recs}) -> {authority, Recs};
encode_message_pop(#dns_message{additional = Recs}) -> {additional, Recs}.

-spec encode_message_put(
    [[rr()] | query() | optrr() | rr()],
    additional | answers | authority | questions,
    message()
) ->
    message().
encode_message_put(Recs, questions, #dns_message{} = Msg) ->
    Msg#dns_message{questions = Recs};
encode_message_put(Recs, answers, #dns_message{} = Msg) ->
    Msg#dns_message{answers = Recs};
encode_message_put(Recs, authority, #dns_message{} = Msg) ->
    Msg#dns_message{authority = Recs};
encode_message_put(Recs, additional, #dns_message{} = Msg) ->
    Msg#dns_message{additional = Recs}.

-spec encode_message_a_setcounts(message()) -> message().
encode_message_a_setcounts(
    #dns_message{
        questions = Q,
        answers = Answers,
        authority = Authority,
        additional = Additional
    } = Msg
) ->
    Msg#dns_message{
        qc = length(Q),
        anc = length(Answers),
        auc = length(Authority),
        adc = length(Additional)
    }.

-spec encode_message_updatecount(
    char(), additional | answers | authority | questions, message()
) ->
    message().
encode_message_updatecount(Count, questions, #dns_message{} = Msg) ->
    Msg#dns_message{qc = Count};
encode_message_updatecount(Count, answers, #dns_message{} = Msg) ->
    Msg#dns_message{anc = Count};
encode_message_updatecount(Count, authority, #dns_message{} = Msg) ->
    Msg#dns_message{auc = Count};
encode_message_updatecount(Count, additional, #dns_message{} = Msg) ->
    Msg#dns_message{adc = Count}.

-spec encode_message_head(message()) -> <<_:96>>.
encode_message_head(#dns_message{
    id = Id,
    qr = QR,
    oc = OC,
    aa = AA,
    tc = TC,
    rd = RD,
    ra = RA,
    ad = AD,
    cd = CD,
    rc = RC,
    qc = QC,
    anc = ANC,
    auc = AUC,
    adc = ADC
}) ->
    <<Id:16, (encode_bool(QR)):1, OC:4, (encode_bool(AA)):1, (encode_bool(TC)):1,
        (encode_bool(RD)):1, (encode_bool(RA)):1, 0:1, (encode_bool(AD)):1, (encode_bool(CD)):1,
        RC:4, QC:16, ANC:16, AUC:16, ADC:16>>.

-spec encode_message_llq(message(), number()) -> binary() | {binary(), message()}.
encode_message_llq(
    #dns_message{
        questions = Q,
        answers = Answers,
        authority = Authority,
        additional = Additional
    } = Msg,
    MaxSize
) ->
    QC = length(Q),
    AnswersLen = length(Answers),
    AuthorityLen = length(Authority),
    AdditionalLen = length(Additional),
    AuAd = Authority ++ Additional,
    Pos = 12,
    SpaceLeft = MaxSize - Pos,
    {CompMap0, QBin, []} =
        encode_message_rec_list(Pos, SpaceLeft, new_compmap(), Q),
    QBinSize = byte_size(QBin),
    SpaceLeft0 = SpaceLeft - QBinSize,
    Pos0 = QBinSize + Pos,
    {_, AuAdTmp, []} =
        encode_message_rec_list(Pos0, SpaceLeft0, CompMap0, AuAd),
    AuAdTmpSize = byte_size(AuAdTmp),
    {CompMap1, AnBin, LeftoverAn} =
        encode_message_rec_list(Pos0, SpaceLeft0 - AuAdTmpSize, CompMap0, Answers),
    LeftoverAnC = length(LeftoverAn),
    EncodedAnC = AnswersLen - LeftoverAnC,
    AnBinSize = byte_size(AnBin),
    Pos1 = Pos0 + AnBinSize,
    SpaceLeft1 = SpaceLeft0 - AnBinSize,
    {_, AuAdBin, []} =
        encode_message_rec_list(Pos1, SpaceLeft1, CompMap1, AuAd),
    Msg0 = Msg#dns_message{qc = QC, anc = EncodedAnC, auc = AuthorityLen, adc = AdditionalLen},
    Head = encode_message_head(Msg0),
    Bin = <<Head/binary, QBin/binary, AnBin/binary, AuAdBin/binary>>,
    case LeftoverAnC =:= 0 of
        true -> Bin;
        false -> {Bin, Msg#dns_message{anc = LeftoverAnC, answers = LeftoverAn}}
    end.

-spec encode_message_rec_list(pos_integer(), number(), _, [
    [{_, _, _, _, _, _}]
    | query()
    | optrr()
    | rr()
]) -> {_, bitstring(), [[any()] | {_, _, _, _} | {_, _, _, _, _, _}]}.
encode_message_rec_list(Pos, SpaceLeft, CompMap, Recs) ->
    encode_message_rec_list(Pos, SpaceLeft, CompMap, <<>>, Recs).

-spec encode_message_rec_list(pos_integer(), number(), _, bitstring(), [
    [{_, _, _, _, _, _}]
    | query()
    | optrr()
    | rr()
]) -> {_, bitstring(), [[any()] | {_, _, _, _} | {_, _, _, _, _, _}]}.
encode_message_rec_list(Pos, SpaceLeft, CompMap, Body, [Rec | Rest] = Recs) ->
    {CompMap0, NewBin} = encode_message_rec(CompMap, Pos, Rec),
    NewBinSize = byte_size(NewBin),
    case SpaceLeft - NewBinSize of
        SpaceLeft0 when SpaceLeft0 > 0 ->
            Pos0 = Pos + NewBinSize,
            Body0 = <<Body/binary, NewBin/binary>>,
            encode_message_rec_list(Pos0, SpaceLeft0, CompMap0, Body0, Rest);
        _ ->
            {CompMap, Body, Recs}
    end;
encode_message_rec_list(_Pos, _SpaceLeft, CompMap, Body, [] = Recs) ->
    {CompMap, Body, Recs}.

-spec encode_message_rec(_, non_neg_integer(), query() | optrr() | rr()) -> {_, <<_:32, _:_*8>>}.
encode_message_rec(CompMap, Pos, #dns_query{name = N, type = T, class = C}) ->
    {NameBin, CompMap0} = encode_dname(CompMap, Pos, N),
    {CompMap0, <<NameBin/binary, T:16, C:16>>};
encode_message_rec(CompMap, _Pos, #dns_optrr{
    udp_payload_size = UPS,
    ext_rcode = ExtRcode,
    version = Version,
    dnssec = DNSSEC,
    data = Data
}) ->
    IntClass = UPS,
    DNSSECBit = encode_bool(DNSSEC),
    RRBin = encode_optrrdata(Data),
    RRBinSize = byte_size(RRBin),
    NewBin =
        <<0, 41:16, IntClass:16, ExtRcode:8, Version:8, DNSSECBit:1, 0:15, RRBinSize:16,
            RRBin/binary>>,
    {CompMap, NewBin};
encode_message_rec(CompMap, Pos, #dns_rr{
    name = N,
    type = T,
    class = C,
    ttl = TTL,
    data = D
}) ->
    {NameBin, CompMap0} = encode_dname(CompMap, Pos, N),
    DPos = Pos + byte_size(NameBin) + 2 + 2 + 4 + 2,
    {DBin, CompMap1} = encode_rrdata(DPos, C, D, CompMap0),
    DSize = byte_size(DBin),
    {CompMap1, <<NameBin/binary, T:16, C:16, TTL:32, DSize:16, DBin/binary>>}.

-spec encode_message_pop_optrr([
    [{_, _, _, _, _, _}]
    | optrr()
    | rr()
]) ->
    {binary(), [
        [{_, _, _, _, _, _}]
        | optrr()
        | rr()
    ]}.
encode_message_pop_optrr([
    #dns_optrr{
        udp_payload_size = UPS,
        ext_rcode = ExtRcode,
        version = Version,
        dnssec = DNSSEC,
        data = Data
    }
    | Rest
]) ->
    Class = UPS,
    DNSSECBit = encode_bool(DNSSEC),
    RRBin = encode_optrrdata(Data),
    RRBinSize = byte_size(RRBin),
    Bin =
        <<0, 41:16, Class:16, ExtRcode:8, Version:8, DNSSECBit:1, 0:15, RRBinSize:16,
            RRBin/binary>>,
    {Bin, Rest};
encode_message_pop_optrr(Other) ->
    {<<>>, Other}.

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
    verify_tsig(MsgBin, Name, Secret, []).

%% @doc Verifies a TSIG message signature.
-spec verify_tsig(message_bin(), dname(), binary(), [tsig_opt()]) ->
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
    Now = proplists:get_value(time, Options, unix_time()),
    Fudge = proplists:get_value(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    PreviousMAC = proplists:get_value(mac, Options, <<>>),
    Tail = proplists:get_bool(tail, Options),
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = CFudge,
        mac = CMAC,
        err = Err,
        other = Other
    } = TData,
    case
        gen_tsig_mac(
            Alg,
            UnsignedMsgBin,
            Name,
            Secret,
            Time,
            CFudge,
            Err,
            Other,
            PreviousMAC,
            Tail
        )
    of
        {ok, SMAC} ->
            case const_compare(CMAC, SMAC) of
                true ->
                    case (Time - Fudge) =< Now andalso Now =< (Time + Fudge) of
                        false ->
                            {error, ?DNS_TSIGERR_BADTIME};
                        true ->
                            {ok, SMAC}
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
    add_tsig(Msg, Alg, Name, Secret, ErrCode, []).

%% @doc Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
-spec add_tsig(
    message(),
    tsig_alg(),
    dname(),
    binary(),
    tsig_error(),
    [tsig_opt()]
) -> message().
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    MsgId = Msg#dns_message.id,
    MsgBin = encode_message(Msg),
    Time = proplists:get_value(time, Options, unix_time()),
    Fudge = proplists:get_value(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    PreviousMAC = proplists:get_value(mac, Options, <<>>),
    Other = proplists:get_value(other, Options, <<>>),
    Tail = proplists:get_bool(tail, Options),
    {ok, MAC} = gen_tsig_mac(
        Alg,
        MsgBin,
        Name,
        Secret,
        Time,
        Fudge,
        ErrCode,
        Other,
        PreviousMAC,
        Tail
    ),
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

-spec strip_tsig(<<_:64, _:_*8>>) -> {<<_:64, _:_*8>>, rr()}.
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
    {_Questions, QRB} = decode_message_questions(HRB, QC, MsgBin),
    {_Answers, TSIGBin} =
        decode_message_body(QRB, ANC + AUC + UnsignedADC, MsgBin),
    case decode_message_body(TSIGBin, 1, MsgBin) of
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
    binary(),
    <<_:64, _:_*8>>,
    binary(),
    _,
    integer(),
    integer(),
    _,
    bitstring(),
    binary(),
    boolean()
) ->
    {error, 17} | {ok, _}.
gen_tsig_mac(Alg, Msg, Name, Secret, Time, Fudge, Err, Other, MAC, Tail) ->
    NameBin = encode_dname(dname_to_lower(Name)),
    AlgBin = encode_dname(dname_to_lower(Alg)),
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

-spec hmac(binary(), _, [bitstring(), ...]) -> {error, bad_alg} | {ok, _}.
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
%%% Record data functions
%%%===================================================================

-define(CLASS_IS_IN(T), (T =:= ?DNS_CLASS_IN orelse T =:= ?DNS_CLASS_NONE)).

%% @private
-spec decode_rrdata(uint16(), uint16(), binary()) -> rrdata().
decode_rrdata(Class, Type, Data) ->
    decode_rrdata(Class, Type, Data, <<>>).

-spec decode_rrdata(uint16(), uint16(), binary(), binary()) -> rrdata().
decode_rrdata(_Class, _Type, <<>>, _MsgBin) ->
    <<>>;
decode_rrdata(Class, ?DNS_TYPE_A, <<A, B, C, D>>, _MsgBin) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_a{ip = {A, B, C, D}};
decode_rrdata(
    Class, ?DNS_TYPE_AAAA, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>, _MsgBin
) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}};
decode_rrdata(_Class, ?DNS_TYPE_AFSDB, <<Subtype:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_afsdb{
        subtype = Subtype,
        hostname = decode_dnameonly(Bin, MsgBin)
    };
decode_rrdata(_Class, ?DNS_TYPE_CAA, <<Flags:8, Len:8, Bin/binary>>, _MsgBin) ->
    <<Tag:Len/binary, Value/binary>> = Bin,
    #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value};
decode_rrdata(_Class, ?DNS_TYPE_CERT, <<Type:16, KeyTag:16, Alg, Bin/binary>>, _MsgBin) ->
    #dns_rrdata_cert{type = Type, key_tag = KeyTag, alg = Alg, cert = Bin};
decode_rrdata(_Class, ?DNS_TYPE_CNAME, Bin, MsgBin) ->
    #dns_rrdata_cname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(Class, ?DNS_TYPE_DHCID, Bin, _MsgBin) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_dhcid{data = Bin};
decode_rrdata(_Class, ?DNS_TYPE_DLV, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, _MsgBin) ->
    #dns_rrdata_dlv{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(_Class, ?DNS_TYPE_DNAME, Bin, MsgBin) ->
    #dns_rrdata_dname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(
    _Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin, _MsgBin
) when
    AlgNum =:= ?DNS_ALG_RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_RSASHA256 orelse
        AlgNum =:= ?DNS_ALG_RSASHA512
->
    Key =
        case PublicKey of
            <<0, Len:16, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)];
            <<Len:8, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)]
        end,
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        key_tag = KeyTag
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_DNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, T, Q:20/unit:8, KeyBin/binary>> = Bin,
    _MsgBin
) when
    (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA) andalso
        T =< 8
->
    S = 64 + T * 8,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = KeyBin,
    Key = [P, Q, G, Y],
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        key_tag = KeyTag
    };
decode_rrdata(
    _Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin, _MsgBin
) ->
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        key_tag = bin_to_key_tag(Bin)
    };
decode_rrdata(
    _Class, ?DNS_TYPE_CDNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin, _MsgBin
) when
    AlgNum =:= ?DNS_ALG_RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_RSASHA256 orelse
        AlgNum =:= ?DNS_ALG_RSASHA512
->
    Key =
        case PublicKey of
            <<0, Len:16, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)];
            <<Len:8, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)]
        end,
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        key_tag = KeyTag
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_CDNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, T, Q:20/unit:8, KeyBin/binary>> = Bin,
    _MsgBin
) when
    (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA) andalso
        T =< 8
->
    S = 64 + T * 8,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = KeyBin,
    Key = [P, Q, G, Y],
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        key_tag = KeyTag
    };
decode_rrdata(
    _Class, ?DNS_TYPE_CDNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin, _MsgBin
) ->
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        key_tag = bin_to_key_tag(Bin)
    };
decode_rrdata(_Class, ?DNS_TYPE_DS, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, _MsgBin) ->
    #dns_rrdata_ds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(_Class, ?DNS_TYPE_CDS, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, _MsgBin) ->
    #dns_rrdata_cds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(_Class, ?DNS_TYPE_HINFO, Bin, _BodyBin) ->
    [CPU, OS] = decode_text(Bin),
    #dns_rrdata_hinfo{cpu = CPU, os = OS};
decode_rrdata(
    _Class, ?DNS_TYPE_IPSECKEY, <<Precedence:8, 0:8, Algorithm:8, PublicKey/binary>>, _MsgBin
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = <<>>,
        public_key = PublicKey
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_IPSECKEY,
    <<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8, PublicKey/binary>>,
    _MsgBin
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D},
        public_key = PublicKey
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_IPSECKEY,
    <<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
        PublicKey/binary>>,
    _MsgBin
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D, E, F, G, H},
        public_key = PublicKey
    };
decode_rrdata(_Class, ?DNS_TYPE_IPSECKEY, <<Precedence:8, 3:8, Algorithm:8, Bin/binary>>, MsgBin) ->
    {Gateway, PublicKey} = decode_dname(Bin, MsgBin),
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = Gateway,
        public_key = PublicKey
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_KEY,
    <<Type:2, 0:1, XT:1, 0:2, NamType:2, 0:4, Sig:4, Protocol:8, Alg:8, PublicKey/binary>>,
    _MsgBin
) ->
    #dns_rrdata_key{
        type = Type,
        xt = XT,
        name_type = NamType,
        sig = Sig,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey
    };
decode_rrdata(_Class, ?DNS_TYPE_KX, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_kx{
        preference = Preference,
        exchange = decode_dnameonly(Bin, MsgBin)
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_LOC,
    <<0:8, SizeB:4, SizeE:4, HorizB:4, HorizE:4, VertB:4, VertE:4, LatPre:32, LonPre:32,
        AltPre:32>>,
    _MsgBin
) when SizeE < 10 andalso HorizE < 10 andalso VertE < 10 ->
    #dns_rrdata_loc{
        size = SizeB * (round_pow(10, SizeE)),
        horiz = HorizB * (round_pow(10, HorizE)),
        vert = VertB * (round_pow(10, VertE)),
        lat = decode_loc_point(LatPre),
        lon = decode_loc_point(LonPre),
        alt = AltPre - 10000000
    };
decode_rrdata(_Class, ?DNS_TYPE_MB, Bin, MsgBin) ->
    #dns_rrdata_mb{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MG, Bin, MsgBin) ->
    #dns_rrdata_mg{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MINFO, Bin, MsgBin) when is_binary(Bin) ->
    {RMB, EMB} = decode_dname(Bin, MsgBin),
    #dns_rrdata_minfo{rmailbx = RMB, emailbx = decode_dnameonly(EMB, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MR, Bin, MsgBin) ->
    #dns_rrdata_mr{newname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MX, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_mx{
        preference = Preference,
        exchange = decode_dnameonly(Bin, MsgBin)
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_NAPTR,
    <<Order:16, Preference:16, Bin/binary>>,
    MsgBin
) ->
    {Bin1, Flags} = decode_string(Bin),
    {Bin2, Services} = decode_string(Bin1),
    {Bin3, RawRegexp} = decode_string(Bin2),
    Regexp = unicode:characters_to_binary(RawRegexp, utf8),
    #dns_rrdata_naptr{
        order = Order,
        preference = Preference,
        flags = Flags,
        services = Services,
        regexp = Regexp,
        replacement = decode_dnameonly(Bin3, MsgBin)
    };
decode_rrdata(_Class, ?DNS_TYPE_NS, Bin, MsgBin) ->
    #dns_rrdata_ns{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_NSEC, Bin, MsgBin) ->
    {NextDName, TypeBMP} = decode_dname(Bin, MsgBin),
    Types = decode_nsec_types(TypeBMP),
    #dns_rrdata_nsec{next_dname = NextDName, types = Types};
decode_rrdata(
    _Class,
    ?DNS_TYPE_NSEC3,
    <<HashAlg:8, _FlagsZ:7, OptOut:1, Iterations:16, SaltLen:8/unsigned, Salt:SaltLen/binary-unit:8,
        HashLen:8/unsigned, Hash:HashLen/binary-unit:8, TypeBMP/binary>>,
    _MsgBin
) ->
    #dns_rrdata_nsec3{
        hash_alg = HashAlg,
        opt_out = decode_bool(OptOut),
        iterations = Iterations,
        salt = Salt,
        hash = Hash,
        types = decode_nsec_types(TypeBMP)
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_NSEC3PARAM,
    <<Alg:8, Flags:8, Iterations:16, SaltLen:8, Salt:SaltLen/binary>>,
    _MsgBin
) ->
    #dns_rrdata_nsec3param{
        hash_alg = Alg,
        flags = Flags,
        iterations = Iterations,
        salt = Salt
    };
decode_rrdata(_Class, ?DNS_TYPE_NXT, Bin, MsgBin) ->
    {NxtDName, BMP} = decode_dname(Bin, MsgBin),
    #dns_rrdata_nxt{dname = NxtDName, types = decode_nxt_bmp(BMP)};
decode_rrdata(_Class, ?DNS_TYPE_PTR, Bin, MsgBin) ->
    #dns_rrdata_ptr{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_RP, Bin, MsgBin) ->
    {Mbox, TxtBin} = decode_dname(Bin, MsgBin),
    #dns_rrdata_rp{mbox = Mbox, txt = decode_dnameonly(TxtBin, MsgBin)};
decode_rrdata(
    _Class,
    ?DNS_TYPE_RRSIG,
    <<Type:16, Alg:8, Labels:8, TTL:32, Expire:32, Inception:32, KeyTag:16, Bin/binary>>,
    MsgBin
) ->
    {SigName, Sig} = decode_dname(Bin, MsgBin),
    #dns_rrdata_rrsig{
        type_covered = Type,
        alg = Alg,
        labels = Labels,
        original_ttl = TTL,
        expiration = Expire,
        inception = Inception,
        key_tag = KeyTag,
        signers_name = SigName,
        signature = Sig
    };
decode_rrdata(_Class, ?DNS_TYPE_RT, <<Pref:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_rt{preference = Pref, host = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_SOA, Bin, MsgBin) ->
    {MName, RNBin} = decode_dname(Bin, MsgBin),
    {RName, Rest} = decode_dname(RNBin, MsgBin),
    <<Ser:32, Ref:32, Ret:32, Exp:32, Min:32>> = Rest,
    #dns_rrdata_soa{
        mname = MName,
        rname = RName,
        serial = Ser,
        refresh = Ref,
        retry = Ret,
        expire = Exp,
        minimum = Min
    };
decode_rrdata(_Class, ?DNS_TYPE_SPF, Bin, _MsgBin) ->
    #dns_rrdata_spf{spf = decode_text(Bin)};
decode_rrdata(
    _Class,
    ?DNS_TYPE_SRV,
    <<Pri:16, Wght:16, Port:16, Bin/binary>>,
    MsgBin
) ->
    #dns_rrdata_srv{
        priority = Pri,
        weight = Wght,
        port = Port,
        target = decode_dnameonly(Bin, MsgBin)
    };
decode_rrdata(
    _Class,
    ?DNS_TYPE_SSHFP,
    <<Alg:8, FPType:8, FingerPrint/binary>>,
    _MsgBin
) ->
    #dns_rrdata_sshfp{alg = Alg, fp_type = FPType, fp = FingerPrint};
decode_rrdata(_Class, ?DNS_TYPE_SVCB, <<SvcPriority:16, Bin/binary>>, MsgBin) ->
    {TargetName, SvcParamsBin} = decode_dname(Bin, MsgBin),
    SvcParams = decode_svcb_svc_params(SvcParamsBin),
    #dns_rrdata_svcb{svc_priority = SvcPriority, target_name = TargetName, svc_params = SvcParams};
decode_rrdata(_Class, ?DNS_TYPE_TSIG, Bin, MsgBin) ->
    {Alg,
        <<Time:48, Fudge:16, MS:16, MAC:MS/bytes, MsgId:16, ErrInt:16, OtherLen:16,
            Other:OtherLen/binary>>} = decode_dname(Bin, MsgBin),
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = Fudge,
        mac = MAC,
        msgid = MsgId,
        err = ErrInt,
        other = Other
    };
decode_rrdata(_Class, ?DNS_TYPE_TXT, Bin, _MsgBin) ->
    #dns_rrdata_txt{txt = decode_text(Bin)};
decode_rrdata(_Class, _Type, Bin, _MsgBin) ->
    Bin.

%% @private
-spec encode_rrdata(_, rrdata()) -> any().
encode_rrdata(Class, Data) ->
    {Bin, undefined} = encode_rrdata(0, Class, Data, undefined),
    Bin.

-spec encode_rrdata(non_neg_integer(), _, rrdata(), _) -> {_, _}.
encode_rrdata(_Pos, Class, #dns_rrdata_a{ip = {A, B, C, D}}, CompMap) when
    ?CLASS_IS_IN(Class)
->
    {<<A, B, C, D>>, CompMap};
encode_rrdata(_Pos, Class, #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}}, CompMap) when
    ?CLASS_IS_IN(Class)
->
    {<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_afsdb{
        subtype = Subtype,
        hostname = Hostname
    },
    CompMap
) ->
    HostnameBin = encode_dname(Hostname),
    {<<Subtype:16, HostnameBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value}, CompMap) ->
    Len = byte_size(Tag),
    {<<Flags:8, Len:8, Tag/binary, Value/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cert{
        type = Type,
        key_tag = KeyTag,
        alg = Alg,
        cert = Bin
    },
    CompMap
) ->
    {<<Type:16, KeyTag:16, Alg, Bin/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_cname{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(_Pos, ?DNS_CLASS_IN, #dns_rrdata_dhcid{data = Bin}, CompMap) ->
    {Bin, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_dlv{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    CompMap
) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_dname{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = [E, M]
    },
    CompMap
) when
    Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    MBin = strip_leading_zeros(binary:encode_unsigned(M)),
    EBin = strip_leading_zeros(binary:encode_unsigned(E)),
    ESize = byte_size(EBin),
    PKBin =
        case ESize of
            _ when ESize =< 16#FF ->
                <<ESize:8, EBin:ESize/binary, MBin/binary>>;
            _ when ESize =< 16#FFFF ->
                <<0, ESize:16, EBin:ESize/binary, MBin/binary>>;
            _ ->
                erlang:error(badarg)
        end,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PKM
    },
    CompMap
) when
    Alg =:= ?DNS_ALG_DSA orelse
        Alg =:= ?DNS_ALG_NSEC3DSA
->
    [P, Q, G, Y] = [
        case X of
            <<L:32, I:L/unit:8>> -> I;
            X when is_binary(X) -> binary:decode_unsigned(X);
            X when is_integer(X) -> X
        end
     || X <- PKM
    ],
    M = byte_size(strip_leading_zeros(binary:encode_unsigned(P))),
    T = (M - 64) div 8,
    PKBin = <<T, Q:20/unit:8, P:M/unit:8, G:M/unit:8, Y:M/unit:8>>,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PK
    },
    CompMap
) ->
    {<<Flags:16, Protocol:8, Alg:8, PK/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = [E, M]
    },
    CompMap
) when
    Alg =:= ?DNS_ALG_RSASHA1 orelse
        Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse
        Alg =:= ?DNS_ALG_RSASHA512
->
    MBin = strip_leading_zeros(binary:encode_unsigned(M)),
    EBin = strip_leading_zeros(binary:encode_unsigned(E)),
    ESize = byte_size(EBin),
    PKBin =
        case ESize of
            _ when ESize =< 16#FF ->
                <<ESize:8, EBin:ESize/binary, MBin/binary>>;
            _ when ESize =< 16#FFFF ->
                <<0, ESize:16, EBin:ESize/binary, MBin/binary>>;
            _ ->
                erlang:error(badarg)
        end,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PKM
    },
    CompMap
) when
    Alg =:= ?DNS_ALG_DSA orelse
        Alg =:= ?DNS_ALG_NSEC3DSA
->
    [P, Q, G, Y] = [
        case X of
            <<L:32, I:L/unit:8>> -> I;
            X when is_binary(X) -> binary:decode_unsigned(X);
            X when is_integer(X) -> X
        end
     || X <- PKM
    ],
    M = byte_size(strip_leading_zeros(binary:encode_unsigned(P))),
    T = (M - 64) div 8,
    PKBin = <<T, Q:20/unit:8, P:M/unit:8, G:M/unit:8, Y:M/unit:8>>,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PK
    },
    CompMap
) ->
    {<<Flags:16, Protocol:8, Alg:8, PK/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_ds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    CompMap
) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    },
    CompMap
) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_hinfo{cpu = CPU, os = OS}, CompMap) ->
    {encode_text([CPU, OS]), CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = <<>>,
        public_key = PublicKey
    },
    CompMap
) ->
    {<<Precedence:8, 0:8, Algorithm:8, PublicKey/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D},
        public_key = PublicKey
    },
    CompMap
) ->
    {<<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8, PublicKey/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D, E, F, G, H},
        public_key = PublicKey
    },
    CompMap
) ->
    {
        <<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
            PublicKey/binary>>,
        CompMap
    };
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = DName,
        public_key = PublicKey
    },
    CompMap
) ->
    DNameBin = encode_dname(DName),
    {<<Precedence:8, 3:8, Algorithm:8, DNameBin/binary, PublicKey/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_key{
        type = Type,
        xt = XT,
        name_type = NameType,
        sig = Sig,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey
    },
    CompMap
) ->
    {
        <<Type:2, 0:1, XT:1, 0:2, NameType:2, 0:4, Sig:4, Protocol:8, Alg:8, PublicKey/binary>>,
        CompMap
    };
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_kx{preference = Pref, exchange = Name},
    CompMap
) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_loc{
        size = Size,
        horiz = Horiz,
        vert = Vert,
        lat = Lat,
        lon = Lon,
        alt = Alt
    },
    CompMap
) ->
    SizeEnc = encode_loc_size(Size),
    HorizEnc = encode_loc_size(Horiz),
    VertEnc = encode_loc_size(Vert),
    LatEnc = Lat + ?MAX_INT32,
    LonEnc = Lon + ?MAX_INT32,
    {
        <<0:8, SizeEnc:1/binary, HorizEnc:1/binary, VertEnc:1/binary, LatEnc:32, LonEnc:32,
            (Alt + 10000000):32>>,
        CompMap
    };
encode_rrdata(Pos, _Class, #dns_rrdata_mb{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_mg{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_minfo{rmailbx = RMB, emailbx = EMB},
    CompMap
) ->
    {RMBBin, CompMap0} = encode_dname(CompMap, Pos, RMB),
    NewPos = Pos + byte_size(RMBBin),
    {EMBBin, NewCompMap} = encode_dname(CompMap0, NewPos, EMB),
    {<<RMBBin/binary, EMBBin/binary>>, NewCompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_mr{newname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_mx{preference = Pref, exchange = Name},
    CompMap
) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_naptr{
        order = Order,
        preference = Pref,
        flags = Flags,
        services = Svcs,
        regexp = Regexp,
        replacement = Replacement
    },
    CompMap
) ->
    Bin0 = encode_string(<<Order:16, Pref:16>>, Flags),
    Bin1 = encode_string(Bin0, Svcs),
    Regexp0 = unicode:characters_to_binary(Regexp, unicode, utf8),
    Bin2 = encode_string(Bin1, Regexp0),
    ReplacementBin = encode_dname(Replacement),
    {<<Bin2/binary, ReplacementBin/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_ns{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_nsec{
        next_dname = NextDName,
        types = Types
    },
    CompMap
) ->
    NextDNameBin = encode_dname(NextDName),
    TypesBin = encode_nsec_types(Types),
    {<<NextDNameBin/binary, TypesBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_nsec3{
        hash_alg = HashAlg,
        opt_out = OptOut,
        iterations = Iterations,
        salt = Salt,
        hash = Hash,
        types = Types
    },
    CompMap
) ->
    TypeBMP = encode_nsec_types(Types),
    OptOutN = encode_bool(OptOut),
    SaltLength = byte_size(Salt),
    HashLength = byte_size(Hash),
    {
        <<HashAlg:8, 0:7, OptOutN:1, Iterations:16, SaltLength:8/unsigned,
            Salt:SaltLength/binary-unit:8, HashLength:8/unsigned, Hash:HashLength/binary-unit:8,
            TypeBMP/binary>>,
        CompMap
    };
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_nsec3param{
        hash_alg = HashAlg,
        flags = Flags,
        iterations = Iterations,
        salt = Salt
    },
    CompMap
) ->
    SaltLength = byte_size(Salt),
    {<<HashAlg:8, Flags:8, Iterations:16, SaltLength:8/unsigned, Salt:SaltLength/binary>>, CompMap};
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_nxt{dname = NxtDName, types = Types},
    CompMap
) ->
    {NextDNameBin, NewCompMap} = encode_dname(CompMap, Pos, NxtDName),
    BMP = encode_nxt_bmp(Types),
    {<<NextDNameBin/binary, BMP/binary>>, NewCompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_ptr{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(_Pos, _Class, #dns_rrdata_rp{mbox = Mbox, txt = Txt}, CompMap) ->
    MboxBin = encode_dname(Mbox),
    TxtBin = encode_dname(Txt),
    {<<MboxBin/binary, TxtBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_rrsig{
        type_covered = TypeCovered,
        alg = Alg,
        labels = Labels,
        original_ttl = OriginalTTL,
        expiration = SigExpire,
        inception = SigIncept,
        key_tag = KeyTag,
        signers_name = SignersName,
        signature = Sig
    },
    CompMap
) ->
    SignersNameBin = encode_dname(SignersName),
    {
        <<TypeCovered:16, Alg:8, Labels:8, OriginalTTL:32, SigExpire:32, SigIncept:32, KeyTag:16,
            SignersNameBin/binary, Sig/binary>>,
        CompMap
    };
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_rt{preference = Pref, host = Name},
    CompMap
) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(
    Pos,
    _Class,
    #dns_rrdata_soa{
        mname = MName,
        rname = RName,
        serial = Serial,
        refresh = Refresh,
        retry = Retry,
        expire = Expire,
        minimum = Minimum
    },
    CompMap
) ->
    {MNBin, MNCMap} = encode_dname(CompMap, Pos, MName),
    NewPos = Pos + byte_size(MNBin),
    {RNBin, RNCMap} = encode_dname(MNBin, MNCMap, NewPos, RName),
    {<<RNBin/binary, Serial:32, Refresh:32, Retry:32, Expire:32, Minimum:32>>, RNCMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_spf{spf = Strings}, CompMap) ->
    {encode_text(Strings), CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_srv{
        priority = Pri,
        weight = Wght,
        port = Port,
        target = Target
    },
    CompMap
) ->
    TargetBin = encode_dname(Target),
    {<<Pri:16, Wght:16, Port:16, TargetBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_sshfp{
        alg = Alg,
        fp_type = FPType,
        fp = FingerPrint
    },
    CompMap
) ->
    {<<Alg:8, FPType:8, FingerPrint/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_svcb{
        svc_priority = SvcPriority,
        target_name = TargetName,
        svc_params = SvcParams
    },
    CompMap
) ->
    TargetNameBin = encode_dname(TargetName),
    SvcParamsBin = encode_svcb_svc_params(SvcParams),
    {<<SvcPriority:16, TargetNameBin/binary, SvcParamsBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = Fudge,
        mac = MAC,
        msgid = MsgId,
        err = Err,
        other = Other
    },
    CompMap
) ->
    AlgBin = encode_dname(Alg),
    MACSize = byte_size(MAC),
    OtherLen = byte_size(Other),
    {
        <<AlgBin/binary, Time:48, Fudge:16, MACSize:16, MAC:MACSize/bytes, MsgId:16, Err:16,
            OtherLen:16, Other/binary>>,
        CompMap
    };
encode_rrdata(_Pos, _Class, #dns_rrdata_txt{txt = Strings}, CompMap) ->
    {encode_text(Strings), CompMap};
encode_rrdata(_Pos, _Class, Bin, CompMap) when is_binary(Bin) ->
    {Bin, CompMap}.

-spec decode_loc_point(non_neg_integer()) -> dns:uint32().
decode_loc_point(P) when is_integer(P), P > ?MAX_INT32 ->
    P - ?MAX_INT32;
decode_loc_point(P) when is_integer(P), P =< ?MAX_INT32 ->
    -(?MAX_INT32 - P).

-spec bin_to_key_tag(<<_:32, _:_*8>>) -> char().
bin_to_key_tag(Binary) when is_binary(Binary) ->
    bin_to_key_tag(Binary, 0).

-spec bin_to_key_tag(binary(), non_neg_integer()) -> char().
bin_to_key_tag(<<>>, AC) ->
    (AC + ((AC bsr 16) band 16#FFFF)) band 16#FFFF;
bin_to_key_tag(<<X:16, Rest/binary>>, AC) ->
    bin_to_key_tag(Rest, AC + X);
bin_to_key_tag(<<X:8>>, AC) ->
    bin_to_key_tag(<<>>, AC + (X bsl 8)).

-spec encode_loc_size(integer()) -> <<_:8>>.
encode_loc_size(Size) when is_integer(Size) -> encode_loc_size(Size, 0).

-spec encode_loc_size(integer(), non_neg_integer()) -> <<_:8>>.
encode_loc_size(Size, Exponent) ->
    case Size rem round_pow(10, Exponent + 1) of
        Size ->
            Base = Size div round_pow(10, Exponent),
            <<Base:4, Exponent:4>>;
        _ ->
            encode_loc_size(Size, Exponent + 1)
    end.

-spec decode_nsec_types(binary()) -> [non_neg_integer()].
decode_nsec_types(Bin) ->
    decode_nsec_types(Bin, []).

-spec decode_nsec_types(binary(), [non_neg_integer()]) -> [non_neg_integer()].
decode_nsec_types(<<>>, Types) ->
    lists:reverse(Types);
decode_nsec_types(<<WindowNum:8, BMPLength:8, BMP:BMPLength/binary, Rest/binary>>, Types) ->
    BaseNo = WindowNum * 256,
    NewTypes = decode_nsec_types(BMP, BaseNo, Types),
    decode_nsec_types(Rest, NewTypes).

-spec decode_nsec_types(bitstring(), non_neg_integer(), [non_neg_integer()]) -> [non_neg_integer()].
decode_nsec_types(<<>>, _Num, Types) ->
    Types;
decode_nsec_types(<<0:1, Rest/bitstring>>, Num, Types) ->
    decode_nsec_types(Rest, Num + 1, Types);
decode_nsec_types(<<1:1, Rest/bitstring>>, Num, Types) ->
    decode_nsec_types(Rest, Num + 1, [Num | Types]).

-spec encode_nsec_types([integer()]) -> binary().
encode_nsec_types([]) ->
    <<>>;
encode_nsec_types([_ | _] = UnsortedTypes) ->
    [FirstType | _] = Types = lists:usort(UnsortedTypes),
    FirstWindowNum = FirstType div 256,
    FirstLastType = FirstWindowNum * 256,
    encode_nsec_types(<<>>, <<>>, FirstWindowNum, FirstLastType, Types).

-spec encode_nsec_types(binary(), bitstring(), integer(), number(), [integer()]) -> <<_:16, _:_*8>>.
encode_nsec_types(Bin, BMP0, WindowNum, _LastType, []) ->
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    <<Bin/binary, WindowNum:8, BMPSize:8, BMP:BMPSize/binary>>;
encode_nsec_types(Bin, BMP0, OldWindowNum, _LastType, [Type | _] = Types) when
    Type div 256 =/= OldWindowNum
->
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    NewBin = <<Bin/binary, OldWindowNum:8, BMPSize:8, BMP:BMPSize/binary>>,
    NewBMP = <<>>,
    NewWindowNum = Type div 256,
    NewLastType = NewWindowNum * 256,
    encode_nsec_types(NewBin, NewBMP, NewWindowNum, NewLastType, Types);
encode_nsec_types(Bin, BMP, WindowNum, LastType, [Type | Types]) ->
    PadBy =
        case LastType rem 256 of
            0 -> Type rem 256;
            _ -> Type - LastType - 1
        end,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    encode_nsec_types(Bin, NewBMP, WindowNum, Type, Types).

-spec decode_nxt_bmp(bitstring()) -> [non_neg_integer()].
decode_nxt_bmp(BMP) ->
    decode_nxt_bmp(BMP, 0, []).

-spec decode_nxt_bmp(bitstring(), non_neg_integer(), [non_neg_integer()]) -> [non_neg_integer()].
decode_nxt_bmp(<<>>, _Offset, Types) ->
    lists:reverse(Types);
decode_nxt_bmp(<<1:1, Rest/bitstring>>, Offset, Types) ->
    decode_nxt_bmp(Rest, Offset + 1, [Offset | Types]);
decode_nxt_bmp(<<0:1, Rest/bitstring>>, Offset, Types) ->
    decode_nxt_bmp(Rest, Offset + 1, Types).

-spec encode_nxt_bmp([any()]) -> bitstring().
encode_nxt_bmp(UnsortedTypes) when is_list(UnsortedTypes) ->
    Types = lists:usort(UnsortedTypes),
    encode_nxt_bmp(0, Types, <<>>).

-spec encode_nxt_bmp(_, [integer()], bitstring()) -> bitstring().
encode_nxt_bmp(_LastType, [], BMP) ->
    pad_bmp(BMP);
encode_nxt_bmp(LastType, [Type | Types], BMP) ->
    PadBy =
        case LastType of
            0 -> Type;
            LastType -> Type - LastType - 1
        end,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    encode_nxt_bmp(Type, Types, NewBMP).

-spec pad_bmp(bitstring()) -> bitstring().
pad_bmp(BMP) when is_binary(BMP) -> BMP;
pad_bmp(BMP) when is_bitstring(BMP) ->
    PadBy = 8 - bit_size(BMP) rem 8,
    <<BMP/binary-unit:1, 0:PadBy/unit:1>>.

%%%===================================================================
%%% EDNS data functions

-spec decode_optrrdata(binary()) -> [Elem] when
    Elem :: opt_nsid() | opt_ul() | opt_unknown() | opt_ecs() | opt_llq() | opt_owner().
decode_optrrdata(<<>>) ->
    [];
decode_optrrdata(Bin) ->
    decode_optrrdata(Bin, []).

-spec decode_optrrdata(binary(), [Elem]) -> [Elem] when
    Elem :: opt_nsid() | opt_ul() | opt_unknown() | opt_ecs() | opt_llq() | opt_owner().
decode_optrrdata(<<>>, Opts) ->
    lists:reverse(Opts);
decode_optrrdata(<<EOptNum:16, EOptLen:16, EOptBin:EOptLen/binary, Rest/binary>>, Opts) ->
    NewOpt = do_decode_optrrdata(EOptNum, EOptBin),
    decode_optrrdata(Rest, [NewOpt | Opts]).

-spec do_decode_optrrdata(uint16(), binary() | _) ->
    opt_nsid()
    | opt_ul()
    | opt_unknown()
    | opt_ecs()
    | opt_llq()
    | opt_owner().
do_decode_optrrdata(?DNS_EOPTCODE_LLQ, <<1:16, OC:16, EC:16, Id:64, LeaseLife:32>>) ->
    #dns_opt_llq{opcode = OC, errorcode = EC, id = Id, leaselife = LeaseLife};
do_decode_optrrdata(?DNS_EOPTCODE_NSID, <<Data/binary>>) ->
    #dns_opt_nsid{data = Data};
do_decode_optrrdata(?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC:6/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC, _ = <<>>};
do_decode_optrrdata(?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC:6/binary, WMAC:6/binary>>) ->
    #dns_opt_owner{
        seq = S,
        primary_mac = PMAC,
        wakeup_mac = WMAC,
        password = <<>>
    };
do_decode_optrrdata(
    ?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC:6/binary, WMAC:6/binary, Password/binary>>
) ->
    #dns_opt_owner{
        seq = S,
        primary_mac = PMAC,
        wakeup_mac = WMAC,
        password = Password
    };
do_decode_optrrdata(?DNS_EOPTCODE_UL, <<Time:32>>) ->
    #dns_opt_ul{lease = Time};
do_decode_optrrdata(?DNS_EOPTCODE_ECS, <<FAMILY:16, SRCPL:8, SCOPEPL:8, Payload/binary>>) ->
    #dns_opt_ecs{
        family = FAMILY,
        source_prefix_length = SRCPL,
        scope_prefix_length = SCOPEPL,
        address = Payload
    };
do_decode_optrrdata(EOpt, <<Bin/binary>>) ->
    #dns_opt_unknown{id = EOpt, bin = Bin}.

-spec encode_optrrdata(
    [any()]
    | opt_nsid()
    | opt_ul()
    | opt_unknown()
    | opt_ecs()
    | opt_llq()
    | opt_owner()
) -> bitstring() | {integer(), binary()}.
encode_optrrdata(Opts) when is_list(Opts) ->
    encode_optrrdata(lists:reverse(Opts), <<>>);
encode_optrrdata(#dns_opt_llq{
    opcode = OC,
    errorcode = EC,
    id = Id,
    leaselife = Length
}) ->
    Data = <<1:16, OC:16, EC:16, Id:64, Length:32>>,
    {?DNS_EOPTCODE_LLQ, Data};
encode_optrrdata(#dns_opt_ul{lease = Lease}) ->
    {?DNS_EOPTCODE_UL, <<Lease:32>>};
encode_optrrdata(#dns_opt_nsid{data = Data}) when is_binary(Data) ->
    {?DNS_EOPTCODE_NSID, Data};
encode_optrrdata(#dns_opt_owner{
    seq = S,
    primary_mac = PMAC,
    wakeup_mac = WMAC,
    password = Password
}) when
    byte_size(PMAC) =:= 6 andalso byte_size(WMAC) =:= 6 andalso
        (byte_size(Password) =:= 6 orelse byte_size(Password) =:= 4)
->
    Bin = <<0:8, S:8, PMAC/binary, WMAC/binary, Password/binary>>,
    {?DNS_EOPTCODE_OWNER, Bin};
encode_optrrdata(#dns_opt_owner{
    seq = S,
    primary_mac = PMAC,
    wakeup_mac = WMAC,
    password = <<>>
}) when
    byte_size(PMAC) =:= 6 andalso byte_size(WMAC) =:= 6
->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary, WMAC/binary>>};
encode_optrrdata(#dns_opt_owner{seq = S, primary_mac = PMAC, _ = <<>>}) when
    byte_size(PMAC) =:= 6
->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary>>};
encode_optrrdata(
    #dns_opt_ecs{
        family = FAMILY,
        source_prefix_length = SRCPL,
        scope_prefix_length = SCOPEPL,
        address = ADDRESS
    }
) ->
    Data = <<FAMILY:16, SRCPL:8, SCOPEPL:8, ADDRESS/binary>>,
    {?DNS_EOPTCODE_ECS, Data};
encode_optrrdata(#dns_opt_unknown{id = Id, bin = Data}) when
    is_integer(Id) andalso is_binary(Data)
->
    {Id, Data}.

-spec encode_optrrdata(
    [
        [any()]
        | opt_nsid()
        | opt_ul()
        | opt_unknown()
        | opt_ecs()
        | opt_llq()
        | opt_owner()
    ],
    bitstring()
) -> bitstring().
encode_optrrdata([], Bin) ->
    Bin;
encode_optrrdata([Opt | Opts], Bin) ->
    {Id, NewBin} = encode_optrrdata(Opt),
    Len = byte_size(NewBin),
    encode_optrrdata(Opts, <<Id:16, Len:16, NewBin/binary, Bin/binary>>).

%%%===================================================================
%%% Domain name functions
%%%===================================================================

%% @doc Compare two domain names insensitive of case.
-spec compare_dname(dname(), dname()) -> boolean().

compare_dname(Name, Name) ->
    true;
compare_dname(NameA, NameB) ->
    NameALwr = dname_to_lower(iolist_to_binary(NameA)),
    NameBLwr = dname_to_lower(iolist_to_binary(NameB)),
    NameALwr =:= NameBLwr.

-spec decode_dname(nonempty_binary(), binary()) -> {binary(), binary()}.
decode_dname(DataBin, MsgBin) ->
    RemBin = DataBin,
    decode_dname(DataBin, MsgBin, RemBin, <<>>, 0).

-spec decode_dname(nonempty_binary(), binary(), _, binary(), non_neg_integer()) ->
    {binary(), binary()}.
decode_dname(_DataBin, MsgBin, _RemBin, _DName, Count) when
    Count > byte_size(MsgBin)
->
    throw(decode_loop);
decode_dname(<<0, DataRBin/binary>>, _MsgBin, RBin, DName0, Count) ->
    NewRemBin = choose_next_bin(Count, DataRBin, RBin),
    NewDName =
        case DName0 of
            <<$., DName/binary>> -> DName;
            <<>> -> <<>>
        end,
    {NewDName, NewRemBin};
decode_dname(<<0:2, Len:6, Label0:Len/binary, DataRemBin/binary>>, MsgBin, RemBin, DName, Count) ->
    Label = escape_label(Label0),
    NewRemBin = choose_next_bin(Count, DataRemBin, RemBin),
    NewDName = <<DName/binary, $., Label/binary>>,
    decode_dname(DataRemBin, MsgBin, NewRemBin, NewDName, Count);
decode_dname(<<3:2, Ptr:14, DataRBin/binary>>, MsgBin, RBin, DName, Count) ->
    NewRemBin = choose_next_bin(Count, DataRBin, RBin),
    NewRemBin =
        case Count of
            0 -> DataRBin;
            _ -> RBin
        end,
    NewCount = Count + 2,
    case MsgBin of
        <<_:Ptr/binary, NewDataBin/binary>> ->
            decode_dname(NewDataBin, MsgBin, NewRemBin, DName, NewCount);
        _ ->
            throw(bad_pointer)
    end.

choose_next_bin(0, DataRBin, _RBin) ->
    DataRBin;
choose_next_bin(_, _DataRBin, RBin) ->
    RBin.

%% @doc Escapes dots in a DNS label
-spec escape_label(label()) -> label().
escape_label(Label) when is_binary(Label) -> escape_label(<<>>, Label).

-spec escape_label(bitstring(), binary()) -> bitstring().
escape_label(Label, <<>>) -> Label;
escape_label(Cur, <<$., Rest/binary>>) -> escape_label(<<Cur/binary, "\\.">>, Rest);
escape_label(Cur, <<C, Rest/binary>>) -> escape_label(<<Cur/binary, C>>, Rest).

-spec decode_dnameonly(nonempty_binary(), binary()) -> binary().
decode_dnameonly(Bin, MsgBin) ->
    case decode_dname(Bin, MsgBin) of
        {DName, <<>>} -> DName;
        _ -> throw(trailing_garbage)
    end.

-spec new_compmap() -> gb_trees:tree(_, _).
new_compmap() -> gb_trees:empty().

%% @private
-spec encode_dname(binary()) -> nonempty_binary().
encode_dname(Name) ->
    Labels = <<<<(byte_size(L)), L/binary>> || L <- dname_to_labels(Name)>>,
    <<Labels/binary, 0>>.

-spec encode_dname(_, non_neg_integer(), binary()) -> {binary(), _}.
encode_dname(CompMap, Pos, Name) ->
    encode_dname(<<>>, CompMap, Pos, Name).

-spec encode_dname(binary(), _, non_neg_integer(), binary()) -> {binary(), _}.
encode_dname(Bin, undefined, _Pos, Name) ->
    DNameBin = encode_dname(Name),
    {<<Bin/binary, DNameBin/binary>>, undefined};
encode_dname(Bin, CompMap, Pos, Name) ->
    Labels = dname_to_labels(Name),
    LwrLabels = dname_to_labels(dname_to_lower(Name)),
    encode_dname_labels(Bin, CompMap, Pos, Labels, LwrLabels).

-spec encode_dname_labels(binary(), _, non_neg_integer(), [binary()], [binary()]) ->
    {nonempty_binary(), _}.
encode_dname_labels(Bin, CompMap, _Pos, [], []) ->
    {<<Bin/binary, 0>>, CompMap};
encode_dname_labels(Bin, CompMap, Pos, [L | Ls], [_ | LwrLs] = LwrLabels) ->
    case gb_trees:lookup(LwrLabels, CompMap) of
        {value, Ptr} ->
            {<<Bin/binary, 3:2, Ptr:14>>, CompMap};
        none ->
            NewCompMap =
                case Pos < (1 bsl 14) of
                    true -> gb_trees:insert(LwrLabels, Pos, CompMap);
                    false -> CompMap
                end,
            Size = byte_size(L),
            NewPos = Pos + 1 + Size,
            encode_dname_labels(
                <<Bin/binary, Size, L/binary>>,
                NewCompMap,
                NewPos,
                Ls,
                LwrLs
            )
    end.

%% @doc Splits a dname into a list of labels and removes unneeded escapes.
-spec dname_to_labels(dname()) -> [label()].
dname_to_labels("") -> [];
dname_to_labels(".") -> [];
dname_to_labels(<<>>) -> [];
dname_to_labels(<<$.>>) -> [];
dname_to_labels(Name) -> dname_to_labels(<<>>, iolist_to_binary(Name)).

-spec dname_to_labels(bitstring(), binary()) -> [bitstring(), ...].
dname_to_labels(Label, <<>>) -> [Label];
dname_to_labels(Label, <<$.>>) -> [Label];
dname_to_labels(Label, <<$., Cs/binary>>) -> [Label | dname_to_labels(<<>>, Cs)];
dname_to_labels(Label, <<"\\.", Cs/binary>>) -> dname_to_labels(<<Label/binary, $.>>, Cs);
dname_to_labels(Label, <<C, Cs/binary>>) -> dname_to_labels(<<Label/binary, C>>, Cs).

%% @doc Joins a list of DNS labels, escaping where necessary.
-spec labels_to_dname([label()]) -> dname().
labels_to_dname(Labels) ->
    <<$., DName/binary>> = <<
        <<$., (escape_label(Label))/binary>>
     || Label <- Labels
    >>,
    DName.

-define(UP(X), (upper(X)):8).
%% @doc Returns provided name with case-insensitive characters in uppercase.
-spec dname_to_upper(dname()) -> dname().
dname_to_upper(Bin) when is_binary(Bin) ->
    do_dname_to_upper(Bin);
dname_to_upper(Bin) when is_list(Bin) ->
    binary_to_list(do_dname_to_upper(list_to_binary(Bin))).

-spec do_dname_to_upper(dname()) -> dname().
do_dname_to_upper(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G), ?UP(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
do_dname_to_upper(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
do_dname_to_upper(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F)>> || <<A, B, C, D, E, F>> <= Data>>;
do_dname_to_upper(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E)>> || <<A, B, C, D, E>> <= Data>>;
do_dname_to_upper(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D)>> || <<A, B, C, D>> <= Data>>;
do_dname_to_upper(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C)>> || <<A, B, C>> <= Data>>;
do_dname_to_upper(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?UP(A), ?UP(B)>> || <<A, B>> <= Data>>;
do_dname_to_upper(Data) ->
    <<<<?UP(N)>> || <<N>> <= Data>>.

-define(LOW(X), (lower(X)):8).
%% @doc Returns provided name with case-insensitive characters in lowercase.
-spec dname_to_lower(dname()) -> dname().
dname_to_lower(Bin) when is_binary(Bin) ->
    do_dname_to_lower(Bin);
dname_to_lower(List) when is_list(List) ->
    binary_to_list(do_dname_to_lower(list_to_binary(List))).

-spec do_dname_to_lower(dname()) -> dname().
do_dname_to_lower(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G), ?LOW(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
do_dname_to_lower(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
do_dname_to_lower(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F)>> || <<A, B, C, D, E, F>> <= Data>>;
do_dname_to_lower(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E)>> || <<A, B, C, D, E>> <= Data>>;
do_dname_to_lower(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D)>> || <<A, B, C, D>> <= Data>>;
do_dname_to_lower(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C)>> || <<A, B, C>> <= Data>>;
do_dname_to_lower(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?LOW(A), ?LOW(B)>> || <<A, B>> <= Data>>;
do_dname_to_lower(Data) ->
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
%%% DNS terms
%%%===================================================================

%% @doc Returns the name of the class as a binary string.
-spec class_name(class()) -> binary() | undefined.
class_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_CLASS_IN_NUMBER -> ?DNS_CLASS_IN_BSTR;
        ?DNS_CLASS_CS_NUMBER -> ?DNS_CLASS_CS_BSTR;
        ?DNS_CLASS_CH_NUMBER -> ?DNS_CLASS_CH_BSTR;
        ?DNS_CLASS_HS_NUMBER -> ?DNS_CLASS_HS_BSTR;
        ?DNS_CLASS_NONE_NUMBER -> ?DNS_CLASS_NONE_BSTR;
        ?DNS_CLASS_ANY_NUMBER -> ?DNS_CLASS_ANY_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of the type as a binary string.
-spec type_name(type()) -> binary() | undefined.
type_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_TYPE_A_NUMBER -> ?DNS_TYPE_A_BSTR;
        ?DNS_TYPE_NS_NUMBER -> ?DNS_TYPE_NS_BSTR;
        ?DNS_TYPE_MD_NUMBER -> ?DNS_TYPE_MD_BSTR;
        ?DNS_TYPE_MF_NUMBER -> ?DNS_TYPE_MF_BSTR;
        ?DNS_TYPE_CNAME_NUMBER -> ?DNS_TYPE_CNAME_BSTR;
        ?DNS_TYPE_SOA_NUMBER -> ?DNS_TYPE_SOA_BSTR;
        ?DNS_TYPE_MB_NUMBER -> ?DNS_TYPE_MB_BSTR;
        ?DNS_TYPE_MG_NUMBER -> ?DNS_TYPE_MG_BSTR;
        ?DNS_TYPE_MR_NUMBER -> ?DNS_TYPE_MR_BSTR;
        ?DNS_TYPE_NULL_NUMBER -> ?DNS_TYPE_NULL_BSTR;
        ?DNS_TYPE_WKS_NUMBER -> ?DNS_TYPE_WKS_BSTR;
        ?DNS_TYPE_PTR_NUMBER -> ?DNS_TYPE_PTR_BSTR;
        ?DNS_TYPE_HINFO_NUMBER -> ?DNS_TYPE_HINFO_BSTR;
        ?DNS_TYPE_MINFO_NUMBER -> ?DNS_TYPE_MINFO_BSTR;
        ?DNS_TYPE_MX_NUMBER -> ?DNS_TYPE_MX_BSTR;
        ?DNS_TYPE_TXT_NUMBER -> ?DNS_TYPE_TXT_BSTR;
        ?DNS_TYPE_RP_NUMBER -> ?DNS_TYPE_RP_BSTR;
        ?DNS_TYPE_AFSDB_NUMBER -> ?DNS_TYPE_AFSDB_BSTR;
        ?DNS_TYPE_X25_NUMBER -> ?DNS_TYPE_X25_BSTR;
        ?DNS_TYPE_ISDN_NUMBER -> ?DNS_TYPE_ISDN_BSTR;
        ?DNS_TYPE_RT_NUMBER -> ?DNS_TYPE_RT_BSTR;
        ?DNS_TYPE_NSAP_NUMBER -> ?DNS_TYPE_NSAP_BSTR;
        ?DNS_TYPE_SIG_NUMBER -> ?DNS_TYPE_SIG_BSTR;
        ?DNS_TYPE_KEY_NUMBER -> ?DNS_TYPE_KEY_BSTR;
        ?DNS_TYPE_PX_NUMBER -> ?DNS_TYPE_PX_BSTR;
        ?DNS_TYPE_GPOS_NUMBER -> ?DNS_TYPE_GPOS_BSTR;
        ?DNS_TYPE_AAAA_NUMBER -> ?DNS_TYPE_AAAA_BSTR;
        ?DNS_TYPE_LOC_NUMBER -> ?DNS_TYPE_LOC_BSTR;
        ?DNS_TYPE_NXT_NUMBER -> ?DNS_TYPE_NXT_BSTR;
        ?DNS_TYPE_EID_NUMBER -> ?DNS_TYPE_EID_BSTR;
        ?DNS_TYPE_NIMLOC_NUMBER -> ?DNS_TYPE_NIMLOC_BSTR;
        ?DNS_TYPE_SRV_NUMBER -> ?DNS_TYPE_SRV_BSTR;
        ?DNS_TYPE_ATMA_NUMBER -> ?DNS_TYPE_ATMA_BSTR;
        ?DNS_TYPE_NAPTR_NUMBER -> ?DNS_TYPE_NAPTR_BSTR;
        ?DNS_TYPE_KX_NUMBER -> ?DNS_TYPE_KX_BSTR;
        ?DNS_TYPE_CERT_NUMBER -> ?DNS_TYPE_CERT_BSTR;
        ?DNS_TYPE_DNAME_NUMBER -> ?DNS_TYPE_DNAME_BSTR;
        ?DNS_TYPE_SINK_NUMBER -> ?DNS_TYPE_SINK_BSTR;
        ?DNS_TYPE_OPT_NUMBER -> ?DNS_TYPE_OPT_BSTR;
        ?DNS_TYPE_APL_NUMBER -> ?DNS_TYPE_APL_BSTR;
        ?DNS_TYPE_DS_NUMBER -> ?DNS_TYPE_DS_BSTR;
        ?DNS_TYPE_CDS_NUMBER -> ?DNS_TYPE_CDS_BSTR;
        ?DNS_TYPE_SSHFP_NUMBER -> ?DNS_TYPE_SSHFP_BSTR;
        ?DNS_TYPE_CAA_NUMBER -> ?DNS_TYPE_CAA_BSTR;
        ?DNS_TYPE_IPSECKEY_NUMBER -> ?DNS_TYPE_IPSECKEY_BSTR;
        ?DNS_TYPE_RRSIG_NUMBER -> ?DNS_TYPE_RRSIG_BSTR;
        ?DNS_TYPE_NSEC_NUMBER -> ?DNS_TYPE_NSEC_BSTR;
        ?DNS_TYPE_DNSKEY_NUMBER -> ?DNS_TYPE_DNSKEY_BSTR;
        ?DNS_TYPE_CDNSKEY_NUMBER -> ?DNS_TYPE_CDNSKEY_BSTR;
        ?DNS_TYPE_NSEC3_NUMBER -> ?DNS_TYPE_NSEC3_BSTR;
        ?DNS_TYPE_NSEC3PARAM_NUMBER -> ?DNS_TYPE_NSEC3PARAM_BSTR;
        ?DNS_TYPE_DHCID_NUMBER -> ?DNS_TYPE_DHCID_BSTR;
        ?DNS_TYPE_HIP_NUMBER -> ?DNS_TYPE_HIP_BSTR;
        ?DNS_TYPE_NINFO_NUMBER -> ?DNS_TYPE_NINFO_BSTR;
        ?DNS_TYPE_RKEY_NUMBER -> ?DNS_TYPE_RKEY_BSTR;
        ?DNS_TYPE_TALINK_NUMBER -> ?DNS_TYPE_TALINK_BSTR;
        ?DNS_TYPE_SPF_NUMBER -> ?DNS_TYPE_SPF_BSTR;
        ?DNS_TYPE_UINFO_NUMBER -> ?DNS_TYPE_UINFO_BSTR;
        ?DNS_TYPE_UID_NUMBER -> ?DNS_TYPE_UID_BSTR;
        ?DNS_TYPE_GID_NUMBER -> ?DNS_TYPE_GID_BSTR;
        ?DNS_TYPE_UNSPEC_NUMBER -> ?DNS_TYPE_UNSPEC_BSTR;
        ?DNS_TYPE_TKEY_NUMBER -> ?DNS_TYPE_TKEY_BSTR;
        ?DNS_TYPE_TSIG_NUMBER -> ?DNS_TYPE_TSIG_BSTR;
        ?DNS_TYPE_IXFR_NUMBER -> ?DNS_TYPE_IXFR_BSTR;
        ?DNS_TYPE_AXFR_NUMBER -> ?DNS_TYPE_AXFR_BSTR;
        ?DNS_TYPE_MAILB_NUMBER -> ?DNS_TYPE_MAILB_BSTR;
        ?DNS_TYPE_MAILA_NUMBER -> ?DNS_TYPE_MAILA_BSTR;
        ?DNS_TYPE_ANY_NUMBER -> ?DNS_TYPE_ANY_BSTR;
        ?DNS_TYPE_DLV_NUMBER -> ?DNS_TYPE_DLV_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an rcode as a binary string.
-spec rcode_name(rcode()) -> binary() | undefined.
rcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_RCODE_NOERROR_NUMBER -> ?DNS_RCODE_NOERROR_BSTR;
        ?DNS_RCODE_FORMERR_NUMBER -> ?DNS_RCODE_FORMERR_BSTR;
        ?DNS_RCODE_SERVFAIL_NUMBER -> ?DNS_RCODE_SERVFAIL_BSTR;
        ?DNS_RCODE_NXDOMAIN_NUMBER -> ?DNS_RCODE_NXDOMAIN_BSTR;
        ?DNS_RCODE_NOTIMP_NUMBER -> ?DNS_RCODE_NOTIMP_BSTR;
        ?DNS_RCODE_REFUSED_NUMBER -> ?DNS_RCODE_REFUSED_BSTR;
        ?DNS_RCODE_YXDOMAIN_NUMBER -> ?DNS_RCODE_YXDOMAIN_BSTR;
        ?DNS_RCODE_YXRRSET_NUMBER -> ?DNS_RCODE_YXRRSET_BSTR;
        ?DNS_RCODE_NXRRSET_NUMBER -> ?DNS_RCODE_NXRRSET_BSTR;
        ?DNS_RCODE_NOTAUTH_NUMBER -> ?DNS_RCODE_NOTAUTH_BSTR;
        ?DNS_RCODE_NOTZONE_NUMBER -> ?DNS_RCODE_NOTZONE_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an opcode as a binary string.
-spec opcode_name(opcode()) -> binary() | undefined.
opcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_OPCODE_QUERY_NUMBER -> ?DNS_OPCODE_QUERY_BSTR;
        ?DNS_OPCODE_IQUERY_NUMBER -> ?DNS_OPCODE_IQUERY_BSTR;
        ?DNS_OPCODE_STATUS_NUMBER -> ?DNS_OPCODE_STATUS_BSTR;
        ?DNS_OPCODE_UPDATE_NUMBER -> ?DNS_OPCODE_UPDATE_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of a TSIG error as a binary string.
-spec tsigerr_name(tsig_error()) -> binary() | undefined.
tsigerr_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_TSIGERR_NOERROR_NUMBER -> ?DNS_TSIGERR_NOERROR_BSTR;
        ?DNS_TSIGERR_BADSIG_NUMBER -> ?DNS_TSIGERR_BADSIG_BSTR;
        ?DNS_TSIGERR_BADKEY_NUMBER -> ?DNS_TSIGERR_BADKEY_BSTR;
        ?DNS_TSIGERR_BADTIME_NUMBER -> ?DNS_TSIGERR_BADTIME_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an extended rcode as a binary string.
-spec ercode_name(ercode()) -> binary() | undefined.
ercode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_ERCODE_NOERROR_NUMBER -> ?DNS_ERCODE_NOERROR_BSTR;
        ?DNS_ERCODE_BADVERS_NUMBER -> ?DNS_ERCODE_BADVERS_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an extended option as a binary string.
-spec eoptcode_name(eoptcode()) -> binary() | undefined.
eoptcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_EOPTCODE_LLQ_NUMBER -> ?DNS_EOPTCODE_LLQ_BSTR;
        ?DNS_EOPTCODE_UL_NUMBER -> ?DNS_EOPTCODE_UL_BSTR;
        ?DNS_EOPTCODE_NSID_NUMBER -> ?DNS_EOPTCODE_NSID_BSTR;
        ?DNS_EOPTCODE_OWNER_NUMBER -> ?DNS_EOPTCODE_OWNER_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an LLQ opcode as a binary string.
-spec llqopcode_name(llqopcode()) -> binary() | undefined.
llqopcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_LLQOPCODE_SETUP_NUMBER -> ?DNS_LLQOPCODE_SETUP_BSTR;
        ?DNS_LLQOPCODE_REFRESH_NUMBER -> ?DNS_LLQOPCODE_REFRESH_BSTR;
        ?DNS_LLQOPCODE_EVENT_NUMBER -> ?DNS_LLQOPCODE_EVENT_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of an LLQ error code as a binary string.
-spec llqerrcode_name(llqerrcode()) -> binary() | undefined.
llqerrcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_LLQERRCODE_NOERROR_NUMBER -> ?DNS_LLQERRCODE_NOERROR_BSTR;
        ?DNS_LLQERRCODE_SERVFULL_NUMBER -> ?DNS_LLQERRCODE_SERVFULL_BSTR;
        ?DNS_LLQERRCODE_STATIC_NUMBER -> ?DNS_LLQERRCODE_STATIC_BSTR;
        ?DNS_LLQERRCODE_FORMATERR_NUMBER -> ?DNS_LLQERRCODE_FORMATERR_BSTR;
        ?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER -> ?DNS_LLQERRCODE_NOSUCHLLQ_BSTR;
        ?DNS_LLQERRCODE_BADVERS_NUMBER -> ?DNS_LLQERRCODE_BADVERS_BSTR;
        ?DNS_LLQERRCODE_UNKNOWNERR_NUMBER -> ?DNS_LLQERRCODE_UNKNOWNERR_BSTR;
        _ -> undefined
    end.

%% @doc Returns the name of a DNS algorithm as a binary string.
-spec alg_name(alg()) -> binary() | undefined.
alg_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_ALG_DSA_NUMBER -> ?DNS_ALG_DSA_BSTR;
        ?DNS_ALG_NSEC3DSA_NUMBER -> ?DNS_ALG_NSEC3DSA_BSTR;
        ?DNS_ALG_RSASHA1_NUMBER -> ?DNS_ALG_RSASHA1_BSTR;
        ?DNS_ALG_NSEC3RSASHA1_NUMBER -> ?DNS_ALG_NSEC3RSASHA1_BSTR;
        ?DNS_ALG_RSASHA256_NUMBER -> ?DNS_ALG_RSASHA256_BSTR;
        ?DNS_ALG_RSASHA512_NUMBER -> ?DNS_ALG_RSASHA512_BSTR;
        _ -> undefined
    end.

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
    Epoch = {{1970, 1, 1}, {0, 0, 0}},
    (calendar:datetime_to_gregorian_seconds(UniversalTime) -
        calendar:datetime_to_gregorian_seconds(Epoch)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec decode_bool(0 | 1) -> boolean().
decode_bool(0) -> false;
decode_bool(1) -> true.

-spec encode_bool(boolean()) -> 0 | 1.
encode_bool(false) -> 0;
encode_bool(true) -> 1.

-spec decode_text(binary()) -> [binary()].
decode_text(<<>>) ->
    [];
decode_text(Bin) when is_binary(Bin) ->
    {RB, String} = decode_string(Bin),
    [String | decode_text(RB)].

-spec decode_string(nonempty_binary()) -> {binary(), binary()}.
decode_string(<<Len, Bin:Len/binary, Rest/binary>>) ->
    {Rest, Bin}.

%% @doc Encodes a character-string as in RFC1035§3.3
%%
%% `<character-string>' is a single length octet followed by that number of characters.
%% `<character-string>' is treated as binary information, and can be up to 256 characters
%% in length (including the length octet).
-spec encode_string(binary(), binary()) -> nonempty_binary().
encode_string(Bin, StringBin) when byte_size(StringBin) < 256 ->
    Size = byte_size(StringBin),
    <<Bin/binary, Size, StringBin/binary>>.

%% @doc Encodes an array of character-strings as in RFC1035§3.3, splitting any oversized segment
%%
%% @see encode_string/2
-spec encode_text([binary()]) -> binary().
encode_text(Strings) ->
    do_decode_text(Strings, <<>>).

-spec do_decode_text([binary()], binary()) -> binary().
do_decode_text([], Bin) ->
    Bin;
do_decode_text([<<Head:255/binary, Tail/binary>> | Strings], Acc) ->
    do_decode_text([Tail | Strings], <<Acc/binary, 255, Head/binary>>);
do_decode_text([<<>> | Strings], Acc) ->
    do_decode_text(Strings, Acc);
do_decode_text([S | Strings], Acc) ->
    Size = byte_size(S),
    do_decode_text(Strings, <<Acc/binary, Size, S/binary>>).

-spec decode_svcb_svc_params(binary()) -> svcb_svc_params().
decode_svcb_svc_params(Bin) ->
    decode_svcb_svc_params(Bin, #{}).

-spec decode_svcb_svc_params(binary(), svcb_svc_params()) -> svcb_svc_params().
decode_svcb_svc_params(<<>>, SvcParams) ->
    SvcParams;
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_ALPN:16, Len:16, SvcParamValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_ALPN => SvcParamValueBin});
decode_svcb_svc_params(<<?DNS_SVCB_PARAM_NO_DEFAULT_ALPN:16, 0:16, Rest/binary>>, SvcParams) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_PORT:16, Len:16, SvcParamValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    <<V:16/integer>> = SvcParamValueBin,
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_PORT => V});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_ECHCONFIG:16, Len:16, SvcParamValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_ECHCONFIG => SvcParamValueBin});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_IPV4HINT:16, Len:16, SvcParamValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_IPV4HINT => SvcParamValueBin});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_IPV6HINT:16, Len:16, SvcParamValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_IPV6HINT => SvcParamValueBin}).

-spec encode_svcb_svc_params(map()) -> binary().

encode_svcb_svc_params(SvcParams) ->
    SortedKeys = lists:sort(maps:keys(SvcParams)),
    lists:foldl(
        fun(K, AccIn) ->
            encode_svcb_svc_params_value(K, maps:get(K, SvcParams), AccIn)
        end,
        <<>>,
        SortedKeys
    ).

-spec encode_svcb_svc_params_value(_, _, _) -> any().
encode_svcb_svc_params_value(alpn, V, Bin) ->
    encode_svcb_svc_params_value(?DNS_SVCB_PARAM_ALPN, V, Bin);
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_ALPN = K, V, Bin) ->
    L = byte_size(V),
    <<Bin/binary, K:16/integer, L:16/integer, V/binary>>;
encode_svcb_svc_params_value(no_default_alpn, V, Bin) ->
    encode_svcb_svc_params_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, V, Bin);
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_NO_DEFAULT_ALPN = K, _, Bin) ->
    L = 0,
    <<Bin/binary, K:16/integer, L:16/integer>>;
encode_svcb_svc_params_value(port, V, Bin) ->
    encode_svcb_svc_params_value(?DNS_SVCB_PARAM_PORT, V, Bin);
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_PORT = K, V, Bin) ->
    <<Bin/binary, K:16/integer, 2:16/integer, V:16/integer>>;
encode_svcb_svc_params_value(echconfig, V, Bin) ->
    encode_svcb_svc_params_value(?DNS_SVCB_PARAM_ECHCONFIG, V, Bin);
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_ECHCONFIG = K, V, Bin) ->
    L = byte_size(V),
    <<Bin/binary, K:16/integer, L:16/integer, V/binary>>;
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV4HINT = K, V, Bin) ->
    L = byte_size(V),
    <<Bin/binary, K:16/integer, L:16/integer, V/binary>>;
encode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV6HINT = K, V, Bin) ->
    L = byte_size(V),
    <<Bin/binary, K:16/integer, L:16/integer, V/binary>>;
encode_svcb_svc_params_value(_, _, Bin) ->
    Bin.

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

-spec round_pow(10, non_neg_integer()) -> integer().
round_pow(N, E) ->
    round(math:pow(N, E)).

-spec strip_leading_zeros(binary()) -> binary().
strip_leading_zeros(<<0, Rest/binary>>) ->
    strip_leading_zeros(Rest);
strip_leading_zeros(Binary) ->
    Binary.
