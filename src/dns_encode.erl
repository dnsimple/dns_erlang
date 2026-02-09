-module(dns_encode).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

%% Minimal size of an OptRR record without any data
-define(OPTRR_MIN_SIZE, 11).
%% 2^31 - 1, the largest signed 32-bit integer value
-define(MAX_INT32, ((1 bsl 31) - 1)).
-define(HEADER_SIZE, 12).
-define(CLASS_IS_IN(T), (T =:= ?DNS_CLASS_IN orelse T =:= ?DNS_CLASS_NONE)).

-export([encode/1, encode/2]).
-export([encode_rrdata/2]).
-export([encode_rsa_key/2, encode_dsa_key/1]).

-ifdef(TEST).
-export([
    encode_dname/3,
    encode_rrdata/4,
    encode_optrrdata/1,
    encode_svcb_svc_params/1
]).
-endif.

-compile({inline, [encode_bool/1]}).

-type compmap() :: #{dns:labels() => non_neg_integer()}.
-export_type([compmap/0]).

-spec encode(dns:message()) -> dns:message_bin().
encode(
    #dns_message{
        questions = Questions,
        answers = Answers,
        authority = Authority,
        additional = Additional
    } = Msg
) ->
    Head = encode_message_header(Msg),
    encode_sections(Head, #{}, [Questions, Answers, Authority, Additional]).

%% Tail-recursive function to encode all sections (replaces lists:foldl)
%% This allows BEAM to optimize binary appending
-spec encode_sections(binary(), compmap(), [dns:records()]) -> binary().
encode_sections(Acc, _CompMap, []) ->
    Acc;
encode_sections(Acc, CompMap, [Section | Rest]) ->
    {NewBin, NewCompMap} = encode_append_section(Acc, CompMap, Section),
    encode_sections(NewBin, NewCompMap, Rest).

%% Tail-recursive function to encode records within a section (replaces lists:foldl)
%% This allows BEAM to optimize binary appending
-spec encode_append_section(binary(), compmap(), dns:records()) -> {binary(), compmap()}.
encode_append_section(Acc, CompMap, []) ->
    {Acc, CompMap};
encode_append_section(Acc, CompMap, [Rec | Rest]) ->
    {NewBin, CompMap0} = encode_message_rec_unbounded(Acc, CompMap, Rec),
    encode_append_section(NewBin, CompMap0, Rest).

%% Encode a dns_message record - will truncate the message as needed.
-spec encode(dns:message(), dns:encode_message_opts()) ->
    dns:message_bin()
    | {dns:message_bin(), dns:tsig_mac()}
    | {truncated, dns:message_bin(), dns:message()}
    | {truncated, dns:message_bin(), dns:tsig_mac(), dns:message()}.
encode(#dns_message{id = MsgId, additional = Additional} = Msg, Opts) ->
    EncodeFun = get_tc_mode_fun(Opts),
    MaxSize = get_max_size(Opts, Additional),
    case maps:get(tsig, Opts, undefined) of
        undefined ->
            case EncodeFun(Msg, MaxSize) of
                {Bin, Leftover} -> {truncated, Bin, Leftover};
                Bin -> Bin
            end;
        #{alg := Alg, name := Name} = TSIGOpts ->
            LowerAlg = dns_domain:to_lower(Alg),
            LowerName = dns_domain:to_lower(Name),
            EncodedName = dns_domain:to_wire(LowerName),
            OrigMsgId = maps:get(msgid, TSIGOpts, MsgId),
            Other = maps:get(other, TSIGOpts, <<>>),
            TSIGSize = dns_tsig:encode_message_tsig_size(EncodedName, LowerAlg, Other),
            Msg0 = Msg#dns_message{id = OrigMsgId},
            {MsgBin, MaybeMsgLeftover} =
                case EncodeFun(Msg0, MaxSize - TSIGSize) of
                    {A, B} -> {A, B};
                    A -> {A, undefined}
                end,
            {MsgBin0, NewMAC} = dns_tsig:encode_message_tsig_add(
                MsgId, EncodedName, LowerAlg, Other, TSIGOpts, MsgBin
            ),
            case MaybeMsgLeftover of
                undefined ->
                    {MsgBin0, NewMAC};
                _ ->
                    MsgLeftover0 = MaybeMsgLeftover#dns_message{id = MsgId},
                    {truncated, MsgBin0, NewMAC, MsgLeftover0}
            end
    end.

-spec get_tc_mode_fun(dns:encode_message_opts()) ->
    fun((dns:message(), number()) -> dns:message_bin() | {dns:message_bin(), dns:message()}).
get_tc_mode_fun(Opts) ->
    case maps:get(tc_mode, Opts, default) of
        default ->
            fun encode_message_default/2;
        llq_event ->
            fun encode_message_llq/2;
        axfr ->
            fun encode_message_axfr/2;
        _ ->
            erlang:error(badarg)
    end.

-spec get_max_size(dns:encode_message_opts(), dns:additional()) -> 512..65535.
get_max_size(#{max_size := Value}, _) when
    not is_integer(Value) orelse Value < 512 orelse 65535 < Value
->
    erlang:error(badarg);
get_max_size(_, [#dns_optrr{udp_payload_size = Value} | _]) when
    not is_integer(Value) orelse Value < 512 orelse 65535 < Value
->
    erlang:error(badarg);
get_max_size(#{max_size := Value}, _) ->
    Value;
get_max_size(_, [#dns_optrr{udp_payload_size = Value} | _]) ->
    Value;
get_max_size(_, _) ->
    512.

-spec encode_message_default(dns:message(), number()) -> binary().
encode_message_default(
    #dns_message{qc = QC, questions = Questions, additional = Additional} = Msg0, MaxSize
) ->
    %% If EDNS0 is used, we need to reserve space for appending the OptRR record at its minimal
    PreservedOptRRBinSize = preserve_optrr_size(Additional),
    SpaceLeft0 = MaxSize - ?HEADER_SIZE - PreservedOptRRBinSize,
    %% RFC6891 §7, the question section MUST always be present
    %% Pass a 12-byte placeholder header so position calculations start from 12 (header size)
    %% instead of 0. This ensures compression pointers are calculated correctly.
    HeaderPlaceholder = <<0:96>>,
    {Acc1WithHeader, CompMap1} = encode_append_section(HeaderPlaceholder, #{}, Questions),
    %% Extract the question section (skip the 12-byte header placeholder)
    Acc1 = binary_part(Acc1WithHeader, ?HEADER_SIZE, byte_size(Acc1WithHeader) - ?HEADER_SIZE),
    Acc1Size = byte_size(Acc1),
    SpaceLeft1 = SpaceLeft0 - Acc1Size,
    Pos1 = ?HEADER_SIZE + Acc1Size,
    MsgTmp = Msg0#dns_message{qc = 0, questions = []},
    case encode_message_d_req(MsgTmp, CompMap1, Pos1, SpaceLeft1, Acc1) of
        truncated ->
            %% We ran out of space, we MUST append a OptRR EDNS0 record,
            %% and this takes precedence over the body
            {AddCountFull, OptRRBinFull} = ensure_optrr(Additional, full),
            OptRRBinSizeFull = byte_size(OptRRBinFull),
            SpaceForOptRR = MaxSize - ?HEADER_SIZE - Acc1Size,
            case OptRRBinSizeFull =< SpaceForOptRR of
                true ->
                    %% Full OptRR fits
                    Head = build_header(Msg0, true, QC, 0, 0, AddCountFull),
                    <<Head/binary, Acc1/binary, OptRRBinFull/binary>>;
                false ->
                    %% Full OptRR doesn't fit, but minimal (should) do
                    {AddCountMin, OptRRBinMin} = ensure_optrr(Additional, minimal),
                    Head = build_header(Msg0, true, QC, 0, 0, AddCountMin),
                    %% If minimal would not fit either, it is most likely bad input,
                    %% the client code should already know the original packet,
                    %% composed of the question plus EDNS, should have fit in this size limit.
                    %% We MUST include OptRR per RFC6891, so include even if it may exceed the space
                    <<Head/binary, Acc1/binary, OptRRBinMin/binary>>
            end;
        {Body, CompMap2} ->
            BodySize = byte_size(Body),
            {OptRRBin, Ad0} = encode_message_pop_optrr(Additional),
            OptRRBinSize = byte_size(OptRRBin),
            Pos2 = BodySize,
            #dns_message{anc = ANC, auc = AUC} = Msg0,
            case SpaceLeft1 + PreservedOptRRBinSize - BodySize of
                SpaceLeft2 when SpaceLeft2 < OptRRBinSize ->
                    Head = build_header(Msg0, false, QC, ANC, AUC, 0),
                    <<Head/binary, Body/binary>>;
                SpaceLeft2 ->
                    Pos3 = Pos2 + OptRRBinSize,
                    SpaceLeft3 = SpaceLeft2 - OptRRBinSize,
                    OptC =
                        case OptRRBinSize of
                            0 -> 0;
                            _ -> 1
                        end,
                    case encode_message_d_opt(Pos3, SpaceLeft3, CompMap2, Ad0) of
                        false ->
                            Head = build_header(Msg0, false, QC, ANC, AUC, OptC),
                            <<Head/binary, Body/binary, OptRRBin/binary>>;
                        {_, AdBin} ->
                            #dns_message{adc = ADC} = Msg0,
                            Head = build_header(Msg0, false, QC, ANC, AUC, ADC),
                            <<Head/binary, Body/binary, OptRRBin/binary, AdBin/binary>>
                    end
            end
    end.

-spec build_header(
    dns:message(), boolean(), dns:uint16(), dns:uint16(), dns:uint16(), dns:uint16()
) ->
    dns:message_bin().
build_header(#dns_message{tc = TC} = Msg, TCBool, EncQC, EncANC, EncAUC, EncADC) ->
    Msg0 = Msg#dns_message{
        qc = EncQC,
        anc = EncANC,
        auc = EncAUC,
        adc = EncADC,
        tc = TC orelse TCBool
    },
    encode_message_header(Msg0).

%% Encodes authorities, and answers, for as long as there is space
%% Will return a false tag if there wasn't enough space
-spec encode_message_d_req(dns:message(), compmap(), pos_integer(), integer(), binary()) ->
    truncated | {binary(), compmap()}.
encode_message_d_req(Msg, CompMap, Pos, SpaceLeft, Acc) ->
    case encode_message_pop(Msg) of
        {additional, _, _} ->
            {Acc, CompMap};
        {Section, RecsLen, Recs} ->
            case encode_message_rec_list(Recs, CompMap, Pos, SpaceLeft) of
                {CompMap1, NewBin, []} ->
                    NewBinSize = byte_size(NewBin),
                    Pos1 = Pos + NewBinSize,
                    SpaceLeft1 = SpaceLeft - NewBinSize,
                    Msg1 = encode_message_put(Msg, [], RecsLen, Section),
                    Acc1 = <<Acc/binary, NewBin/binary>>,
                    encode_message_d_req(Msg1, CompMap1, Pos1, SpaceLeft1, Acc1);
                _ ->
                    truncated
            end
    end.

-spec encode_message_d_opt(
    pos_integer(),
    number(),
    compmap(),
    dns:records()
) -> false | {non_neg_integer(), bitstring()}.
encode_message_d_opt(Pos, SpaceLeft, CompMap, Recs) ->
    case encode_message_rec_list(Recs, CompMap, Pos, SpaceLeft) of
        {_, Bin, []} -> {length(Recs), Bin};
        _ -> false
    end.

-spec encode_message_axfr(dns:message(), number()) -> binary() | {binary(), dns:message()}.
encode_message_axfr(#dns_message{} = Msg, MaxSize) ->
    Pos = ?HEADER_SIZE,
    SpaceLeft = MaxSize - Pos,
    encode_message_axfr(Msg, Pos, SpaceLeft, #{}, <<>>).

-spec encode_message_axfr(dns:message(), pos_integer(), number(), compmap(), binary()) ->
    binary() | {binary(), dns:message()}.
encode_message_axfr(Msg, Pos, SpaceLeft, CompMap, Bin) ->
    {Section, RecsLen, Recs} = encode_message_pop(Msg),
    {CompMap0, NewBin, Recs0} = encode_message_rec_list(Recs, CompMap, Pos, SpaceLeft),
    Recs0Len = length(Recs0),
    EncodedLen = RecsLen - Recs0Len,
    Msg1 = encode_message_put(Msg, Recs0, EncodedLen, Section),
    case Recs0Len of
        0 when Section =:= additional ->
            Head = encode_message_header(Msg1),
            <<Head/binary, Bin/binary, NewBin/binary>>;
        0 ->
            NewBinSize = byte_size(NewBin),
            Pos0 = Pos + NewBinSize,
            SpaceLeft0 = SpaceLeft - NewBinSize,
            Bin0 = <<Bin/binary, NewBin/binary>>,
            encode_message_axfr(Msg1, Pos0, SpaceLeft0, CompMap0, Bin0);
        _ ->
            Head = encode_message_header(Msg1),
            Msg2 = encode_message_a_setcounts(Msg1),
            {<<Head/binary, Bin/binary, NewBin/binary>>, Msg2}
    end.

-spec encode_message_pop(dns:message()) ->
    {additional, dns:uint16(), dns:additional()}
    | {answers, dns:uint16(), dns:answers()}
    | {authority, dns:uint16(), dns:authority()}
    | {questions, dns:uint16(), dns:questions()}.
encode_message_pop(#dns_message{qc = C, questions = [_ | _] = Recs}) ->
    {questions, C, Recs};
encode_message_pop(#dns_message{anc = C, answers = [_ | _] = Recs}) ->
    {answers, C, Recs};
encode_message_pop(#dns_message{auc = C, authority = [_ | _] = Recs}) ->
    {authority, C, Recs};
encode_message_pop(#dns_message{adc = C, additional = Recs}) ->
    {additional, C, Recs}.

-spec encode_message_put
    (dns:message(), dns:questions(), dns:uint16(), questions) -> dns:message();
    (dns:message(), dns:answers(), dns:uint16(), answers) -> dns:message();
    (dns:message(), dns:authority(), dns:uint16(), authority) -> dns:message();
    (dns:message(), dns:additional(), dns:uint16(), additional) -> dns:message().
encode_message_put(Msg, Recs, Count, questions) ->
    Msg#dns_message{qc = Count, questions = Recs};
encode_message_put(Msg, Recs, Count, answers) ->
    Msg#dns_message{anc = Count, answers = Recs};
encode_message_put(Msg, Recs, Count, authority) ->
    Msg#dns_message{auc = Count, authority = Recs};
encode_message_put(Msg, Recs, Count, additional) ->
    Msg#dns_message{adc = Count, additional = Recs}.

-spec encode_message_a_setcounts(dns:message()) -> dns:message().
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

-spec encode_message_header(dns:message()) -> <<_:96>>.
encode_message_header(#dns_message{
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

-spec encode_message_llq(dns:message(), number()) -> binary() | {binary(), dns:message()}.
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
    Pos = ?HEADER_SIZE,
    SpaceLeft = MaxSize - Pos,
    {CompMap0, QBin, []} = encode_message_rec_list(Q, #{}, Pos, SpaceLeft),
    QBinSize = byte_size(QBin),
    SpaceLeft0 = SpaceLeft - QBinSize,
    Pos0 = QBinSize + Pos,
    {_, AuAdTmp, []} = encode_message_rec_list(AuAd, CompMap0, Pos0, SpaceLeft0),
    AuAdTmpSize = byte_size(AuAdTmp),
    {CompMap1, AnBin, LeftoverAn} =
        encode_message_rec_list(Answers, CompMap0, Pos0, SpaceLeft0 - AuAdTmpSize),
    LeftoverAnC = length(LeftoverAn),
    EncodedAnC = AnswersLen - LeftoverAnC,
    AnBinSize = byte_size(AnBin),
    Pos1 = Pos0 + AnBinSize,
    SpaceLeft1 = SpaceLeft0 - AnBinSize,
    {_, AuAdBin, []} =
        encode_message_rec_list(AuAd, CompMap1, Pos1, SpaceLeft1),
    Msg0 = Msg#dns_message{qc = QC, anc = EncodedAnC, auc = AuthorityLen, adc = AdditionalLen},
    Head = encode_message_header(Msg0),
    Bin = <<Head/binary, QBin/binary, AnBin/binary, AuAdBin/binary>>,
    case LeftoverAnC of
        0 -> Bin;
        _ -> {Bin, Msg#dns_message{anc = LeftoverAnC, answers = LeftoverAn}}
    end.

-spec encode_message_rec_list(dns:records(), compmap(), pos_integer(), number()) ->
    {compmap(), binary(), dns:records()}.
encode_message_rec_list(Recs, CompMap, Pos, SpaceLeft) ->
    encode_message_rec_list(Recs, CompMap, Pos, SpaceLeft, <<>>).

-spec encode_message_rec_list(dns:records(), compmap(), pos_integer(), number(), binary()) ->
    {compmap(), binary(), dns:records()}.
encode_message_rec_list([Rec | Rest] = Recs, CompMap, Pos, SpaceLeft, Body) ->
    case encode_message_rec(Rec, CompMap, Pos, SpaceLeft, Body) of
        {NewBody, CompMap1} ->
            NewBinSize = byte_size(NewBody) - byte_size(Body),
            Pos1 = Pos + NewBinSize,
            SpaceLeft1 = SpaceLeft - NewBinSize,
            encode_message_rec_list(Rest, CompMap1, Pos1, SpaceLeft1, NewBody);
        not_appended ->
            {CompMap, Body, Recs}
    end;
encode_message_rec_list([], CompMap, _, _, Body) ->
    {CompMap, Body, []}.

-spec encode_message_rec(
    dns:query() | dns:optrr() | dns:rr(),
    compmap(),
    non_neg_integer(),
    non_neg_integer() | infinity,
    binary()
) -> {binary(), compmap()} | not_appended.
encode_message_rec(#dns_query{name = N, type = T, class = C}, CompMap, Pos, MaxSize, Acc) ->
    {NameBin, CompMap0} = encode_dname(CompMap, Pos, N),
    RecSize = byte_size(NameBin) + 2 + 2,
    case RecSize =< MaxSize of
        true ->
            Acc1 = <<Acc/binary, NameBin/binary, T:16, C:16>>,
            {Acc1, CompMap0};
        false ->
            not_appended
    end;
encode_message_rec(#dns_optrr{} = OptRR, CompMap, _Pos, MaxSize, Acc) ->
    OptRRBin = encode_optrr(<<>>, OptRR),
    OptRRSize = byte_size(OptRRBin),
    case OptRRSize =< MaxSize of
        true ->
            Acc1 = <<Acc/binary, OptRRBin/binary>>,
            {Acc1, CompMap};
        false ->
            not_appended
    end;
encode_message_rec(
    #dns_rr{name = N, type = T, class = C, ttl = TTL, data = D},
    CompMap,
    Pos,
    MaxSize,
    Acc
) ->
    maybe
        %% Check if we have at least enough space for the fixed header
        %% If not, we can skip the expensive rrdata encoding
        {NameBin, CompMap0} = encode_dname(CompMap, Pos, N),
        %% Fixed header size: type (2) + class (2) + ttl (4) + rdlength (2) = 10 bytes
        FixedHeaderSize = byte_size(NameBin) + 10,
        true ?= FixedHeaderSize =< MaxSize,
        DPos = Pos + FixedHeaderSize,
        {DBin, CompMap1} = encode_rrdata(DPos, C, D, CompMap0),
        DSize = byte_size(DBin),
        RecSize = FixedHeaderSize + DSize,
        true ?= RecSize =< MaxSize,
        Acc1 = <<Acc/binary, NameBin/binary, T:16, C:16, TTL:32, DSize:16, DBin/binary>>,
        {Acc1, CompMap1}
    else
        false ->
            not_appended
    end.

-spec encode_message_rec_unbounded(binary(), compmap(), dns:query() | dns:optrr() | dns:rr()) ->
    {binary(), compmap()}.
encode_message_rec_unbounded(Acc, CompMap, #dns_query{name = N, type = T, class = C}) ->
    {Wire, CompMap0} = encode_dname(CompMap, byte_size(Acc), N),
    Acc1 = <<Acc/binary, Wire/binary>>,
    {<<Acc1/binary, T:16, C:16>>, CompMap0};
encode_message_rec_unbounded(Acc, CompMap, #dns_optrr{} = OptRR) ->
    Acc1 = encode_optrr(Acc, OptRR),
    {Acc1, CompMap};
encode_message_rec_unbounded(
    Acc,
    CompMap,
    #dns_rr{
        name = N,
        type = T,
        class = C,
        ttl = TTL,
        data = D
    }
) ->
    {Wire, CompMap0} = encode_dname(CompMap, byte_size(Acc), N),
    Acc1 = <<Acc/binary, Wire/binary>>,
    Acc2 = <<Acc1/binary, T:16, C:16, TTL:32>>,
    {DBin, CompMap1} = encode_rrdata(byte_size(Acc2) + 2, C, D, CompMap0),
    Acc3 = <<Acc2/binary, (byte_size(DBin)):16, DBin/binary>>,
    {Acc3, CompMap1}.

-spec encode_message_pop_optrr(dns:additional()) -> {binary(), dns:additional()}.
encode_message_pop_optrr([#dns_optrr{} = OptRR | Rest]) ->
    {encode_optrr(<<>>, OptRR), Rest};
encode_message_pop_optrr(Other) ->
    {<<>>, Other}.

-spec ensure_optrr(dns:additional(), minimal | full) -> {0 | 1, binary()}.
ensure_optrr([#dns_optrr{} = OptRR | _], full) ->
    {1, encode_optrr(<<>>, OptRR)};
ensure_optrr([#dns_optrr{} = OptRR | _], minimal) ->
    {1, encode_optrr(<<>>, OptRR#dns_optrr{data = []})};
ensure_optrr(_, _) ->
    {0, <<>>}.

-spec preserve_optrr_size(dns:additional()) -> non_neg_integer().
preserve_optrr_size([#dns_optrr{} | _]) ->
    ?OPTRR_MIN_SIZE;
preserve_optrr_size(_) ->
    0.

-spec encode_optrr(binary(), dns:optrr()) -> binary().
encode_optrr(Acc, #dns_optrr{
    udp_payload_size = UPS,
    ext_rcode = ExtRcode0,
    version = Version0,
    dnssec = DNSSEC,
    data = Data
}) ->
    %% TODO: if returning BADVERS, we want to avoid returning any answer in the top #dns_message{}
    {Version, ExtRcode} = ensure_edns_version(Version0, ExtRcode0),
    DNSSECBit = encode_bool(DNSSEC),
    RRBin = encode_optrrdata(Data),
    RRBinSize = byte_size(RRBin),
    <<Acc/binary, 0, ?DNS_TYPE_OPT:16, UPS:16, ExtRcode:8, Version:8, DNSSECBit:1, 0:15,
        RRBinSize:16, RRBin/binary>>.

ensure_edns_version(Version, ExtRcode) when
    ?DNS_EDNS_MIN_VERSION =< Version andalso Version =< ?DNS_EDNS_MAX_VERSION
->
    {Version, ExtRcode};
ensure_edns_version(_, _) ->
    {?DNS_EDNS_MAX_VERSION, ?DNS_ERCODE_BADVERS_NUMBER}.

-spec encode_rrdata(dns:class(), dns:rrdata()) -> binary().
encode_rrdata(Class, Data) ->
    {Bin, undefined} = encode_rrdata(0, Class, Data, undefined),
    Bin.

-spec encode_rrdata(non_neg_integer(), dns:class(), dns:rrdata(), undefined | compmap()) ->
    {binary(), undefined | compmap()}.
encode_rrdata(_Pos, Class, #dns_rrdata_a{ip = {A, B, C, D}}, CompMap) when
    ?CLASS_IS_IN(Class)
->
    {<<A, B, C, D>>, CompMap};
encode_rrdata(_Pos, Class, #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}}, CompMap) when
    ?CLASS_IS_IN(Class)
->
    {<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>, CompMap};
encode_rrdata(
    _Pos, Class, #dns_rrdata_eui48{address = Address}, CompMap
) when
    ?CLASS_IS_IN(Class), 6 =:= byte_size(Address)
->
    {Address, CompMap};
encode_rrdata(
    _Pos, Class, #dns_rrdata_eui64{address = Address}, CompMap
) when
    ?CLASS_IS_IN(Class), 8 =:= byte_size(Address)
->
    {Address, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_afsdb{
        subtype = Subtype,
        hostname = Hostname
    },
    CompMap
) ->
    HostnameBin = dns_domain:to_wire(Hostname),
    {<<Subtype:16, HostnameBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value}, CompMap) ->
    Len = byte_size(Tag),
    {<<Flags:8, Len:8, Tag/binary, Value/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_cert{
        type = Type,
        keytag = KeyTag,
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
encode_rrdata(_Pos, ?DNS_CLASS_IN, #dns_rrdata_openpgpkey{data = Bin}, CompMap) ->
    {Bin, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_uri{
        priority = Priority,
        weight = Weight,
        target = Target
    },
    CompMap
) ->
    {<<Priority:16, Weight:16, Target/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_resinfo{data = Strings}, CompMap) ->
    {encode_text(Strings), CompMap};
encode_rrdata(_Pos, ?DNS_CLASS_IN, #dns_rrdata_wallet{data = Bin}, CompMap) ->
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
    PKBin = encode_rsa_key(E, M),
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
    PKBin = encode_dsa_key(PKM),
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
) when
    (Alg =:= ?DNS_ALG_ECDSAP256SHA256 andalso is_binary(PK) andalso 64 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ECDSAP384SHA384 andalso is_binary(PK) andalso 96 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ED25519 andalso is_binary(PK) andalso 32 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ED448 andalso is_binary(PK) andalso 57 =:= byte_size(PK))
->
    {<<Flags:16, Protocol:8, Alg:8, PK/binary>>, CompMap};
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
    PKBin = encode_rsa_key(E, M),
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
    PKBin = encode_dsa_key(PKM),
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
) when
    (Alg =:= ?DNS_ALG_ECDSAP256SHA256 andalso is_binary(PK) andalso 64 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ECDSAP384SHA384 andalso is_binary(PK) andalso 96 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ED25519 andalso is_binary(PK) andalso 32 =:= byte_size(PK)) orelse
        (Alg =:= ?DNS_ALG_ED448 andalso is_binary(PK) andalso 57 =:= byte_size(PK))
->
    {<<Flags:16, Protocol:8, Alg:8, PK/binary>>, CompMap};
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
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_zonemd{
        serial = Serial,
        scheme = Scheme,
        algorithm = Algorithm,
        hash = Hash
    },
    CompMap
) ->
    {<<Serial:32, Scheme:8, Algorithm:8, Hash/binary>>, CompMap};
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
    DNameBin = dns_domain:to_wire(DName),
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
    {Wire, NewCompMap} = dns_domain:to_wire(CompMap, Pos + 2, Name),
    {<<Pref:16, Wire/binary>>, NewCompMap};
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
    {Wire, NewCompMap} = encode_dname(CompMap, Pos + 2, Name),
    {<<Pref:16, Wire/binary>>, NewCompMap};
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
    ReplacementBin = dns_domain:to_wire(Replacement),
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
    NextDNameBin = dns_domain:to_wire(NextDName),
    TypesBin = encode_nsec_types(Types),
    {<<NextDNameBin/binary, TypesBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_csync{
        soa_serial = SOASerial,
        flags = Flags,
        types = Types
    },
    CompMap
) ->
    TypesBin = encode_nsec_types(Types),
    {<<SOASerial:32, Flags:16, TypesBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_dsync{
        rrtype = RRType,
        scheme = Scheme,
        port = Port,
        target = Target
    },
    CompMap
) ->
    %% DSYNC target must be uncompressed per RFC 9859
    TargetBin = dns_domain:to_wire(Target),
    {<<RRType:16, Scheme:8, Port:16, TargetBin/binary>>, CompMap};
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
    _Pos,
    _Class,
    #dns_rrdata_tlsa{
        usage = Usage,
        selector = Selector,
        matching_type = MatchingType,
        certificate = Certificate
    },
    CompMap
) ->
    {<<Usage:8, Selector:8, MatchingType:8, Certificate/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_smimea{
        usage = Usage,
        selector = Selector,
        matching_type = MatchingType,
        certificate = Certificate
    },
    CompMap
) ->
    {<<Usage:8, Selector:8, MatchingType:8, Certificate/binary>>, CompMap};
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
    MboxBin = dns_domain:to_wire(Mbox),
    TxtBin = dns_domain:to_wire(Txt),
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
        keytag = KeyTag,
        signers_name = SignersName,
        signature = Sig
    },
    CompMap
) ->
    SignersNameBin = dns_domain:to_wire(SignersName),
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
    {Wire, NewCompMap} = encode_dname(CompMap, Pos + 2, Name),
    {<<Pref:16, Wire/binary>>, NewCompMap};
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
    {RWire, RNCMap} = encode_dname(MNCMap, NewPos, RName),
    RNBin = <<MNBin/binary, RWire/binary>>,
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
    TargetBin = dns_domain:to_wire(Target),
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
    TargetNameBin = dns_domain:to_wire(TargetName),
    SvcParamsBin = encode_svcb_svc_params(SvcParams),
    {<<SvcPriority:16, TargetNameBin/binary, SvcParamsBin/binary>>, CompMap};
encode_rrdata(
    _Pos,
    _Class,
    #dns_rrdata_https{
        svc_priority = SvcPriority,
        target_name = TargetName,
        svc_params = SvcParams
    },
    CompMap
) ->
    TargetNameBin = dns_domain:to_wire(TargetName),
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
    AlgBin = dns_domain:to_wire(Alg),
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

-spec encode_loc_size(integer()) -> <<_:8>>.
encode_loc_size(Size) when is_integer(Size) ->
    do_encode_loc_size(Size, 0).

-spec do_encode_loc_size(integer(), non_neg_integer()) -> <<_:8>>.
do_encode_loc_size(Size, Exponent) ->
    case Size rem round_pow(Exponent + 1) of
        Size ->
            Base = Size div round_pow(Exponent),
            <<Base:4, Exponent:4>>;
        _ ->
            do_encode_loc_size(Size, Exponent + 1)
    end.

-spec encode_nsec_types([integer()]) -> binary().
encode_nsec_types([]) ->
    <<>>;
encode_nsec_types([_ | _] = UnsortedTypes) ->
    [FirstType | _] = Types = lists:usort(UnsortedTypes),
    FirstWindowNum = FirstType div 256,
    FirstLastType = FirstWindowNum * 256,
    do_encode_nsec_types(<<>>, <<>>, FirstWindowNum, FirstLastType, Types).

-spec do_encode_nsec_types(binary(), bitstring(), integer(), number(), [integer()]) ->
    <<_:16, _:_*8>>.
do_encode_nsec_types(Bin, BMP0, WindowNum, _LastType, []) ->
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    <<Bin/binary, WindowNum:8, BMPSize:8, BMP:BMPSize/binary>>;
do_encode_nsec_types(Bin, BMP0, OldWindowNum, _LastType, [Type | _] = Types) when
    Type div 256 =/= OldWindowNum
->
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    NewBin = <<Bin/binary, OldWindowNum:8, BMPSize:8, BMP:BMPSize/binary>>,
    NewBMP = <<>>,
    NewWindowNum = Type div 256,
    NewLastType = NewWindowNum * 256,
    do_encode_nsec_types(NewBin, NewBMP, NewWindowNum, NewLastType, Types);
do_encode_nsec_types(Bin, BMP, WindowNum, LastType, [Type | Types]) ->
    PadBy =
        case LastType rem 256 of
            0 -> Type rem 256;
            _ -> Type - LastType - 1
        end,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    do_encode_nsec_types(Bin, NewBMP, WindowNum, Type, Types).

-spec encode_nxt_bmp([non_neg_integer()]) -> bitstring().
encode_nxt_bmp(UnsortedTypes) when is_list(UnsortedTypes) ->
    Types = lists:usort(UnsortedTypes),
    encode_nxt_bmp(Types, 0, <<>>).

-spec encode_nxt_bmp([non_neg_integer()], non_neg_integer(), bitstring()) -> bitstring().
encode_nxt_bmp([], _LastType, BMP) ->
    pad_bmp(BMP);
encode_nxt_bmp([Type | Types], 0, BMP) ->
    NewBMP = <<BMP/bitstring, 0:Type/unit:1, 1:1>>,
    encode_nxt_bmp(Types, Type, NewBMP);
encode_nxt_bmp([Type | Types], LastType, BMP) ->
    PadBy = Type - LastType - 1,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    encode_nxt_bmp(Types, Type, NewBMP).

-spec pad_bmp(bitstring()) -> bitstring().
pad_bmp(BMP) when is_binary(BMP) -> BMP;
pad_bmp(BMP) when is_bitstring(BMP) ->
    PadBy = 8 - bit_size(BMP) rem 8,
    <<BMP/binary-unit:1, 0:PadBy/unit:1>>.

%%%===================================================================
%%% EDNS data functions

-spec encode_optrrdata([dns:optrr_elem()]) -> bitstring() | {integer(), binary()}.
encode_optrrdata(Opts) when is_list(Opts) ->
    encode_optrrdata(Opts, <<>>).

-spec encode_optrrdata([dns:optrr_elem()], bitstring()) -> bitstring().
encode_optrrdata([], Bin) ->
    Bin;
encode_optrrdata([Opt | Opts], Bin) ->
    {Id, NewBin} = do_encode_optrrdata(Opt),
    Len = byte_size(NewBin),
    encode_optrrdata(Opts, <<Bin/binary, Id:16, Len:16, NewBin/binary>>).

do_encode_optrrdata(#dns_opt_llq{
    opcode = OC,
    errorcode = EC,
    id = Id,
    leaselife = Length
}) ->
    Data = <<1:16, OC:16, EC:16, Id:64, Length:32>>,
    {?DNS_EOPTCODE_LLQ, Data};
do_encode_optrrdata(#dns_opt_ul{lease = Lease}) ->
    {?DNS_EOPTCODE_UL, <<Lease:32>>};
do_encode_optrrdata(#dns_opt_nsid{data = Data}) when is_binary(Data) ->
    {?DNS_EOPTCODE_NSID, Data};
do_encode_optrrdata(#dns_opt_owner{
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
do_encode_optrrdata(#dns_opt_owner{
    seq = S,
    primary_mac = PMAC,
    wakeup_mac = WMAC,
    password = <<>>
}) when
    byte_size(PMAC) =:= 6 andalso byte_size(WMAC) =:= 6
->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary, WMAC/binary>>};
do_encode_optrrdata(#dns_opt_owner{seq = S, primary_mac = PMAC, _ = <<>>}) when
    byte_size(PMAC) =:= 6
->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary>>};
do_encode_optrrdata(
    #dns_opt_ecs{
        family = FAMILY,
        source_prefix_length = SRCPL,
        scope_prefix_length = SCOPEPL,
        address = Address
    }
) ->
    Data = <<FAMILY:16, SRCPL:8, SCOPEPL:8, Address/binary>>,
    {?DNS_EOPTCODE_ECS, Data};
do_encode_optrrdata(#dns_opt_cookie{client = <<ClientCookie:8/binary>>, server = undefined}) ->
    {?DNS_EOPTCODE_COOKIE, ClientCookie};
do_encode_optrrdata(#dns_opt_cookie{
    client = <<ClientCookie:8/binary>>, server = <<ServerCookie/binary>>
}) when
    8 =< byte_size(ServerCookie), byte_size(ServerCookie) =< 32
->
    {?DNS_EOPTCODE_COOKIE, <<ClientCookie/binary, ServerCookie/binary>>};
do_encode_optrrdata(#dns_opt_cookie{}) ->
    erlang:error(bad_cookie);
do_encode_optrrdata(#dns_opt_ede{info_code = InfoCode, extra_text = ExtraText}) when
    is_integer(InfoCode), is_binary(ExtraText)
->
    Data = <<InfoCode:16, ExtraText/binary>>,
    {?DNS_EOPTCODE_EDE, Data};
do_encode_optrrdata(#dns_opt_unknown{id = Id, bin = Data}) when
    is_integer(Id) andalso is_binary(Data)
->
    {Id, Data}.

-spec encode_dname(undefined | compmap(), non_neg_integer(), dns:dname()) ->
    {dns:dname(), undefined | compmap()}.
encode_dname(undefined, _Pos, Name) ->
    {dns_domain:to_wire(Name), undefined};
encode_dname(CompMap, Pos, Name) ->
    dns_domain:to_wire(CompMap, Pos, Name).

-spec encode_bool(boolean()) -> 0 | 1.
encode_bool(false) -> 0;
encode_bool(true) -> 1.

-spec round_pow(non_neg_integer()) -> integer().
round_pow(E) ->
    round(math:pow(10, E)).

-spec strip_leading_zeros(binary()) -> binary().
strip_leading_zeros(<<0, Rest/binary>>) ->
    strip_leading_zeros(Rest);
strip_leading_zeros(Binary) ->
    Binary.

%% Helper function to encode RSA keys for DNSKEY and CDNSKEY records
-spec encode_rsa_key(integer(), integer()) -> binary().
encode_rsa_key(E, M) ->
    MBin = strip_leading_zeros(binary:encode_unsigned(M)),
    EBin = strip_leading_zeros(binary:encode_unsigned(E)),
    ESize = byte_size(EBin),
    case ESize of
        _ when ESize =< 16#FF ->
            <<ESize:8, EBin:ESize/binary, MBin/binary>>;
        _ when ESize =< 16#FFFF ->
            <<0, ESize:16, EBin:ESize/binary, MBin/binary>>;
        _ ->
            erlang:error(badarg)
    end.

%% Helper function to encode DSA keys for DNSKEY and CDNSKEY records
-spec encode_dsa_key(list()) -> binary().
encode_dsa_key(PKM) ->
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
    <<T, Q:20/unit:8, P:M/unit:8, G:M/unit:8, Y:M/unit:8>>.

%% Encodes a character-string as in RFC1035§3.3
%%
%% `<character-string>' is a single length octet followed by that number of characters.
%% `<character-string>' is treated as binary information, and can be up to 256 characters
%% in length (including the length octet).
-spec encode_string(binary(), binary()) -> nonempty_binary().
encode_string(Bin, StringBin) when byte_size(StringBin) < 256 ->
    Size = byte_size(StringBin),
    <<Bin/binary, Size, StringBin/binary>>.

%% Encodes an array of character-strings as in RFC1035§3.3, splitting any oversized segment
%%
%% @see encode_string/2
-spec encode_text([binary()]) -> binary().
encode_text(Strings) ->
    do_encode_text(Strings, <<>>).

-spec do_encode_text([binary()], binary()) -> binary().
do_encode_text([], Bin) ->
    Bin;
do_encode_text([<<Head:255/binary, Tail/binary>> | Strings], Acc) ->
    do_encode_text([Tail | Strings], <<Acc/binary, 255, Head/binary>>);
do_encode_text([<<>> | Strings], Acc) ->
    do_encode_text(Strings, Acc);
do_encode_text([S | Strings], Acc) ->
    Size = byte_size(S),
    do_encode_text(Strings, <<Acc/binary, Size, S/binary>>).

-spec encode_svcb_svc_params(dns:svcb_svc_params()) -> binary().
encode_svcb_svc_params(SvcParams) ->
    dns_svcb_params:to_wire(SvcParams).
