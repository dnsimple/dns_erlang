-module(dns_decode).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-endif.
?MODULEDOC(false).

-include_lib("dns_erlang/include/dns.hrl").

-define(CLASS_IS_IN(T), (T =:= ?DNS_CLASS_IN orelse T =:= ?DNS_CLASS_NONE)).
-define(MAX_INT32, ((1 bsl 31) - 1)).

-export([decode/1]).
-export([
    decode_message_questions/3,
    decode_message_additional/3,
    decode_message_body/3,
    decode_rrdata/3
]).

-ifdef(TEST).
-export([
    decode_dname/2,
    decode_rrdata/4,
    decode_optrrdata/1,
    decode_svcb_svc_params/1
]).
-endif.

-compile({inline, [decode_bool/1, round_pow/1, choose_next_bin/3]}).

-spec decode(dns:message_bin()) ->
    dns:message() | {dns:decode_error(), dns:message() | undefined, binary()}.
decode(
    <<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, 0:1, AD:1, CD:1, RC:4, QC:16, ANC:16, AUC:16,
        ADC:16, Rest0/binary>> = MsgBin
) ->
    Msg0 = #dns_message{
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
    },
    maybe
        {Msg1, Rest1} ?= decode_questions(MsgBin, Rest0, Msg0),
        {Msg2, Rest2} ?= decode_answers(MsgBin, Rest1, Msg1),
        {Msg3, Rest3} ?= decode_authority(MsgBin, Rest2, Msg2),
        {Msg4, Rest4} ?= decode_additional(MsgBin, Rest3, Msg3),
        decode_finished(MsgBin, Rest4, Msg4)
    else
        Other ->
            Other
    end;
decode(<<_/binary>> = MsgBin) ->
    {formerr, undefined, MsgBin}.

-spec decode_questions(dns:message_bin(), binary(), dns:message()) ->
    {dns:message(), binary()} | {dns:decode_error(), dns:message(), binary()}.
decode_questions(MsgBin, Body, #dns_message{qc = QC} = Msg) ->
    case decode_message_questions(MsgBin, Body, QC, []) of
        {Questions, Rest} ->
            {Msg#dns_message{questions = Questions}, Rest};
        {Error, Questions, Rest} ->
            {Error, Msg#dns_message{questions = Questions}, Rest}
    end.

-spec decode_answers(dns:message_bin(), binary(), dns:message()) ->
    {dns:message(), binary()} | {dns:decode_error(), dns:message(), binary()}.
decode_answers(MsgBin, Body, #dns_message{anc = ANC} = Msg) ->
    case decode_message_body(MsgBin, Body, ANC) of
        {RR, Rest} ->
            {Msg#dns_message{answers = RR}, Rest};
        {Error, RR, Rest} ->
            {Error, Msg#dns_message{answers = RR}, Rest}
    end.

-spec decode_authority(dns:message_bin(), binary(), dns:message()) ->
    {dns:message(), binary()} | {dns:decode_error(), dns:message(), binary()}.
decode_authority(MsgBin, Body, #dns_message{auc = AUC} = Msg) ->
    case decode_message_body(MsgBin, Body, AUC) of
        {RR, Rest} ->
            {Msg#dns_message{authority = RR}, Rest};
        {Error, RR, Rest} ->
            {Error, Msg#dns_message{authority = RR}, Rest}
    end.

-spec decode_additional(dns:message_bin(), binary(), dns:message()) ->
    {dns:message(), binary()} | {dns:decode_error(), dns:message(), binary()}.
decode_additional(MsgBin, Body, #dns_message{adc = ADC} = Msg) ->
    case decode_message_additional(MsgBin, Body, ADC) of
        {RR, Rest} ->
            {Msg#dns_message{additional = RR}, Rest};
        {Error, RR, Rest} ->
            {Error, Msg#dns_message{additional = RR}, Rest}
    end.

-spec decode_finished(dns:message_bin(), binary(), dns:message()) ->
    dns:message() | {dns:decode_error(), dns:message(), binary()}.
decode_finished(_MsgBin, <<>>, #dns_message{} = Msg) ->
    Msg;
decode_finished(_MsgBin, Bin, #dns_message{} = Msg) when is_binary(Bin) ->
    {trailing_garbage, Msg, Bin}.

-spec decode_message_questions(dns:message_bin(), binary(), dns:uint16()) ->
    {dns:questions(), binary()} | {dns:decode_error(), dns:questions(), binary()}.
decode_message_questions(MsgBin, DataBin, Count) ->
    decode_message_questions(MsgBin, DataBin, Count, []).

-spec decode_message_questions(dns:message_bin(), binary(), dns:uint16(), dns:questions()) ->
    {dns:questions(), binary()} | {dns:decode_error(), dns:questions(), binary()}.
decode_message_questions(_MsgBin, DataBin, 0, RRs) ->
    {lists:reverse(RRs), DataBin};
decode_message_questions(_MsgBin, <<>>, _Count, RRs) ->
    {truncated, lists:reverse(RRs), <<>>};
decode_message_questions(MsgBin, DataBin, Count, RRs) ->
    try decode_dname(MsgBin, DataBin) of
        {Name, <<Type:16, Class:16, RB/binary>>} ->
            R = #dns_query{name = Name, type = Type, class = Class},
            decode_message_questions(MsgBin, RB, Count - 1, [R | RRs]);
        {_Name, _Bin} ->
            {truncated, lists:reverse(RRs), DataBin}
    catch
        Error when is_atom(Error) ->
            {Error, lists:reverse(RRs), DataBin};
        _:_ ->
            {formerr, lists:reverse(RRs), DataBin}
    end.

-spec decode_message_additional(dns:message_bin(), binary(), dns:uint16()) ->
    {dns:additional(), binary()} | {dns:decode_error(), [dns:optrr() | dns:rr()], binary()}.
decode_message_additional(MsgBin, DataBin, Count) when
    is_binary(MsgBin), is_binary(DataBin), is_integer(Count), 0 =< Count, Count =< 65535
->
    do_decode_message_additional(MsgBin, DataBin, Count, []).

-spec do_decode_message_additional(dns:message_bin(), binary(), integer(), dns:additional()) ->
    {dns:additional(), binary()} | {dns:decode_error(), [dns:optrr() | dns:rr()], binary()}.
do_decode_message_additional(_MsgBin, DataBin, 0, RRs) ->
    {lists:reverse(RRs), DataBin};
do_decode_message_additional(_MsgBin, <<>>, _Count, RRs) ->
    {truncated, lists:reverse(RRs), <<>>};
do_decode_message_additional(MsgBin, DataBin, Count, RRs) ->
    try decode_dname(MsgBin, DataBin) of
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
            do_decode_message_additional(MsgBin, RemBin, Count - 1, [RR | RRs]);
        {Name,
            <<Type:16/unsigned, Class:16/unsigned, TTL:32/signed, Len:16, RdataBin:Len/binary,
                RemBin/binary>>} ->
            RR = #dns_rr{
                name = Name,
                type = Type,
                class = Class,
                ttl = TTL,
                data = decode_rrdata(MsgBin, Class, Type, RdataBin)
            },
            do_decode_message_additional(MsgBin, RemBin, Count - 1, [RR | RRs]);
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

-spec decode_message_body(dns:message_bin(), binary(), dns:uint16()) ->
    {[dns:rr()], binary()} | {dns:decode_error(), [dns:rr()], binary()}.
decode_message_body(MsgBin, DataBin, Count) when
    is_binary(MsgBin), is_binary(MsgBin), is_integer(Count), 0 =< Count, Count =< 65535
->
    do_decode_message_body(MsgBin, DataBin, Count, []).

-spec do_decode_message_body(dns:message_bin(), binary(), integer(), [dns:rr()]) ->
    {[dns:rr()], binary()} | {dns:decode_error(), [dns:rr()], binary()}.
do_decode_message_body(_MsgBin, DataBin, 0, RRs) ->
    {lists:reverse(RRs), DataBin};
do_decode_message_body(_MsgBin, <<>>, _Count, RRs) ->
    {truncated, lists:reverse(RRs), <<>>};
do_decode_message_body(MsgBin, DataBin, Count, RRs) ->
    try decode_dname(MsgBin, DataBin) of
        {Name,
            <<Type:16/unsigned, Class:16/unsigned, TTL:32/signed, Len:16, RdataBin:Len/binary,
                RemBin/binary>>} ->
            RR = #dns_rr{
                name = Name,
                type = Type,
                class = Class,
                ttl = TTL,
                data = decode_rrdata(MsgBin, Class, Type, RdataBin)
            },
            do_decode_message_body(MsgBin, RemBin, Count - 1, [RR | RRs]);
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

-spec decode_dname(dns:message_bin(), nonempty_binary()) -> {dns:dname(), binary()}.
decode_dname(MsgBin, DataBin) ->
    decode_dname(MsgBin, DataBin, DataBin, <<>>, 0).

-spec decode_dname(
    dns:message_bin(), nonempty_binary(), nonempty_binary(), binary(), non_neg_integer()
) ->
    {dns:dname(), binary()}.
decode_dname(MsgBin, _DataBin, _RemBin, _DName, Count) when Count > byte_size(MsgBin) ->
    throw(decode_loop);
decode_dname(_MsgBin, <<0, DataRBin/binary>>, RBin, DName0, Count) ->
    NewRemBin = choose_next_bin(Count, DataRBin, RBin),
    NewDName =
        case DName0 of
            <<$., DName/binary>> -> DName;
            <<>> -> <<>>
        end,
    {NewDName, NewRemBin};
decode_dname(MsgBin, <<0:2, Len:6, Label0:Len/binary, DataRemBin/binary>>, RemBin, DName, Count) ->
    Label = dns:escape_label(Label0),
    NewRemBin = choose_next_bin(Count, DataRemBin, RemBin),
    NewDName = <<DName/binary, $., Label/binary>>,
    decode_dname(MsgBin, DataRemBin, NewRemBin, NewDName, Count);
decode_dname(MsgBin, <<3:2, Ptr:14, DataRBin/binary>>, RBin, DName, Count) ->
    NewRemBin = choose_next_bin(Count, DataRBin, RBin),
    NewCount = Count + 2,
    case MsgBin of
        <<_:Ptr/binary, NewDataBin/binary>> ->
            decode_dname(MsgBin, NewDataBin, NewRemBin, DName, NewCount);
        _ ->
            throw(bad_pointer)
    end.

choose_next_bin(0, DataRBin, _RBin) ->
    DataRBin;
choose_next_bin(_, _DataRBin, RBin) ->
    RBin.

-spec decode_optrrdata(binary()) -> [dns:optrr_elem()].
decode_optrrdata(Bin) ->
    decode_optrrdata(Bin, []).

-spec decode_optrrdata(binary(), [dns:optrr_elem()]) -> [dns:optrr_elem()].
decode_optrrdata(<<>>, Opts) ->
    lists:reverse(Opts);
decode_optrrdata(<<EOptNum:16, EOptLen:16, EOptBin:EOptLen/binary, Rest/binary>>, Opts) ->
    NewOpt = do_decode_optrrdata(EOptNum, EOptBin),
    decode_optrrdata(Rest, [NewOpt | Opts]).

-spec do_decode_optrrdata(dns:uint16(), binary()) -> dns:optrr_elem().
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
do_decode_optrrdata(?DNS_EOPTCODE_COOKIE, <<ClientCookie:8/binary>>) ->
    #dns_opt_cookie{client = ClientCookie};
do_decode_optrrdata(?DNS_EOPTCODE_COOKIE, <<ClientCookie:8/binary, ServerCookie/binary>>) when
    8 =< byte_size(ServerCookie), byte_size(ServerCookie) =< 32
->
    #dns_opt_cookie{client = ClientCookie, server = ServerCookie};
do_decode_optrrdata(?DNS_EOPTCODE_COOKIE, _) ->
    erlang:error(bad_cookie);
do_decode_optrrdata(?DNS_EOPTCODE_EDE, <<InfoCode:16, ExtraText/binary>>) ->
    #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText};
do_decode_optrrdata(?DNS_EOPTCODE_EDE, <<>>) ->
    #dns_opt_ede{info_code = 0, extra_text = <<>>};
do_decode_optrrdata(EOpt, <<Bin/binary>>) ->
    #dns_opt_unknown{id = EOpt, bin = Bin}.

-spec decode_rrdata(dns:message_bin(), dns:uint16(), dns:uint16()) -> dns:rrdata().
decode_rrdata(MsgBin, Class, Type) ->
    decode_rrdata(MsgBin, Class, Type, MsgBin).

-spec decode_rrdata(dns:message_bin(), dns:uint16(), dns:uint16(), binary()) -> dns:rrdata().
decode_rrdata(_MsgBin, _Class, _Type, <<>>) ->
    <<>>;
decode_rrdata(_MsgBin, Class, ?DNS_TYPE_A, <<A, B, C, D>>) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_a{ip = {A, B, C, D}};
decode_rrdata(
    _MsgBin, Class, ?DNS_TYPE_AAAA, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_aaaa{ip = {A, B, C, D, E, F, G, H}};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_AFSDB, <<Subtype:16, Bin/binary>>) ->
    #dns_rrdata_afsdb{
        subtype = Subtype,
        hostname = decode_dnameonly(MsgBin, Bin)
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_CAA, <<Flags:8, Len:8, Bin/binary>>) ->
    <<Tag:Len/binary, Value/binary>> = Bin,
    #dns_rrdata_caa{flags = Flags, tag = Tag, value = Value};
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_CERT, <<Type:16, KeyTag:16, Alg, Bin/binary>>) ->
    #dns_rrdata_cert{type = Type, keytag = KeyTag, alg = Alg, cert = Bin};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_CNAME, Bin) ->
    #dns_rrdata_cname{dname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(_MsgBin, Class, ?DNS_TYPE_DHCID, Bin) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_dhcid{data = Bin};
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_DLV, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>) ->
    #dns_rrdata_dlv{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_DNAME, Bin) ->
    #dns_rrdata_dname{dname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(
    _MsgBin, _Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) when
    AlgNum =:= ?DNS_ALG_RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_RSASHA256 orelse
        AlgNum =:= ?DNS_ALG_RSASHA512
->
    {Key, KeyTag} = decode_rsa_key(PublicKey, Bin),
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        keytag = KeyTag
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_DNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, T, Q:20/unit:8, KeyBin/binary>> = Bin
) when
    (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA) andalso
        T =< 8
->
    {Key, KeyTag} = decode_dsa_key(T, Q, KeyBin, Bin),
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        keytag = KeyTag
    };
decode_rrdata(
    _MsgBin, _Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) when
    (AlgNum =:= ?DNS_ALG_ECDSAP256SHA256 andalso 64 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ECDSAP384SHA384 andalso 96 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ED25519 andalso 32 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ED448 andalso 57 =:= byte_size(PublicKey))
->
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        keytag = bin_to_key_tag(Bin)
    };
decode_rrdata(
    _MsgBin, _Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) ->
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        keytag = bin_to_key_tag(Bin)
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_CDNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) when
    AlgNum =:= ?DNS_ALG_RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        AlgNum =:= ?DNS_ALG_RSASHA256 orelse
        AlgNum =:= ?DNS_ALG_RSASHA512
->
    {Key, KeyTag} = decode_rsa_key(PublicKey, Bin),
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        keytag = KeyTag
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_CDNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, T, Q:20/unit:8, KeyBin/binary>> = Bin
) when
    (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA) andalso
        T =< 8
->
    {Key, KeyTag} = decode_dsa_key(T, Q, KeyBin, Bin),
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = Key,
        keytag = KeyTag
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_CDNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) when
    (AlgNum =:= ?DNS_ALG_ECDSAP256SHA256 andalso 64 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ECDSAP384SHA384 andalso 96 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ED25519 andalso 32 =:= byte_size(PublicKey)) orelse
        (AlgNum =:= ?DNS_ALG_ED448 andalso 57 =:= byte_size(PublicKey))
->
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        keytag = bin_to_key_tag(Bin)
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_CDNSKEY,
    <<Flags:16, Protocol:8, AlgNum:8, PublicKey/binary>> = Bin
) ->
    #dns_rrdata_cdnskey{
        flags = Flags,
        protocol = Protocol,
        alg = AlgNum,
        public_key = PublicKey,
        keytag = bin_to_key_tag(Bin)
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_DS, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>) ->
    #dns_rrdata_ds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_CDS, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>) ->
    #dns_rrdata_cds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_ZONEMD, <<Serial:32, Scheme:8, Alg:8, Hash/binary>>) ->
    #dns_rrdata_zonemd{
        serial = Serial,
        scheme = Scheme,
        algorithm = Alg,
        hash = Hash
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_HINFO, Bin) ->
    [CPU, OS] = decode_text(Bin),
    #dns_rrdata_hinfo{cpu = CPU, os = OS};
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_IPSECKEY,
    <<Precedence:8, 0:8, Algorithm:8, PublicKey/binary>>
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = <<>>,
        public_key = PublicKey
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_IPSECKEY,
    <<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8, PublicKey/binary>>
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D},
        public_key = PublicKey
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_IPSECKEY,
    <<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
        PublicKey/binary>>
) ->
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = {A, B, C, D, E, F, G, H},
        public_key = PublicKey
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_IPSECKEY, <<Precedence:8, 3:8, Algorithm:8, Bin/binary>>) ->
    {Gateway, PublicKey} = decode_dname(MsgBin, Bin),
    #dns_rrdata_ipseckey{
        precedence = Precedence,
        alg = Algorithm,
        gateway = Gateway,
        public_key = PublicKey
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_KEY,
    <<Type:2, 0:1, XT:1, 0:2, NamType:2, 0:4, Sig:4, Protocol:8, Alg:8, PublicKey/binary>>
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
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_KX, <<Preference:16, Bin/binary>>) ->
    #dns_rrdata_kx{
        preference = Preference,
        exchange = decode_dnameonly(MsgBin, Bin)
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_LOC,
    <<0:8, SizeB:4, SizeE:4, HorizB:4, HorizE:4, VertB:4, VertE:4, LatPre:32, LonPre:32, AltPre:32>>
) when SizeE < 10 andalso HorizE < 10 andalso VertE < 10 ->
    #dns_rrdata_loc{
        size = SizeB * (round_pow(SizeE)),
        horiz = HorizB * (round_pow(HorizE)),
        vert = VertB * (round_pow(VertE)),
        lat = decode_loc_point(LatPre),
        lon = decode_loc_point(LonPre),
        alt = AltPre - 10000000
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_MB, Bin) ->
    #dns_rrdata_mb{madname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_MG, Bin) ->
    #dns_rrdata_mg{madname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_MINFO, Bin) when is_binary(Bin) ->
    {RMB, EMB} = decode_dname(Bin, MsgBin),
    #dns_rrdata_minfo{rmailbx = RMB, emailbx = decode_dnameonly(MsgBin, EMB)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_MR, Bin) ->
    #dns_rrdata_mr{newname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_MX, <<Preference:16, Bin/binary>>) ->
    #dns_rrdata_mx{
        preference = Preference,
        exchange = decode_dnameonly(MsgBin, Bin)
    };
decode_rrdata(
    MsgBin,
    _Class,
    ?DNS_TYPE_NAPTR,
    <<Order:16, Preference:16, Bin/binary>>
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
        replacement = decode_dnameonly(MsgBin, Bin3)
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_NS, Bin) ->
    #dns_rrdata_ns{dname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_NSEC, Bin) ->
    {NextDName, TypeBMP} = decode_dname(MsgBin, Bin),
    Types = decode_nsec_types(TypeBMP),
    #dns_rrdata_nsec{next_dname = NextDName, types = Types};
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_NSEC3,
    <<HashAlg:8, _FlagsZ:7, OptOut:1, Iterations:16, SaltLen:8/unsigned, Salt:SaltLen/binary-unit:8,
        HashLen:8/unsigned, Hash:HashLen/binary-unit:8, TypeBMP/binary>>
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
    _MsgBin,
    _Class,
    ?DNS_TYPE_NSEC3PARAM,
    <<Alg:8, Flags:8, Iterations:16, SaltLen:8, Salt:SaltLen/binary>>
) ->
    #dns_rrdata_nsec3param{
        hash_alg = Alg,
        flags = Flags,
        iterations = Iterations,
        salt = Salt
    };
decode_rrdata(
    _MsgBin, _Class, ?DNS_TYPE_TLSA, <<Usage:8, Selector:8, MatchingType:8, Certificate/binary>>
) ->
    #dns_rrdata_tlsa{
        usage = Usage,
        selector = Selector,
        matching_type = MatchingType,
        certificate = Certificate
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_NXT, Bin) ->
    {NxtDName, BMP} = decode_dname(MsgBin, Bin),
    #dns_rrdata_nxt{dname = NxtDName, types = decode_nxt_bmp(BMP)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_PTR, Bin) ->
    #dns_rrdata_ptr{dname = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_RP, Bin) ->
    {Mbox, TxtBin} = decode_dname(MsgBin, Bin),
    #dns_rrdata_rp{mbox = Mbox, txt = decode_dnameonly(MsgBin, TxtBin)};
decode_rrdata(
    MsgBin,
    _Class,
    ?DNS_TYPE_RRSIG,
    <<Type:16, Alg:8, Labels:8, TTL:32, Expire:32, Inception:32, KeyTag:16, Bin/binary>>
) ->
    {SigName, Sig} = decode_dname(MsgBin, Bin),
    #dns_rrdata_rrsig{
        type_covered = Type,
        alg = Alg,
        labels = Labels,
        original_ttl = TTL,
        expiration = Expire,
        inception = Inception,
        keytag = KeyTag,
        signers_name = SigName,
        signature = Sig
    };
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_RT, <<Pref:16, Bin/binary>>) ->
    #dns_rrdata_rt{preference = Pref, host = decode_dnameonly(MsgBin, Bin)};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_SOA, Bin) ->
    {MName, RNBin} = decode_dname(MsgBin, Bin),
    {RName, Rest} = decode_dname(MsgBin, RNBin),
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
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_SPF, Bin) ->
    #dns_rrdata_spf{spf = decode_text(Bin)};
decode_rrdata(
    MsgBin,
    _Class,
    ?DNS_TYPE_SRV,
    <<Pri:16, Wght:16, Port:16, Bin/binary>>
) ->
    #dns_rrdata_srv{
        priority = Pri,
        weight = Wght,
        port = Port,
        target = decode_dnameonly(MsgBin, Bin)
    };
decode_rrdata(
    _MsgBin,
    _Class,
    ?DNS_TYPE_SSHFP,
    <<Alg:8, FPType:8, FingerPrint/binary>>
) ->
    #dns_rrdata_sshfp{alg = Alg, fp_type = FPType, fp = FingerPrint};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_SVCB, <<SvcPriority:16, Bin/binary>>) ->
    {TargetName, SvcParamsBin} = decode_dname(MsgBin, Bin),
    SvcParams = decode_svcb_svc_params(SvcParamsBin),
    #dns_rrdata_svcb{svc_priority = SvcPriority, target_name = TargetName, svc_params = SvcParams};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_HTTPS, <<SvcPriority:16, Bin/binary>>) ->
    {TargetName, SvcParamsBin} = decode_dname(MsgBin, Bin),
    SvcParams = decode_svcb_svc_params(SvcParamsBin),
    #dns_rrdata_https{svc_priority = SvcPriority, target_name = TargetName, svc_params = SvcParams};
decode_rrdata(MsgBin, _Class, ?DNS_TYPE_TSIG, Bin) ->
    {Alg,
        <<Time:48, Fudge:16, MS:16, MAC:MS/bytes, MsgId:16, ErrInt:16, OtherLen:16,
            Other:OtherLen/binary>>} = decode_dname(MsgBin, Bin),
    #dns_rrdata_tsig{
        alg = Alg,
        time = Time,
        fudge = Fudge,
        mac = MAC,
        msgid = MsgId,
        err = ErrInt,
        other = Other
    };
decode_rrdata(_MsgBin, _Class, ?DNS_TYPE_TXT, Bin) ->
    #dns_rrdata_txt{txt = decode_text(Bin)};
decode_rrdata(_MsgBin, _Class, _Type, Bin) ->
    Bin.

-spec decode_dnameonly(dns:message_bin(), nonempty_binary()) -> binary().
decode_dnameonly(MsgBin, Bin) ->
    case decode_dname(MsgBin, Bin) of
        {DName, <<>>} -> DName;
        _ -> throw(trailing_garbage)
    end.

%% Helper function to decode RSA keys for DNSKEY and CDNSKEY records
-spec decode_rsa_key(binary(), binary()) -> {list(), dns:uint16()}.
decode_rsa_key(PublicKey, Bin) ->
    Key =
        case PublicKey of
            <<0, Len:16, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)];
            <<Len:8, Exp:Len/unit:8, ModBin/binary>> ->
                [Exp, binary:decode_unsigned(ModBin)]
        end,
    KeyTag = bin_to_key_tag(Bin),
    {Key, KeyTag}.

%% Helper function to decode DSA keys for DNSKEY and CDNSKEY records
-spec decode_dsa_key(byte(), non_neg_integer(), binary(), binary()) -> {list(), dns:uint16()}.
decode_dsa_key(T, Q, KeyBin, Bin) ->
    S = 64 + T * 8,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = KeyBin,
    Key = [P, Q, G, Y],
    KeyTag = bin_to_key_tag(Bin),
    {Key, KeyTag}.

-spec decode_text(binary()) -> [binary()].
decode_text(<<>>) ->
    [];
decode_text(Bin) when is_binary(Bin) ->
    {RB, String} = decode_string(Bin),
    [String | decode_text(RB)].

-spec decode_string(nonempty_binary()) -> {binary(), binary()}.
decode_string(<<Len, Bin:Len/binary, Rest/binary>>) ->
    {Rest, Bin}.

-spec bin_to_key_tag(<<_:32, _:_*8>>) -> dns:uint16().
bin_to_key_tag(Binary) when is_binary(Binary) ->
    do_bin_to_key_tag(Binary, 0).

-spec do_bin_to_key_tag(binary(), non_neg_integer()) -> dns:uint16().
do_bin_to_key_tag(<<>>, AC) ->
    (AC + ((AC bsr 16) band 16#FFFF)) band 16#FFFF;
do_bin_to_key_tag(<<X:16, Rest/binary>>, AC) ->
    do_bin_to_key_tag(Rest, AC + X);
do_bin_to_key_tag(<<X:8>>, AC) ->
    do_bin_to_key_tag(<<>>, AC + (X bsl 8)).

-spec decode_loc_point(non_neg_integer()) -> dns:uint32().
decode_loc_point(P) when is_integer(P), P > ?MAX_INT32 ->
    P - ?MAX_INT32;
decode_loc_point(P) when is_integer(P), P =< ?MAX_INT32 ->
    -(?MAX_INT32 - P).

-spec decode_nsec_types(binary()) -> [non_neg_integer()].
decode_nsec_types(Bin) ->
    do_decode_nsec_types(Bin, []).

-spec do_decode_nsec_types(binary(), [non_neg_integer()]) -> [non_neg_integer()].
do_decode_nsec_types(<<>>, Types) ->
    lists:reverse(Types);
do_decode_nsec_types(<<WindowNum:8, BMPLength:8, BMP:BMPLength/binary, Rest/binary>>, Types) ->
    BaseNo = WindowNum * 256,
    NewTypes = do_decode_nsec_types(BMP, BaseNo, Types),
    do_decode_nsec_types(Rest, NewTypes).

-spec do_decode_nsec_types(bitstring(), non_neg_integer(), [non_neg_integer()]) ->
    [non_neg_integer()].
do_decode_nsec_types(<<>>, _Num, Types) ->
    Types;
do_decode_nsec_types(<<0:1, Rest/bitstring>>, Num, Types) ->
    do_decode_nsec_types(Rest, Num + 1, Types);
do_decode_nsec_types(<<1:1, Rest/bitstring>>, Num, Types) ->
    do_decode_nsec_types(Rest, Num + 1, [Num | Types]).

-spec decode_nxt_bmp(bitstring()) -> [non_neg_integer()].
decode_nxt_bmp(BMP) ->
    do_decode_nxt_bmp(BMP, 0, []).

-spec do_decode_nxt_bmp(bitstring(), non_neg_integer(), [non_neg_integer()]) -> [non_neg_integer()].
do_decode_nxt_bmp(<<>>, _Offset, Types) ->
    lists:reverse(Types);
do_decode_nxt_bmp(<<1:1, Rest/bitstring>>, Offset, Types) ->
    do_decode_nxt_bmp(Rest, Offset + 1, [Offset | Types]);
do_decode_nxt_bmp(<<0:1, Rest/bitstring>>, Offset, Types) ->
    do_decode_nxt_bmp(Rest, Offset + 1, Types).

-spec decode_svcb_svc_params(binary()) -> dns:svcb_svc_params().
decode_svcb_svc_params(Bin) ->
    decode_svcb_svc_params(Bin, #{}).

-spec decode_svcb_svc_params(binary(), dns:svcb_svc_params()) -> dns:svcb_svc_params().
decode_svcb_svc_params(<<>>, SvcParams) ->
    SvcParams;
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_MANDATORY:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    Value = [K || <<K:16>> <= ValueBin],
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_MANDATORY => Value});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_ALPN:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    Value = decode_svcb_svc_params_value(?DNS_SVCB_PARAM_ALPN, ValueBin),
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_ALPN => Value});
decode_svcb_svc_params(<<?DNS_SVCB_PARAM_NO_DEFAULT_ALPN:16, 0:16, Rest/binary>>, SvcParams) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_PORT:16, 2:16, Port:16/integer, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_PORT => Port});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_ECHCONFIG:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_ECHCONFIG => ValueBin});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_IPV4HINT:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    Value = decode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV4HINT, ValueBin),
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_IPV4HINT => Value});
decode_svcb_svc_params(
    <<?DNS_SVCB_PARAM_IPV6HINT:16, Len:16, ValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    Value = decode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV6HINT, ValueBin),
    decode_svcb_svc_params(Rest, SvcParams#{?DNS_SVCB_PARAM_IPV6HINT => Value});
decode_svcb_svc_params(
    <<UnknownKey:16, Len:16, UnknownValueBin:Len/binary, Rest/binary>>, SvcParams
) ->
    decode_svcb_svc_params(Rest, SvcParams#{UnknownKey => UnknownValueBin}).

decode_svcb_svc_params_value(?DNS_SVCB_PARAM_ALPN, Bin) ->
    decode_alpn_list(Bin);
decode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV4HINT, Bin) ->
    [{A, B, C, D} || <<A, B, C, D>> <= Bin];
decode_svcb_svc_params_value(?DNS_SVCB_PARAM_IPV6HINT, Bin) ->
    [{A, B, C, D, E, F, G, H} || <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> <= Bin].

decode_alpn_list(<<Len:8, Str:Len/binary, Rest/binary>>) ->
    [Str | decode_alpn_list(Rest)];
decode_alpn_list(<<>>) ->
    [].

-spec decode_bool(0 | 1) -> boolean().
decode_bool(0) -> false;
decode_bool(1) -> true.

-spec round_pow(non_neg_integer()) -> integer().
round_pow(E) ->
    round(math:pow(10, E)).
