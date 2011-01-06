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
%% @headerfile "dns_records.hrl"
-module(dns).

-compile({inline, [term_or_arg/2, int_or_badarg/2]}).

-export([decode_message/1, encode_message/1]).
-export([verify_tsig/3, verify_tsig/4]).
-export([add_tsig/5, add_tsig/6]).

-export([compare_dname/2]).
-export([dname_to_upper/1, dname_to_lower/1]).
-export([dname_to_labels/1]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-export([class_to_atom/1, class_to_int/1]).
-export([type_to_atom/1, type_to_int/1]).
-export([rcode_to_atom/1, rcode_to_int/1]).
-export([opcode_to_atom/1, opcode_to_int/1]).
-export([tsigerr_to_atom/1, tsigerr_to_int/1]).
-export([ercode_to_atom/1, ercode_to_int/1]).
-export([eoptcode_to_atom/1, eoptcode_to_int/1]).
-export([llqopcode_to_atom/1, llqopcode_to_int/1]).
-export([llqerrcode_to_atom/1, llqerrcode_to_int/1]).
-export([alg_to_atom/1, alg_to_int/1]).

-export([const_compare/2]).

-include("dns.hrl").
-include("dns_tests.hrl").

-define(DEFAULT_TSIG_FUDGE, 5 * 60).

%%%===================================================================
%%% Message body functions
%%%===================================================================

%% @doc Decode a binary DNS message.
%% @spec decode_message(MsgBin :: binary()) -> dns_message()
%% @throws bad_pointer | decode_loop | formerr | trailing_garbage
decode_message(<<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, 0:1, AD:1, CD:1,
		 RC:4, QC:16, ANC:16, AUC:16, ADC:16, HRB/binary>> = MsgBin) ->
    {Questions, QRB} = decode_message_questions(HRB, QC, MsgBin),
    {Answers, AnRB} = decode_message_body(QRB, ANC, MsgBin),
    {Authority, AuRB} = decode_message_body(AnRB, AUC, MsgBin),
    {Additional, AdRB} = decode_message_body(AuRB, ADC, MsgBin),
    case AdRB of
	<<>> ->
	    #dns_message{id = Id,
			 qr = decode_bool(QR),
			 oc = term_or_arg(fun opcode_to_atom/1, OC),
			 aa = decode_bool(AA),
			 tc = decode_bool(TC),
			 rd = decode_bool(RD),
			 ra = decode_bool(RA),
			 ad = decode_bool(AD),
			 cd = decode_bool(CD),
			 rc = term_or_arg(fun rcode_to_atom/1, RC),
			 qc = QC,
			 anc = ANC,
			 auc = AUC,
			 adc = ADC, questions = Questions, answers = Answers,
			 authority = Authority, additional = Additional};
	_ -> throw(trailing_garbage)
    end.

decode_message_questions(DataBin, Count, MsgBin) ->
    decode_message_questions(DataBin, Count, MsgBin, []).

decode_message_questions(<<>>, _Count, _MsgBin, Qs) ->
    {lists:reverse(Qs), <<>>};
decode_message_questions(DataBin, 0, _MsgBin, Qs) ->
    {lists:reverse(Qs), DataBin};
decode_message_questions(DataBin, Count, MsgBin, Qs) ->
    {Name, <<TypeN:16, ClassN:16, RB/binary>>} = decode_dname(DataBin, MsgBin),
    Type = term_or_arg(fun type_to_atom/1, TypeN),
    Class = term_or_arg(fun class_to_atom/1, ClassN),
    Q = #dns_query{name = Name, type = Type, class = Class},
    decode_message_questions(RB, Count - 1, MsgBin, [Q|Qs]).

decode_message_body(DataBin, Count, MsgBin) ->
    decode_message_body(DataBin, Count, MsgBin, []).

decode_message_body(<<>>, _Count, _MsgBin, RRs) ->
    {lists:reverse(RRs), <<>>};
decode_message_body(DataBin, 0, _MsgBin, RRs) ->
    {lists:reverse(RRs), DataBin};
decode_message_body(DataBin, Count, MsgBin, RRs) ->
    case decode_dname(DataBin, MsgBin) of
	{<<>>, <<?DNS_TYPE_OPT:16/unsigned, UPS:16/unsigned, ExtRcode:8,
		 Version:8, DNSSEC:1, _Z:15, EDataLen:16,
		 EDataBin:EDataLen/binary, RemBin/binary>>} ->
	    Data = decode_optrrdata(EDataBin),
	    RR = #dns_optrr{udp_payload_size = UPS,
			    ext_rcode = ExtRcode,
			    version = Version,
			    dnssec = decode_bool(DNSSEC),
			    data = Data},
	    decode_message_body(RemBin, Count - 1, MsgBin, [RR|RRs]);
	{Name, <<TypeN:16/unsigned, ClassN:16/unsigned, TTL:32/signed, Len:16,
		 RdataBin:Len/binary, RemBin/binary>>} ->
	    Class = term_or_arg(fun class_to_atom/1, ClassN),
	    Type = term_or_arg(fun type_to_atom/1, TypeN),
	    RR = #dns_rr{name = Name,
			 type = Type,
			 class = Class,
			 ttl = TTL,
			 data = decode_rrdata(Class, Type, RdataBin, MsgBin)},
	    decode_message_body(RemBin, Count - 1, MsgBin, [RR|RRs]);
	_ -> throw(formerr)
    end.

%% @doc Encode a dns_message record.
%% @spec encode_message(dns_message()) -> MsgBin
encode_message(#dns_message{id = Id, qr = QR, oc = OC, aa = AA, tc = TC,
			    rd = RD, ra = RA, ad = AD, cd = CD, rc = RC,
			    qc = QC, anc = ANC, auc = AUC, adc = ADC,
			    questions = Questions, answers = Answers,
			    authority = Authority, additional = Additional}) ->
    OCInt = int_or_badarg(fun opcode_to_int/1, OC),
    RCInt = int_or_badarg(fun rcode_to_int/1, RC),
    QRInt = encode_bool(QR),
    AAInt = encode_bool(AA),
    TCInt = encode_bool(TC),
    RDInt = encode_bool(RD),
    RAInt = encode_bool(RA),
    ADInt = encode_bool(AD),
    CDInt = encode_bool(CD),
    BinH = <<Id:16, QRInt:1, OCInt:4, AAInt:1, TCInt:1, RDInt:1, RAInt:1, 0:1,
	     ADInt:1, CDInt:1, RCInt:4, QC:16, ANC:16, AUC:16, ADC:16>>,
    NewCompMap = gb_trees:empty(),
    {QBin, CompMapQ} = encode_message_questions(BinH, NewCompMap, Questions),
    {AnBin, CompMapAn} = encode_message_body(QBin, CompMapQ, Answers),
    {AuBin, CompMapAU} = encode_message_body(AnBin, CompMapAn, Authority),
    {Bin, _CompMap} = encode_message_body(AuBin, CompMapAU, Additional),
    Bin.

encode_message_questions(Bin, CompMap, []) -> {Bin, CompMap};
encode_message_questions(Bin, CompMap, [#dns_query{name = Name,
						   type = Type,
						   class = Class}|Questions]) ->
    {NameBin, NewCompMap} = encode_dname(Bin, CompMap, byte_size(Bin), Name),
    TypeInt = int_or_badarg(fun type_to_int/1, Type),
    ClassInt = int_or_badarg(fun class_to_int/1, Class),
    NewBin = <<NameBin/binary, TypeInt:16, ClassInt:16>>,
    encode_message_questions(NewBin, NewCompMap, Questions).

encode_message_body(Bin, CompMap, []) -> {Bin, CompMap};
encode_message_body(Bin, CompMap, [#dns_rr{name = Name,
					   type = Type,
					   class = Class,
					   ttl = TTL,
					   data = Data}|Records]) ->
    IntType = int_or_badarg(fun type_to_int/1, Type),
    IntClass = int_or_badarg(fun class_to_int/1, Class),
    {NameBin, NameCompMap} = encode_dname(CompMap, byte_size(Bin), Name),
    RRBinOffset = byte_size(Bin) + byte_size(NameBin) + 2 + 2 + 32 + 2,
    {RRBin, NewCompMap} = encode_rrdata(RRBinOffset, Class, Data, NameCompMap),
    RRBinSize = byte_size(RRBin),
    NewBin = <<Bin/binary, NameBin/binary, IntType:16, IntClass:16, TTL:32,
	       RRBinSize:16, RRBin/binary>>,
    encode_message_body(NewBin, NewCompMap, Records);    
encode_message_body(Bin, CompMap, [#dns_optrr{udp_payload_size = UPS,
					      ext_rcode = ExtRcode,
					      version = Version,
					      dnssec = DNSSEC,
					      data = Data}|Records]) ->
    IntClass = UPS,
    DNSSECBit = encode_bool(DNSSEC),
    RRBin = encode_optrrdata(Data),
    RRBinSize = byte_size(RRBin),
    NewBin = <<Bin/binary, 0, 41:16, IntClass:16, ExtRcode:8, Version:8,
	       DNSSECBit:1, 0:15, RRBinSize:16, RRBin/binary>>,
    encode_message_body(NewBin, CompMap, Records).

%% @doc Returns a random integer suitable for use as DNS message identifier.
%% @spec random_id() -> integer()
random_id() -> crypto:rand_uniform(0, 65535).

%%%===================================================================
%%% TSIG functions
%%%===================================================================

%% @spec verify_tsig(binary(), dname(), binary()) ->
%%       {ok, MAC :: binary()} |
%%       {ok, bad_time | bad_sig | bad_key} |
%%       {error, term()}
%% @equiv verify_tsig(MsgBin, Name, Secret, [])
%% @throws bad_pointer | decode_loop | formerr | trailing_garbage | no_tsig
verify_tsig(MsgBin, Name, Secret) ->
    verify_tsig(MsgBin, Name, Secret, []).

%% @doc Verifies a TSIG message signature.
%% @spec verify_tsig(binary(), dname(), binary(), [tsig_option()]) ->
%%       {ok, MAC :: binary()} |
%%       {ok, bad_time | bad_sig | bad_key} |
%%       {error, term()}
%% @throws bad_pointer | decode_loop | formerr | trailing_garbage | no_tsig
%% @type tsig_option() = {time, unix_time()} | {fudge, integer()} |
%%                       {mac, binary()} | {other, binary()}
verify_tsig(MsgBin, Name, Secret, Options) ->
    Now = proplists:get_value(time, Options, unix_time()),
    Fudge = proplists:get_value(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    PreviousMAC = proplists:get_value(mac, Options, <<>>),
    {UnsignedMsgBin, #dns_rr{name = TName, data = TData}} = strip_tsig(MsgBin),
    case compare_dname(Name, TName) of
	true ->
	    #dns_rrdata_tsig{alg = Alg, time = Time, fudge = CFudge, mac = CMAC,
			     err = Err, other = Other} = TData,
	    case gen_tsig_mac(Alg, UnsignedMsgBin, Name, Secret, Time, CFudge,
			      Err, Other, PreviousMAC) of
		{ok, SMAC} ->
		    case const_compare(CMAC, SMAC) of
			true ->
			    if Now < (Time - Fudge) -> {ok, bad_time};
			       Now > (Time + Fudge) -> {ok, bad_time};
			       true -> {ok, SMAC}
			    end;
			false -> {ok, bad_sig}
		    end;
		{error, Error} -> {error, Error}
	    end;
	false -> {ok, bad_key}
    end.

%% @doc Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
%% @spec add_tsig(Msg, Algorithim, Name, Secret, ErrCode) -> SignedMsg
%% @equiv add_tsig(Msg, Alg, Name, Secret, ErrCode, [])
add_tsig(Msg, Alg, Name, Secret, ErrCode) ->
    add_tsig(Msg, Alg, Name, Secret, ErrCode, []).

%% @doc Generates and then appends a TSIG RR to a message.
%%      Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
%% @spec add_tsig(Msg, Algorithim, Name, Secret, ErrCode, [tsig_option()]) -> SignedMsg
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    MsgId = Msg#dns_message.id,
    MsgBin = encode_message(Msg),
    Time = proplists:get_value(time, Options, unix_time()),
    Fudge = proplists:get_value(fudge, Options, ?DEFAULT_TSIG_FUDGE),
    PreviousMAC = proplists:get_value(mac, Options, <<>>),
    Other = proplists:get_value(other, Options, <<>>),
    {ok, MAC} = gen_tsig_mac(Alg, MsgBin, Name, Secret, Time, Fudge, ErrCode,
			     Other, PreviousMAC),
    Data = #dns_rrdata_tsig{msgid = MsgId, alg = Alg, time = Time,
			    fudge = Fudge, mac = MAC, err = ErrCode,
			    other = Other},
    RR = #dns_rr{name = Name, class = any, type = tsig, ttl = 0, data = Data},
    NewAdditional = Msg#dns_message.additional ++ [RR],
    NewADC = Msg#dns_message.adc + 1,
    Msg#dns_message{adc = NewADC, additional = NewAdditional}.
    

strip_tsig(<<_Id:16, _QR:1, _OC:4, _AA:1, _TC:1, _RD:1, _RA:1, _PR:1, _Z:2,
	     _RC:4, _QC:16, _ANC:16, _AUC:16, ADC:16, _HRB/binary>>)
  when ADC =:= 0 -> throw(no_tsig);
strip_tsig(<<_Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, PR:1, Z:2, RC:4, QC:16,
	ANC:16, AUC:16, ADC:16, HRB/binary>> = MsgBin) ->
    UnsignedADC = ADC - 1,
    {_Questions, QRB} = decode_message_questions(HRB, QC, MsgBin),
    {_Answers, TSIGBin} = decode_message_body(QRB, ANC + AUC + UnsignedADC, MsgBin),
    case decode_message_body(TSIGBin, 1, MsgBin) of
	{[#dns_rr{data = #dns_rrdata_tsig{msgid = NewId}} = TSIG_RR], <<>>} ->
	    MsgBodyLen = byte_size(HRB) - byte_size(TSIGBin),
	    {UnsignedBodyBin, TSIGBin} = split_binary(HRB, MsgBodyLen),
	    UnsignedMsgBin = <<NewId:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1,
			       PR:1, Z:2, RC:4, QC:16, ANC:16, AUC:16,
			       UnsignedADC:16, UnsignedBodyBin/binary>>,
	    {UnsignedMsgBin, TSIG_RR};
	{[#dns_rr{data = #dns_rrdata_tsig{}}], _} -> throw(trailing_garbage);
	_ -> throw(no_tsig)
    end.

gen_tsig_mac(Alg, MsgBin, Name, Secret, Time, Fudge, ErrorCode, Other, PMAC) ->
    ErrorCodeInt = encode_tsigerr(ErrorCode),
    NameBin = encode_dname(dname_to_lower(Name)),
    AlgBin = encode_dname(dname_to_lower(Alg)),
    OtherLen = byte_size(Other),
    Base = case PMAC of
	       <<>> -> <<>>;
	       PMAC -> 
		   PMACLen = byte_size(PMAC),
		   <<PMACLen:16, PMAC/binary>>
	   end,
    MACData = [Base, MsgBin, NameBin, <<?DNS_CLASS_ANY:16>>, <<0:32>>, AlgBin,
	       <<Time:48>>, <<Fudge:16>>, <<ErrorCodeInt:16>>, <<OtherLen:16>>,
	       Other],
    case dname_to_lower(iolist_to_binary(Alg)) of
	?DNS_TSIG_ALG_MD5 -> {ok, crypto:md5_mac(Secret, MACData)};
	?DNS_TSIG_ALG_SHA1 -> {ok, crypto:sha_mac(Secret, MACData)};
	?DNS_TSIG_ALG_SHA224 -> {ok, sha2:hmac_sha224(Secret, MACData)};
	?DNS_TSIG_ALG_SHA256 -> {ok, sha2:hmac_sha256(Secret, MACData)};
	?DNS_TSIG_ALG_SHA384 -> {ok, sha2:hmac_sha384(Secret, MACData)};
	?DNS_TSIG_ALG_SHA512 -> {ok, sha2:hmac_sha512(Secret, MACData)};
	_ -> {error, bad_alg}
    end.

%%%===================================================================
%%% Record data functions
%%%===================================================================

-define(CLASS_IS_IN(Term), (Term =:= in orelse Term =:= none)).

decode_rrdata(Class, a, <<A, B, C, D>>, _MsgBin) when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    #dns_rrdata_a{ip = list_to_binary(IP)};
decode_rrdata(Class, aaaa, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>, _MsgBin)
  when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D,E,F,G,H}),
    #dns_rrdata_aaaa{ip = list_to_binary(IP)};
decode_rrdata(_Class, afsdb, <<Subtype:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_afsdb{subtype = Subtype,
		      hostname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, cert, <<Type:16, KeyTag:16, Alg, Bin/binary>>, _MsgBin) ->
    #dns_rrdata_cert{type = Type, key_tag = KeyTag, alg = Alg, cert = Bin};
decode_rrdata(_Class, cname, Bin, MsgBin) ->
    #dns_rrdata_cname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(Class, dhcid, Bin, _MsgBin) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_dhcid{data = Bin};
decode_rrdata(_Class, dlv, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>,
	      _MsgBin) ->
    #dns_rrdata_dlv{keytag=KeyTag, alg=Alg, digest_type=DigestType, digest=Digest};
decode_rrdata(_Class, dname, Bin, MsgBin) ->
    #dns_rrdata_dname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, dnskey, <<Flags:16, Protocol:8, AlgNum:8,
				PublicKey/binary>> = Bin, _MsgBin)
  when AlgNum =:= ?DNS_ALG_RSASHA1 orelse
       AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
       AlgNum =:= ?DNS_ALG_RSASHA256 orelse
       AlgNum =:= ?DNS_ALG_RSASHA512 ->
    Alg = term_or_arg(fun alg_to_atom/1, AlgNum),
    Key = case PublicKey of
	      <<0, Len:16, Exp:Len/unit:8, ModBin/binary>> ->
		  Mod = binary:decode_unsigned(ModBin),
		  [crypto:mpint(Exp), crypto:mpint(Mod)];
	      <<Len:8, Exp:Len/unit:8, ModBin/binary>> ->
		  Mod = binary:decode_unsigned(ModBin),
		  [crypto:mpint(Exp), crypto:mpint(Mod)]
	  end,
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = Alg,
		       public_key = Key, key_tag = KeyTag};
decode_rrdata(_Class, dnskey, <<Flags:16, Protocol:8, AlgNum:8,
				T, Q:20/unit:8, KeyBin/binary>> = Bin, _MsgBin)
  when (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA)
       andalso T =< 8 ->
    Alg = term_or_arg(fun alg_to_atom/1, AlgNum),
    S = 64 + T * 8,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = KeyBin,
    Key = [crypto:mpint(P),
	   crypto:mpint(Q),
	   crypto:mpint(G),
	   crypto:mpint(Y)],
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = Alg,
		       public_key = Key, key_tag = KeyTag};    
decode_rrdata(_Class, dnskey, <<Flags:16, Protocol:8, AlgNum:8,
				PublicKey/binary>> = Bin, _MsgBin) ->
    Alg = term_or_arg(fun alg_to_atom/1, AlgNum),
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = Alg,
		       public_key = PublicKey, key_tag = bin_to_key_tag(Bin)};
decode_rrdata(_Class, ds, <<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>,
	      _MsgBin) ->
    #dns_rrdata_ds{keytag=KeyTag, alg=Alg, digest_type=DigestType, digest=Digest};
decode_rrdata(_Class, hinfo, Bin, _BodyBin) ->
    [CPU, OS] = decode_txt(Bin),
    #dns_rrdata_hinfo{cpu = CPU, os = OS};
decode_rrdata(_Class, ipseckey, <<Precedence:8, 0:8, Algorithm:8,
				  PublicKey/binary>>, _MsgBin) ->
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = none, public_key = PublicKey};
decode_rrdata(_Class, ipseckey, <<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8,
				  D:8, PublicKey/binary>>, _MsgBin) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = ipv4, gateway = IP,
			 public_key = PublicKey};
decode_rrdata(_Class, ipseckey, <<Precedence:8, 2:8, Algorithm:8, A:16, B:16,
				  C:16, D:16, E:16, F:16, G:16, H:16,
				  PublicKey/binary>>, _MsgBin) ->
    IP = inet_parse:ntoa({A,B,C,D,E,F,G,H}),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = ipv6, gateway = IP,
			 public_key = PublicKey};
decode_rrdata(_Class, ipseckey, <<Precedence:8, 3:8, Algorithm:8, Bin/binary>>, MsgBin) ->
    {Gateway, PublicKey} = decode_dname(Bin, MsgBin),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = dname, gateway = Gateway,
			 public_key = PublicKey};
decode_rrdata(_Class, isdn, <<Len, Addr:Len/binary>>, _MsgBin) ->
    #dns_rrdata_isdn{address = Addr, subaddress = undefined};
decode_rrdata(_Class, isdn, <<ALen, Addr:ALen/binary,
			      SLen, Subaddr:SLen/binary>>, _MsgBin) ->
    #dns_rrdata_isdn{address = Addr, subaddress = Subaddr};
decode_rrdata(_Class, key, <<Type:2, 0:1, XT:1, 0:2, NamType:2, 0:4, SIG:4,
			     Protocol:8, Alg:8, PublicKey/binary>>, _MsgBin) ->
    #dns_rrdata_key{type = Type, xt = XT, name_type = NamType, sig = SIG,
		    protocol = Protocol, alg = Alg, public_key = PublicKey};
decode_rrdata(_Class, kx, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_kx{preference = Preference,
		   exchange = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, loc, <<0:8, SizeB:4, SizeE:4, HorizB:4, HorizE:4, VertB:4,
			     VertE:4, LatPre:32, LonPre:32, AltPre:32>>,
	      _MsgBin) when SizeE < 10 andalso HorizE < 10 andalso VertE < 10 ->
    #dns_rrdata_loc{size = SizeB * (round_pow(10, SizeE)),
		    horiz = HorizB * (round_pow(10, HorizE)),
		    vert = VertB * (round_pow(10, VertE)),
		    lat = decode_loc_point(LatPre),
		    lon = decode_loc_point(LonPre),
		    alt = AltPre - 10000000};
decode_rrdata(_Class, mb, Bin, MsgBin) ->
    #dns_rrdata_mb{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, md, Bin, MsgBin) ->
    #dns_rrdata_md{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, mf, Bin, MsgBin) ->
    #dns_rrdata_mf{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, mg, Bin, MsgBin) ->
    #dns_rrdata_mg{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, minfo, Bin, MsgBin) when is_binary(Bin) ->
    {RMB, EMB} = decode_dname(Bin, MsgBin),
    #dns_rrdata_minfo{rmailbx = RMB, emailbx = decode_dnameonly(EMB, MsgBin)};
decode_rrdata(_Class, mr, Bin, MsgBin) ->
    #dns_rrdata_mr{newname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, mx, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_mx{preference = Preference,
		   exchange = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, naptr, <<Order:16, Preference:16, Bin/binary>>, MsgBin) ->
    {Bin1, Flags} = decode_string(Bin),
    {Bin2, Services} = decode_string(Bin1),
    {Bin3, RawRegexp} = decode_string(Bin2),
    Regexp = unicode:characters_to_binary(RawRegexp, utf8),
    #dns_rrdata_naptr{order = Order, preference = Preference, flags = Flags,
		      services = Services, regexp = Regexp,
		      replacement = decode_dnameonly(Bin3, MsgBin)};
decode_rrdata(_Class, ns, Bin, MsgBin) ->
    #dns_rrdata_ns{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, nsec, Bin, MsgBin) ->
    {NextDName, TypeBMP} = decode_dname(Bin, MsgBin),
    Types = decode_nsec_types(TypeBMP),
    #dns_rrdata_nsec{next_dname = NextDName, types = Types};
decode_rrdata(_Class, nsec3, <<HashAlg:8, _FlagsZ:7, OptOut:1, Iterations:16,
			       SaltLen:8/unsigned, Salt:SaltLen/binary-unit:8,
			       HashLen:8/unsigned, Hash:HashLen/binary-unit:8,
			       TypeBMP/binary>>, _MsgBin) ->
    #dns_rrdata_nsec3{hash_alg = HashAlg, opt_out = decode_bool(OptOut),
		      iterations = Iterations, salt = Salt,
		      hash = Hash, types = decode_nsec_types(TypeBMP)};
decode_rrdata(_Class, nsec3param, <<Alg:8, Flags:8, Iterations:16, SaltLen:8,
				    Salt:SaltLen/binary>>, _MsgBin) ->
    #dns_rrdata_nsec3param{hash_alg = Alg, flags = Flags,
			   iterations = Iterations, salt = Salt};
decode_rrdata(_Class, nxt, Bin, MsgBin) ->
    {NxtDName, BMP} = decode_dname(Bin, MsgBin),
    #dns_rrdata_nxt{dname = NxtDName, types = decode_nxt_bmp(BMP)};
decode_rrdata(_Class, ptr, Bin, MsgBin) ->
    #dns_rrdata_ptr{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, px, <<Pref:16, Bin/binary>>, MsgBin) ->
    {Map822, Mapx400Bin} = decode_dname(Bin, MsgBin),
    Mapx400 = decode_dnameonly(Mapx400Bin, MsgBin),
    #dns_rrdata_px{preference = Pref, map822 = Map822, mapx400 = Mapx400};
decode_rrdata(_Class, rp, Bin, MsgBin) ->
    {Mbox, TxtBin} = decode_dname(Bin, MsgBin),
    #dns_rrdata_rp{mbox = Mbox, txt = decode_dnameonly(TxtBin, MsgBin)};
decode_rrdata(_Class, rrsig, <<TypeN:16, Alg:8, Labels:8, TTL:32, Expire:32,
			       Inception:32, KeyTag:16, Bin/binary>>, MsgBin) ->
    {SigName, Sig} = decode_dname(Bin, MsgBin),
    Type = term_or_arg(fun type_to_atom/1, TypeN),
    #dns_rrdata_rrsig{type_covered = Type, alg = Alg, labels = Labels,
		      original_ttl = TTL, expiration = Expire,
		      inception = Inception, key_tag = KeyTag,
		      signers_name = SigName, signature = Sig};
decode_rrdata(_Class, rt, <<Pref:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_rt{preference = Pref, host = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, soa, Bin, MsgBin) ->
    {MName, RNBin} = decode_dname(Bin, MsgBin),
    {RName, Rest} = decode_dname(RNBin, MsgBin),
    <<Ser:32, Ref:32, Ret:32, Exp:32, Min:32>> = Rest,
    #dns_rrdata_soa{mname = MName, rname = RName, serial = Ser, refresh = Ref,
		    retry = Ret, expire = Exp, minimum = Min};
decode_rrdata(_Class, spf, Bin, _MsgBin) ->
    #dns_rrdata_spf{spf = decode_txt(Bin)};
decode_rrdata(_Class, srv, <<Pri:16, Wght:16, Port:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_srv{priority = Pri, weight = Wght, port = Port,
		    target = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, sshfp, <<Alg:8, FPType:8, FingerPrint/binary>>, _MsgBin) ->
    #dns_rrdata_sshfp{alg=Alg, fp_type=FPType, fp=FingerPrint};
decode_rrdata(_Class, tsig, Bin, MsgBin) ->
    {Alg, <<Time:48, Fudge:16, MS:16, MAC:MS/bytes, MsgID:16, ErrInt:16,
	    OtherLen:16, Other:OtherLen/binary>>} = decode_dname(Bin, MsgBin),
    #dns_rrdata_tsig{alg = Alg, time = Time, fudge = Fudge,
		     mac = MAC, msgid = MsgID, other = Other,
		     err = term_or_arg(fun tsigerr_to_atom/1, ErrInt)};
decode_rrdata(_Class, txt, Bin, _MsgBin) ->
    #dns_rrdata_txt{txt = decode_txt(Bin)};
decode_rrdata(Class, wks, <<A, B, C, D, P, BMP/binary>>, _MsgBin)
  when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    Address = list_to_binary(IP),
    #dns_rrdata_wks{address = Address, protocol = P, bitmap = BMP};
decode_rrdata(_Class, x25, Bin, _MsgBin) ->
    #dns_rrdata_x25{psdn_address = list_to_integer(binary_to_list(Bin))};
decode_rrdata(_Class, _Type, Bin, _MsgBin) -> Bin.

encode_rrdata(_Pos, Class, #dns_rrdata_a{ip = IP}, CompMap)
  when ?CLASS_IS_IN(Class) ->
    {ok, {A,B,C,D}} = parse_ip(IP),
    {<<A, B, C, D>>, CompMap};
encode_rrdata(_Pos, Class, #dns_rrdata_aaaa{ip = IP}, CompMap)
  when ?CLASS_IS_IN(Class) ->
    {ok, {A, B, C, D, E, F, G, H}} = parse_ip(IP),
    {<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_afsdb{subtype = Subtype,
					      hostname = Hostname}, CompMap) ->
    HostnameBin = encode_dname(Hostname),
    {<<Subtype:16, HostnameBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_cert{type = Type, key_tag = KeyTag,
					     alg = Alg, cert = Bin}, CompMap) ->
    {<<Type:16, KeyTag:16, Alg, Bin/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_cname{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(_Pos, in, #dns_rrdata_dhcid{data=Bin}, CompMap) ->
    {Bin, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_dlv{keytag = KeyTag, alg = Alg,
					   digest_type = DigestType,
					   digest = Digest}, CompMap) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_dname{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, Class, #dns_rrdata_dnskey{alg = Alg} = Data, CompMap)
  when is_atom(Alg) ->
    AlgNum = int_or_badarg(fun alg_to_int/1, Alg),
    encode_rrdata(Pos, Class, Data#dns_rrdata_dnskey{alg = AlgNum}, CompMap);
encode_rrdata(_Pos, _Class, #dns_rrdata_dnskey{flags = Flags,
					       protocol = Protocol,
					       alg = Alg,
					       public_key = [E, M]}, CompMap)
  when Alg =:= ?DNS_ALG_RSASHA1 orelse
       Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
       Alg =:= ?DNS_ALG_RSASHA256 orelse
       Alg =:= ?DNS_ALG_RSASHA512 ->
    EBin = binary:encode_unsigned(crypto:erlint(E)),
    MBin = binary:encode_unsigned(crypto:erlint(M)),
    ESize = byte_size(EBin),
    PKBin =  if ESize =< 16#FF ->
		     <<ESize:8, EBin:ESize/binary, MBin/binary>>;
		ESize =< 16#FFFF ->
		     <<0, ESize:16, EBin:ESize/binary, MBin/binary>>;
		true -> erlang:error(badarg)
	     end,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};    
encode_rrdata(_Pos, _Class, #dns_rrdata_dnskey{flags = Flags,
					       protocol = Protocol,
					       alg = Alg,
					       public_key = PKM}, CompMap)
  when Alg =:= ?DNS_ALG_DSA orelse
       Alg =:= ?DNS_ALG_NSEC3DSA ->
    [P, Q, G, Y] = [ crypto:erlint(Mpint) || Mpint <- PKM ],
    M = byte_size(binary:encode_unsigned(P)),
    T = (M - 64) div 8,
    PKBin = <<T, Q:20/unit:8, P:M/unit:8, G:M/unit:8, Y:M/unit:8>>,
    {<<Flags:16, Protocol:8, Alg:8, PKBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_dnskey{flags = Flags,
					       protocol = Protocol,
					       alg = Alg,
					       public_key=PK}, CompMap) ->
    {<<Flags:16, Protocol:8, Alg:8, PK/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ds{keytag = KeyTag, alg = Alg,
					   digest_type = DigestType,
					   digest = Digest}, CompMap) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_hinfo{cpu = CPU, os = OS}, CompMap) ->
    {encode_txt([CPU, OS]), CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type = none,
						 public_key = PublicKey}, CompMap) ->
    {<<Precedence:8, 0:8, Algorithm:8, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type=ipv4,
						 gateway = IP,
						 public_key = PublicKey}, CompMap) ->
    {ok, {A, B, C, D}} = parse_ip(IP),
    {<<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type = ipv6,
						 gateway = IP,
						 public_key = PublicKey}, CompMap) ->
    {ok, {A, B, C, D, E, F, G, H}} = parse_ip(IP),
    {<<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type = dname,
						 gateway = DName,
						 public_key = PublicKey}, CompMap) ->
    DNameBin = encode_dname(DName),
    {<<Precedence:8, 3:8, Algorithm:8, DNameBin/binary, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_isdn{address = Addr,
					     subaddress = undefined}, CompMap) ->
    AddrBin = iolist_to_binary(Addr),
    AddrLen = byte_size(AddrBin),
    {<<AddrLen, AddrBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_isdn{address = Addr,
					     subaddress = Subaddr}, CompMap) ->
    AddrBin = iolist_to_binary(Addr),
    AddrLen = byte_size(AddrBin),
    SubaddrBin = iolist_to_binary(Subaddr),
    SubaddrLen = byte_size(SubaddrBin),
    {<<AddrLen, AddrBin/binary, SubaddrLen, SubaddrBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_key{type = Type,
					    xt = XT,
					    name_type = NameType,
					    sig = SIG,
					    protocol = Protocol,
					    alg = Alg,
					    public_key = PublicKey}, CompMap) ->
    {<<Type:2, 0:1, XT:1, 0:2, NameType:2, 0:4, SIG:4,
       Protocol:8, Alg:8, PublicKey/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_kx{preference = Pref, exchange = Name},
	      CompMap) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(_Pos, _Class, #dns_rrdata_loc{size = Size, horiz = Horiz,
					    vert = Vert, lat = Lat, lon = Lon,
					    alt = Alt}, CompMap) ->
    SizeEnc = encode_loc_size(Size),
    HorizEnc = encode_loc_size(Horiz),
    VertEnc = encode_loc_size(Vert),    
    LatEnc = Lat + 2147483647,
    LonEnc = Lon + 2147483647,
    {<<0:8, SizeEnc:1/binary, HorizEnc:1/binary, VertEnc:1/binary, LatEnc:32, LonEnc:32, (Alt+10000000):32>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_mb{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_md{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_mf{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_mg{madname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_minfo{rmailbx = RMB, emailbx = EMB},
	      CompMap) ->
    {RMBBin, CompMap0} = encode_dname(CompMap, Pos, RMB),
    NewPos = Pos + byte_size(RMBBin),
    {EMBBin, NewCompMap} = encode_dname(CompMap0, NewPos, EMB),
    {<<RMBBin/binary, EMBBin/binary>>, NewCompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_mr{newname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_mx{preference = Pref, exchange = Name},
	      CompMap) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(_Pos, _Class, #dns_rrdata_naptr{order = Order, preference = Pref,
					      flags = Flags, services = Svcs,
					      regexp = Regexp,
					      replacement = Replacement},
	      CompMap) ->
    Bin0 = encode_string(<<Order:16, Pref:16>>, Flags),
    Bin1 = encode_string(Bin0, Svcs),
    Regexp0 = unicode:characters_to_binary(Regexp, unicode, utf8),
    Bin2 = encode_string(Bin1, Regexp0),
    ReplacementBin = encode_dname(Replacement),
    {<<Bin2/binary, ReplacementBin/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_ns{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(_Pos, _Class, #dns_rrdata_nsec{next_dname = NextDName,
					     types = Types}, CompMap) ->
    NextDNameBin = encode_dname(NextDName),
    TypesBin = encode_nsec_types(Types),
    {<<NextDNameBin/binary, TypesBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_nsec3{hash_alg = HashAlg,
					      opt_out = OptOut,
					      iterations = Iterations,
					      salt = Salt,
					      hash = Hash,
					      types = Types}, CompMap) ->
    TypeBMP = encode_nsec_types(Types),
    OptOutN = encode_bool(OptOut),
    SaltLength = byte_size(Salt),
    HashLength = byte_size(Hash),
    {<<HashAlg:8, 0:7, OptOutN:1, Iterations:16,
       SaltLength:8/unsigned, Salt:SaltLength/binary-unit:8,
       HashLength:8/unsigned, Hash:HashLength/binary-unit:8,
       TypeBMP/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_nsec3param{hash_alg = HashAlg,
						   flags = Flags,
						   iterations = Iterations,
						   salt = Salt}, CompMap) ->
    SaltLength = byte_size(Salt),
    {<<HashAlg:8, Flags:8, Iterations:16, SaltLength:8/unsigned,
       Salt:SaltLength/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_nxt{dname = NxtDName, types = Types},
	      CompMap) ->
    {NextDNameBin, NewCompMap} = encode_dname(CompMap, Pos, NxtDName),
    BMP = encode_nxt_bmp(Types),
    {<<NextDNameBin/binary, BMP/binary>>, NewCompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_ptr{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_px{preference = Pref,
					  map822 = Map822,
					  mapx400 = Mapx400}, CompMap) ->
    {Map822Bin, Map822CompMap} = encode_dname(CompMap, Pos + 2, Map822),
    NewPos = Pos + byte_size(Map822Bin) + 2,
    {DnameBin, NewMap} = encode_dname(Map822Bin, Map822CompMap,
				      NewPos, Mapx400),
    {<<Pref:16, DnameBin/binary>>, NewMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_rp{mbox=Mbox, txt=Txt}, CompMap) ->
    MboxBin = encode_dname(Mbox),
    TxtBin = encode_dname(Txt),
    {<<MboxBin/binary, TxtBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_rrsig{type_covered = TypeCovered,
					      alg = Alg, labels=Labels,
					      original_ttl = OriginalTTL,
					      expiration = SigExpire,
					      inception = SigIncept,
					      key_tag = KeyTag,
					      signers_name = SignersName,
					      signature = Sig}, CompMap) ->
    TypeCoveredN = int_or_badarg(fun type_to_int/1, TypeCovered),
    SignersNameBin = encode_dname(SignersName),
    {<<TypeCoveredN:16, Alg:8, Labels:8, OriginalTTL:32, SigExpire:32,
       SigIncept:32, KeyTag:16, SignersNameBin/binary, Sig/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_rt{preference = Pref, host = Name},
	      CompMap) ->
    encode_dname(<<Pref:16>>, CompMap, Pos + 2, Name);
encode_rrdata(Pos, _Class, #dns_rrdata_soa{mname = MName, rname = RName,
					   serial = Serial, refresh = Refresh,
					   retry = Retry, expire = Expire,
					   minimum = Minimum}, CompMap) ->
    {MNBin, MNCMap} = encode_dname(CompMap, Pos, MName),
    NewPos = Pos + byte_size(MNBin),
    {RNBin, RNCMap} = encode_dname(MNBin, MNCMap, NewPos, RName),
    {<<RNBin/binary, Serial:32, Refresh:32, Retry:32, Expire:32, Minimum:32>>,
     RNCMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_spf{spf = Strings}, CompMap) ->
    {encode_txt(Strings), CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_srv{priority = Pri, weight = Wght,
					    port = Port, target = Target},
	      CompMap) ->
    TargetBin = encode_dname(Target),
    {<<Pri:16, Wght:16, Port:16, TargetBin/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_sshfp{alg = Alg,
					      fp_type = FPType,
					      fp = FingerPrint}, CompMap) ->
    {<<Alg:8, FPType:8, FingerPrint/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_tsig{alg = Alg, time = Time,
					     fudge = Fudge, mac = MAC,
					     msgid = MsgID, err = Err,
					     other = Other}, CompMap) ->
    ErrInt = encode_tsigerr(Err),
    AlgBin = encode_dname(Alg),
    MACSize = byte_size(MAC),
    OtherLen = byte_size(Other),
    {<<AlgBin/binary, Time:48, Fudge:16, MACSize:16, MAC:MACSize/bytes,
       MsgID:16, ErrInt:16, OtherLen:16, Other/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_txt{txt = Strings}, CompMap) ->
    {encode_txt(Strings), CompMap};
encode_rrdata(_Pos, Class, #dns_rrdata_wks{address = Address,
					   protocol = P,
					   bitmap = BMP}, CompMap)
  when ?CLASS_IS_IN(Class) ->
    {ok, {A, B, C, D}} = parse_ip(Address),
    {<<A, B, C, D, P, BMP/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_x25{psdn_address = Number}, CompMap) ->
    {list_to_binary(integer_to_list(Number)), CompMap};
encode_rrdata(_Pos, _Class, Bin, CompMap) when is_binary(Bin) ->
    {Bin, CompMap}.

decode_loc_point(P) when is_integer(P) ->
    M = 2147483647,
    case P > M of
	true -> (P - M);
	false -> -1 * (M - P)
    end.

parse_ip(IP) when is_list(IP) andalso is_integer(hd(IP)) ->
    inet_parse:address(IP);
parse_ip(IP) when is_binary(IP) ->
    parse_ip(binary_to_list(IP)).

bin_to_key_tag(Binary) when is_binary(Binary) ->
    bin_to_key_tag(Binary, 0).

bin_to_key_tag(<<>>, AC) ->
    (AC + ((AC bsr 16) band 16#FFFF)) band 16#FFFF;
bin_to_key_tag(<<X:16, Rest/binary>>, AC) -> bin_to_key_tag(Rest, AC + X);
bin_to_key_tag(<<X:8>>, AC) -> bin_to_key_tag(<<>>, AC + (X bsl 8)).

encode_loc_size(Size) when is_float(Size) -> encode_loc_size(round(Size));
encode_loc_size(Size) when is_integer(Size) -> encode_loc_size(Size, 0).

encode_loc_size(Size, Exponent) ->
    case Size rem round_pow(10, Exponent + 1) of
	Size ->
	    Base = Size div round_pow(10, Exponent),
	    <<Base:4, Exponent:4>>;
	_ -> encode_loc_size(Size, Exponent + 1)
    end.

decode_nsec_types(Bin) when is_binary(Bin) -> decode_nsec_types(Bin, []).

decode_nsec_types(<<>>, Types) -> lists:reverse(Types);
decode_nsec_types(<<WindowNum:8, BMPLength:8, BMP:BMPLength/binary,
		    Rest/binary>>, Types) ->
    BaseNo = WindowNum * 256,
    NewTypes = decode_nsec_types(BaseNo, BMP, Types),
    decode_nsec_types(Rest, NewTypes).

decode_nsec_types(_Num, <<>>, Types) -> Types;
decode_nsec_types(Num, <<0:1, Rest/bitstring>>, Types) ->
    decode_nsec_types(Num + 1, Rest, Types);
decode_nsec_types(Num, <<1:1, Rest/bitstring>>, Types) ->
    NewType = term_or_arg(fun type_to_atom/1, Num),
    decode_nsec_types(Num + 1, Rest, [NewType|Types]).

encode_nsec_types([]) -> <<>>;
encode_nsec_types([_|_]=UnsortedTypes) ->
    [FirstType|_] = Types = unique_list([int_or_badarg(fun type_to_int/1, Type)
				     || Type <- UnsortedTypes ]),
    FirstWindowNum = FirstType div 256,
    FirstLastType = FirstWindowNum * 256,
    encode_nsec_types(<<>>, <<>>, FirstWindowNum, FirstLastType, Types).

encode_nsec_types(Bin, BMP0, WindowNum, _LastType, []) -> 
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    <<Bin/binary, WindowNum:8, BMPSize:8, BMP:BMPSize/binary>>;
encode_nsec_types(Bin, BMP0, OldWindowNum, _LastType, [Type|_]=Types)
  when Type div 256 =/= OldWindowNum ->
    BMP = pad_bmp(BMP0),
    BMPSize = byte_size(BMP),
    NewBin = <<Bin/binary, OldWindowNum:8, BMPSize:8, BMP:BMPSize/binary>>,
    NewBMP = <<>>,
    NewWindowNum = Type div 256,
    NewLastType = NewWindowNum * 256,
    encode_nsec_types(NewBin, NewBMP, NewWindowNum, NewLastType, Types);
encode_nsec_types(Bin, BMP, WindowNum, LastType, [Type|Types]) ->
    PadBy = case LastType rem 256 of
		0 -> Type rem 256;
		_ -> Type - LastType - 1
	    end,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    encode_nsec_types(Bin, NewBMP, WindowNum, Type, Types).

decode_nxt_bmp(BMP) -> decode_nxt_bmp(0, BMP, []).

decode_nxt_bmp(_Offset, <<>>, Types) -> lists:reverse(Types);
decode_nxt_bmp(Offset, <<1:1, Rest/bitstring>>, Types) ->
    NewType = term_or_arg(fun type_to_atom/1, Offset),
    decode_nxt_bmp(Offset + 1, Rest, [NewType|Types]);
decode_nxt_bmp(Offset, <<0:1, Rest/bitstring>>, Types) ->
    decode_nxt_bmp(Offset + 1, Rest, Types).

encode_nxt_bmp(UnsortedTypes) when is_list(UnsortedTypes) ->
    Types = unique_list([int_or_badarg(fun type_to_int/1, Type)
			 || Type <- UnsortedTypes]),
    encode_nxt_bmp(0, Types, <<>>).

encode_nxt_bmp(_LastType, [], BMP) -> pad_bmp(BMP);
encode_nxt_bmp(LastType, [Type|Types], BMP) ->
    PadBy = case LastType of
		0 -> Type;
		LastType -> Type - LastType - 1
	    end,
    NewBMP = <<BMP/bitstring, 0:PadBy/unit:1, 1:1>>,
    encode_nxt_bmp(Type, Types, NewBMP).

pad_bmp(BMP) when is_binary(BMP) -> BMP;
pad_bmp(BMP) when is_bitstring(BMP) ->
    PadBy = 8 - bit_size(BMP) rem 8,
    <<BMP/binary-unit:1, 0:PadBy/unit:1>>.



%%%===================================================================
%%% EDNS data functions
%%%===================================================================

decode_optrrdata(Bin) -> decode_optrrdata(Bin, []).

decode_optrrdata(<<EOptNum:16, EOptLen:16, EOptBin:EOptLen/binary, Rest/binary>>, Opts) ->
    EOpt = term_or_arg(fun eoptcode_to_atom/1, EOptNum),
    NewOpt = decode_optrrdata(EOpt, EOptBin),
    NewOpts = [NewOpt|Opts],
    case Rest of
	<<>> -> lists:reverse(NewOpts);
	Rest -> decode_optrrdata(Rest, NewOpts)
    end;
decode_optrrdata(llq, <<1:16, OCNum:16, ECNum:16, Id:64, LeaseLife:32>>) ->
    OC = term_or_arg(fun llqopcode_to_atom/1, OCNum),
    EC = term_or_arg(fun llqerrcode_to_atom/1, ECNum),
    #dns_opt_llq{opcode = OC, errorcode = EC, id = Id, leaselife = LeaseLife};
decode_optrrdata(nsid, Data) ->
    #dns_opt_nsid{data = Data};
decode_optrrdata(owner, <<0:8, S:8, PMAC:6/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC};
decode_optrrdata(owner, <<0:8, S:8, PMAC:6/binary, WMAC:6/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC};
decode_optrrdata(owner, <<0:8, S:8, PMAC:6/binary, WMAC:6/binary,
			  Password/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC,
		   password = Password};
decode_optrrdata(ul, <<Time:32>>) -> #dns_opt_ul{lease = Time};
decode_optrrdata(EOpt, Bin) -> #dns_opt_unknown{id = EOpt, bin = Bin}.

encode_optrrdata(Opts) when is_list(Opts) ->
    encode_optrrdata(lists:reverse(Opts), <<>>);
encode_optrrdata(#dns_opt_llq{opcode = OC, errorcode = EC, id = Id,
			      leaselife = Length}) ->
    OCNum = int_or_badarg(fun llqopcode_to_int/1, OC),
    ECNum = int_or_badarg(fun llqerrcode_to_int/1, EC),
    Data = <<1:16, OCNum:16, ECNum:16, Id:64, Length:32>>,
    {?DNS_EOPTCODE_LLQ, Data};
encode_optrrdata(#dns_opt_ul{lease = Lease}) ->
    {?DNS_EOPTCODE_UL, <<Lease:32>>};
encode_optrrdata(#dns_opt_nsid{data = Data}) when is_binary(Data) ->
    {?DNS_EOPTCODE_NSID, Data};
encode_optrrdata(#dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC,
				password = Password})
  when byte_size(PMAC) =:= 6 andalso byte_size(WMAC) =:= 6 andalso
       (byte_size(Password) =:= 6 orelse byte_size(Password) =:= 4) ->
    Bin = <<0:8, S:8, PMAC/binary, WMAC/binary, Password/binary>>,
    {?DNS_EOPTCODE_OWNER, Bin};
encode_optrrdata(#dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC,
				password = undefined})
  when byte_size(PMAC) =:= 6 andalso byte_size(WMAC) =:= 6 ->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary, WMAC/binary>>};
encode_optrrdata(#dns_opt_owner{seq = S, primary_mac = PMAC, _ = undefined})
  when byte_size(PMAC) =:= 6 ->
    {?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC/binary>>};
encode_optrrdata(#dns_opt_unknown{id = Id, bin = Data})
  when is_integer(Id) andalso is_binary(Data) -> {Id, Data}.

encode_optrrdata([], Bin) -> Bin;
encode_optrrdata([Opt|Opts], Bin) ->
    {Id, NewBin} = encode_optrrdata(Opt),
    Len = byte_size(NewBin),
    encode_optrrdata(Opts, <<Id:16, Len:16, NewBin/binary, Bin/binary>>).

%%%===================================================================
%%% Domain name functions
%%%===================================================================

%% @doc Compare two domain names insensitive of case.
%% @spec compare_dname(A :: dname(), B :: dname()) -> bool()
compare_dname(Name, Name) -> true;
compare_dname(NameA, NameB) ->
    NameALwr = dname_to_lower(iolist_to_binary(NameA)),
    NameBLwr = dname_to_lower(iolist_to_binary(NameB)),
    NameALwr =:= NameBLwr.

decode_dname(DataBin, MsgBin) ->
    RemBin = DataBin,
    decode_dname(DataBin, MsgBin, RemBin, <<>>, 0).

decode_dname(_DataBin, MsgBin, _RemBin, _Dname, Count)
  when Count > byte_size(MsgBin) -> throw(decode_loop);
decode_dname(<<0, DataRBin/binary>>, _MsgBin, RBin, Dname0, Count) ->
    NewRemBin = case Count of
		    0 -> DataRBin;
		    _ -> RBin
		end,
    NewDname = case Dname0 of
		   <<$., Dname/binary>> -> Dname;
		   <<>> -> <<>>
	       end,
    {NewDname, NewRemBin};
decode_dname(<<0:2, Len:6, Label:Len/binary, DataRemBin/binary>>,
	     MsgBin, RemBin, Dname, Count) ->
    NewRemBin = case Count of
		    0 -> DataRemBin;
		    _ -> RemBin
		end,
    NewDname = <<Dname/binary, $., Label/binary>>,
    decode_dname(DataRemBin, MsgBin, NewRemBin, NewDname, Count);
decode_dname(<<3:2, Ptr:14, DataRBin/binary>>, MsgBin, RBin, Dname, Count) ->
    NewRemBin = case Count of
		    0 -> DataRBin;
		    _ -> RBin
		end,
    NewCount = Count + 2,
    case MsgBin of
	<<_:Ptr/binary, NewDataBin/binary>> ->
	    decode_dname(NewDataBin, MsgBin, NewRemBin, Dname, NewCount);
	_ -> throw(bad_pointer)
    end.

decode_dnameonly(Bin, MsgBin) ->
    case decode_dname(Bin, MsgBin) of
	{Dname, <<>>} -> Dname;
	_ -> throw(trailing_garbage)
    end.

encode_dname(Name) ->
    Labels = << <<(byte_size(L)), L/binary>> || L <- dname_to_labels(Name) >>,
    <<Labels/binary, 0>>.

encode_dname(CompMap, Pos, Name) -> encode_dname(<<>>, CompMap, Pos, Name).

encode_dname(Bin, undefined, _Pos, Name) ->
    DnameBin = encode_dname(Name),
    {<<Bin/binary, DnameBin/binary>>, undefined};
encode_dname(Bin, CompMap, Pos, Name) ->
    Labels = dname_to_labels(Name),
    LwrLabels = dname_to_labels(dname_to_lower(Name)),
    encode_dname_labels(Bin, CompMap, Pos, Labels, LwrLabels).

encode_dname_labels(Bin, CompMap, _Pos, [], []) -> {<<Bin/binary, 0>>, CompMap};
encode_dname_labels(Bin, CompMap, Pos, [L|Ls], [_|LwrLs]=LwrLabels) ->
    case gb_trees:lookup(LwrLabels, CompMap) of
	{value, Ptr} ->
	    {<<Bin/binary, 3:2, Ptr:14>>, CompMap};
	none ->
	    NewCompMap = case Pos < (1 bsl 14) of
			     true -> gb_trees:insert(LwrLabels, Pos, CompMap);
			     false -> CompMap
			 end,
	    Size = byte_size(L),
	    NewPos = Pos + 1 + Size,
	    encode_dname_labels(<<Bin/binary, Size, L/binary>>, NewCompMap,
				NewPos, Ls, LwrLs)
    end.

dname_to_labels("") -> [];
dname_to_labels(".") -> [];
dname_to_labels(<<>>) -> [];
dname_to_labels(<<$.>>) -> [];
dname_to_labels(Name) -> dname_to_labels(<<>>, iolist_to_binary(Name)).
dname_to_labels(Label, <<>>) -> [Label];
dname_to_labels(Label, <<$.>>) -> [Label];
dname_to_labels(Label, <<$., Cs/binary>>) -> [Label|dname_to_labels(<<>>, Cs)];
dname_to_labels(Label, <<"\\.", Cs/binary>>) ->
    dname_to_labels(<<Label/binary, $.>>, Cs);
dname_to_labels(Label, <<C, Cs/binary>>) ->
    dname_to_labels(<<Label/binary, C>>, Cs).

%% @doc Returns provided domain name with case-insensitive characters in uppercase.
%% @spec dname_to_upper(string() | binary()) -> string() | binary()
dname_to_upper(Bin) when is_binary(Bin) ->
    << <<(dname_to_upper(C))>> || <<C>> <= Bin >>; 
dname_to_upper(List) when is_list(List) ->
    [ dname_to_upper(C) || C <- List ];
dname_to_upper(Int) 
  when is_integer(Int) andalso  (Int >= $a) andalso (Int =< $z) -> Int - 32;
dname_to_upper(Int) when is_integer(Int) -> Int.

%% @doc Returns provided domain name with case-insensitive characters in lowercase.
%% @spec dname_to_lower(string() | binary()) -> string() | binary()
dname_to_lower(Bin) when is_binary(Bin) ->
    << <<(dname_to_lower(C))>> || <<C>> <= Bin >>; 
dname_to_lower(List) when is_list(List) ->
    [ dname_to_lower(C) || C <- List ];
dname_to_lower(Int)
  when is_integer(Int) andalso (Int >= $A) andalso (Int =< $Z) -> Int + 32;
dname_to_lower(Int) when is_integer(Int) -> Int.

%%%===================================================================
%%% DNS terms
%%%===================================================================

%% @doc Return the atom representation of a class integer.
%% @spec class_to_atom(Class :: integer()) -> atom() | undefined
class_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_CLASS_IN_NUMBER -> ?DNS_CLASS_IN_ATOM;
	?DNS_CLASS_CS_NUMBER -> ?DNS_CLASS_CS_ATOM;
	?DNS_CLASS_CH_NUMBER -> ?DNS_CLASS_CH_ATOM;
	?DNS_CLASS_HS_NUMBER -> ?DNS_CLASS_HS_ATOM;
	?DNS_CLASS_NONE_NUMBER -> ?DNS_CLASS_NONE_ATOM;
	?DNS_CLASS_ANY_NUMBER -> ?DNS_CLASS_ANY_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a class atom.
%% @spec class_to_int(Class :: atom()) -> integer() | undefined
class_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_CLASS_IN_ATOM -> ?DNS_CLASS_IN_NUMBER;
	?DNS_CLASS_CS_ATOM -> ?DNS_CLASS_CS_NUMBER;
	?DNS_CLASS_CH_ATOM -> ?DNS_CLASS_CH_NUMBER;
	?DNS_CLASS_HS_ATOM -> ?DNS_CLASS_HS_NUMBER;
	?DNS_CLASS_NONE_ATOM -> ?DNS_CLASS_NONE_NUMBER;
	?DNS_CLASS_ANY_ATOM -> ?DNS_CLASS_ANY_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of a type integer.
%% @spec type_to_atom(Type :: integer()) -> atom() | undefined
type_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_TYPE_A_NUMBER -> ?DNS_TYPE_A_ATOM;
	?DNS_TYPE_NS_NUMBER -> ?DNS_TYPE_NS_ATOM;
	?DNS_TYPE_MD_NUMBER -> ?DNS_TYPE_MD_ATOM;
	?DNS_TYPE_MF_NUMBER -> ?DNS_TYPE_MF_ATOM;
	?DNS_TYPE_CNAME_NUMBER -> ?DNS_TYPE_CNAME_ATOM;
	?DNS_TYPE_SOA_NUMBER -> ?DNS_TYPE_SOA_ATOM;
	?DNS_TYPE_MB_NUMBER -> ?DNS_TYPE_MB_ATOM;
	?DNS_TYPE_MG_NUMBER -> ?DNS_TYPE_MG_ATOM;
	?DNS_TYPE_MR_NUMBER -> ?DNS_TYPE_MR_ATOM;
	?DNS_TYPE_NULL_NUMBER -> ?DNS_TYPE_NULL_ATOM;
	?DNS_TYPE_WKS_NUMBER -> ?DNS_TYPE_WKS_ATOM;
	?DNS_TYPE_PTR_NUMBER -> ?DNS_TYPE_PTR_ATOM;
	?DNS_TYPE_HINFO_NUMBER -> ?DNS_TYPE_HINFO_ATOM;
	?DNS_TYPE_MINFO_NUMBER -> ?DNS_TYPE_MINFO_ATOM;
	?DNS_TYPE_MX_NUMBER -> ?DNS_TYPE_MX_ATOM;
	?DNS_TYPE_TXT_NUMBER -> ?DNS_TYPE_TXT_ATOM;
	?DNS_TYPE_RP_NUMBER -> ?DNS_TYPE_RP_ATOM;
	?DNS_TYPE_AFSDB_NUMBER -> ?DNS_TYPE_AFSDB_ATOM;
	?DNS_TYPE_X25_NUMBER -> ?DNS_TYPE_X25_ATOM;
	?DNS_TYPE_ISDN_NUMBER -> ?DNS_TYPE_ISDN_ATOM;
	?DNS_TYPE_RT_NUMBER -> ?DNS_TYPE_RT_ATOM;
	?DNS_TYPE_NSAP_NUMBER -> ?DNS_TYPE_NSAP_ATOM;
	?DNS_TYPE_SIG_NUMBER -> ?DNS_TYPE_SIG_ATOM;
	?DNS_TYPE_KEY_NUMBER -> ?DNS_TYPE_KEY_ATOM;
	?DNS_TYPE_PX_NUMBER -> ?DNS_TYPE_PX_ATOM;
	?DNS_TYPE_GPOS_NUMBER -> ?DNS_TYPE_GPOS_ATOM;
	?DNS_TYPE_AAAA_NUMBER -> ?DNS_TYPE_AAAA_ATOM;
	?DNS_TYPE_LOC_NUMBER -> ?DNS_TYPE_LOC_ATOM;
	?DNS_TYPE_NXT_NUMBER -> ?DNS_TYPE_NXT_ATOM;
	?DNS_TYPE_EID_NUMBER -> ?DNS_TYPE_EID_ATOM;
	?DNS_TYPE_NIMLOC_NUMBER -> ?DNS_TYPE_NIMLOC_ATOM;
	?DNS_TYPE_SRV_NUMBER -> ?DNS_TYPE_SRV_ATOM;
	?DNS_TYPE_ATMA_NUMBER -> ?DNS_TYPE_ATMA_ATOM;
	?DNS_TYPE_NAPTR_NUMBER -> ?DNS_TYPE_NAPTR_ATOM;
	?DNS_TYPE_KX_NUMBER -> ?DNS_TYPE_KX_ATOM;
	?DNS_TYPE_CERT_NUMBER -> ?DNS_TYPE_CERT_ATOM;
	?DNS_TYPE_DNAME_NUMBER -> ?DNS_TYPE_DNAME_ATOM;
	?DNS_TYPE_SINK_NUMBER -> ?DNS_TYPE_SINK_ATOM;
	?DNS_TYPE_OPT_NUMBER -> ?DNS_TYPE_OPT_ATOM;
	?DNS_TYPE_APL_NUMBER -> ?DNS_TYPE_APL_ATOM;
	?DNS_TYPE_DS_NUMBER -> ?DNS_TYPE_DS_ATOM;
	?DNS_TYPE_SSHFP_NUMBER -> ?DNS_TYPE_SSHFP_ATOM;
	?DNS_TYPE_IPSECKEY_NUMBER -> ?DNS_TYPE_IPSECKEY_ATOM;
	?DNS_TYPE_RRSIG_NUMBER -> ?DNS_TYPE_RRSIG_ATOM;
	?DNS_TYPE_NSEC_NUMBER -> ?DNS_TYPE_NSEC_ATOM;
	?DNS_TYPE_DNSKEY_NUMBER -> ?DNS_TYPE_DNSKEY_ATOM;
	?DNS_TYPE_NSEC3_NUMBER -> ?DNS_TYPE_NSEC3_ATOM;
	?DNS_TYPE_NSEC3PARAM_NUMBER -> ?DNS_TYPE_NSEC3PARAM_ATOM;
	?DNS_TYPE_DHCID_NUMBER -> ?DNS_TYPE_DHCID_ATOM;
	?DNS_TYPE_HIP_NUMBER -> ?DNS_TYPE_HIP_ATOM;
	?DNS_TYPE_NINFO_NUMBER -> ?DNS_TYPE_NINFO_ATOM;
	?DNS_TYPE_RKEY_NUMBER -> ?DNS_TYPE_RKEY_ATOM;
	?DNS_TYPE_TALINK_NUMBER -> ?DNS_TYPE_TALINK_ATOM;
	?DNS_TYPE_SPF_NUMBER -> ?DNS_TYPE_SPF_ATOM;
	?DNS_TYPE_UINFO_NUMBER -> ?DNS_TYPE_UINFO_ATOM;
	?DNS_TYPE_UID_NUMBER -> ?DNS_TYPE_UID_ATOM;
	?DNS_TYPE_GID_NUMBER -> ?DNS_TYPE_GID_ATOM;
	?DNS_TYPE_UNSPEC_NUMBER -> ?DNS_TYPE_UNSPEC_ATOM;
	?DNS_TYPE_TKEY_NUMBER -> ?DNS_TYPE_TKEY_ATOM;
	?DNS_TYPE_TSIG_NUMBER -> ?DNS_TYPE_TSIG_ATOM;
	?DNS_TYPE_IXFR_NUMBER -> ?DNS_TYPE_IXFR_ATOM;
	?DNS_TYPE_AXFR_NUMBER -> ?DNS_TYPE_AXFR_ATOM;
	?DNS_TYPE_MAILB_NUMBER -> ?DNS_TYPE_MAILB_ATOM;
	?DNS_TYPE_MAILA_NUMBER -> ?DNS_TYPE_MAILA_ATOM;
	?DNS_TYPE_DLV_NUMBER -> ?DNS_TYPE_DLV_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a type integer.
%% @spec type_to_int(Type :: atom()) -> integer() | undefined
type_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_TYPE_A_ATOM -> ?DNS_TYPE_A_NUMBER;
	?DNS_TYPE_NS_ATOM -> ?DNS_TYPE_NS_NUMBER;
	?DNS_TYPE_MD_ATOM -> ?DNS_TYPE_MD_NUMBER;
	?DNS_TYPE_MF_ATOM -> ?DNS_TYPE_MF_NUMBER;
	?DNS_TYPE_CNAME_ATOM -> ?DNS_TYPE_CNAME_NUMBER;
	?DNS_TYPE_SOA_ATOM -> ?DNS_TYPE_SOA_NUMBER;
	?DNS_TYPE_MB_ATOM -> ?DNS_TYPE_MB_NUMBER;
	?DNS_TYPE_MG_ATOM -> ?DNS_TYPE_MG_NUMBER;
	?DNS_TYPE_MR_ATOM -> ?DNS_TYPE_MR_NUMBER;
	?DNS_TYPE_NULL_ATOM -> ?DNS_TYPE_NULL_NUMBER;
	?DNS_TYPE_WKS_ATOM -> ?DNS_TYPE_WKS_NUMBER;
	?DNS_TYPE_PTR_ATOM -> ?DNS_TYPE_PTR_NUMBER;
	?DNS_TYPE_HINFO_ATOM -> ?DNS_TYPE_HINFO_NUMBER;
	?DNS_TYPE_MINFO_ATOM -> ?DNS_TYPE_MINFO_NUMBER;
	?DNS_TYPE_MX_ATOM -> ?DNS_TYPE_MX_NUMBER;
	?DNS_TYPE_TXT_ATOM -> ?DNS_TYPE_TXT_NUMBER;
	?DNS_TYPE_RP_ATOM -> ?DNS_TYPE_RP_NUMBER;
	?DNS_TYPE_AFSDB_ATOM -> ?DNS_TYPE_AFSDB_NUMBER;
	?DNS_TYPE_X25_ATOM -> ?DNS_TYPE_X25_NUMBER;
	?DNS_TYPE_ISDN_ATOM -> ?DNS_TYPE_ISDN_NUMBER;
	?DNS_TYPE_RT_ATOM -> ?DNS_TYPE_RT_NUMBER;
	?DNS_TYPE_NSAP_ATOM -> ?DNS_TYPE_NSAP_NUMBER;
	?DNS_TYPE_SIG_ATOM -> ?DNS_TYPE_SIG_NUMBER;
	?DNS_TYPE_KEY_ATOM -> ?DNS_TYPE_KEY_NUMBER;
	?DNS_TYPE_PX_ATOM -> ?DNS_TYPE_PX_NUMBER;
	?DNS_TYPE_GPOS_ATOM -> ?DNS_TYPE_GPOS_NUMBER;
	?DNS_TYPE_AAAA_ATOM -> ?DNS_TYPE_AAAA_NUMBER;
	?DNS_TYPE_LOC_ATOM -> ?DNS_TYPE_LOC_NUMBER;
	?DNS_TYPE_NXT_ATOM -> ?DNS_TYPE_NXT_NUMBER;
	?DNS_TYPE_EID_ATOM -> ?DNS_TYPE_EID_NUMBER;
	?DNS_TYPE_NIMLOC_ATOM -> ?DNS_TYPE_NIMLOC_NUMBER;
	?DNS_TYPE_SRV_ATOM -> ?DNS_TYPE_SRV_NUMBER;
	?DNS_TYPE_ATMA_ATOM -> ?DNS_TYPE_ATMA_NUMBER;
	?DNS_TYPE_NAPTR_ATOM -> ?DNS_TYPE_NAPTR_NUMBER;
	?DNS_TYPE_KX_ATOM -> ?DNS_TYPE_KX_NUMBER;
	?DNS_TYPE_CERT_ATOM -> ?DNS_TYPE_CERT_NUMBER;
	?DNS_TYPE_DNAME_ATOM -> ?DNS_TYPE_DNAME_NUMBER;
	?DNS_TYPE_SINK_ATOM -> ?DNS_TYPE_SINK_NUMBER;
	?DNS_TYPE_OPT_ATOM -> ?DNS_TYPE_OPT_NUMBER;
	?DNS_TYPE_APL_ATOM -> ?DNS_TYPE_APL_NUMBER;
	?DNS_TYPE_DS_ATOM -> ?DNS_TYPE_DS_NUMBER;
	?DNS_TYPE_SSHFP_ATOM -> ?DNS_TYPE_SSHFP_NUMBER;
	?DNS_TYPE_IPSECKEY_ATOM -> ?DNS_TYPE_IPSECKEY_NUMBER;
	?DNS_TYPE_RRSIG_ATOM -> ?DNS_TYPE_RRSIG_NUMBER;
	?DNS_TYPE_NSEC_ATOM -> ?DNS_TYPE_NSEC_NUMBER;
	?DNS_TYPE_DNSKEY_ATOM -> ?DNS_TYPE_DNSKEY_NUMBER;
	?DNS_TYPE_NSEC3_ATOM -> ?DNS_TYPE_NSEC3_NUMBER;
	?DNS_TYPE_NSEC3PARAM_ATOM -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
	?DNS_TYPE_DHCID_ATOM -> ?DNS_TYPE_DHCID_NUMBER;
	?DNS_TYPE_HIP_ATOM -> ?DNS_TYPE_HIP_NUMBER;
	?DNS_TYPE_NINFO_ATOM -> ?DNS_TYPE_NINFO_NUMBER;
	?DNS_TYPE_RKEY_ATOM -> ?DNS_TYPE_RKEY_NUMBER;
	?DNS_TYPE_TALINK_ATOM -> ?DNS_TYPE_TALINK_NUMBER;
	?DNS_TYPE_SPF_ATOM -> ?DNS_TYPE_SPF_NUMBER;
	?DNS_TYPE_UINFO_ATOM -> ?DNS_TYPE_UINFO_NUMBER;
	?DNS_TYPE_UID_ATOM -> ?DNS_TYPE_UID_NUMBER;
	?DNS_TYPE_GID_ATOM -> ?DNS_TYPE_GID_NUMBER;
	?DNS_TYPE_UNSPEC_ATOM -> ?DNS_TYPE_UNSPEC_NUMBER;
	?DNS_TYPE_TKEY_ATOM -> ?DNS_TYPE_TKEY_NUMBER;
	?DNS_TYPE_TSIG_ATOM -> ?DNS_TYPE_TSIG_NUMBER;
	?DNS_TYPE_IXFR_ATOM -> ?DNS_TYPE_IXFR_NUMBER;
	?DNS_TYPE_AXFR_ATOM -> ?DNS_TYPE_AXFR_NUMBER;
	?DNS_TYPE_MAILB_ATOM -> ?DNS_TYPE_MAILB_NUMBER;
	?DNS_TYPE_MAILA_ATOM -> ?DNS_TYPE_MAILA_NUMBER;
	?DNS_TYPE_DLV_ATOM -> ?DNS_TYPE_DLV_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of an rcode integer.
%% @spec rcode_to_atom(Rcode :: integer()) -> atom()
rcode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_RCODE_NOERROR_NUMBER -> ?DNS_RCODE_NOERROR_ATOM;
	?DNS_RCODE_FORMERR_NUMBER -> ?DNS_RCODE_FORMERR_ATOM;
	?DNS_RCODE_SERVFAIL_NUMBER -> ?DNS_RCODE_SERVFAIL_ATOM;
	?DNS_RCODE_NXDOMAIN_NUMBER -> ?DNS_RCODE_NXDOMAIN_ATOM;
	?DNS_RCODE_NOTIMP_NUMBER -> ?DNS_RCODE_NOTIMP_ATOM;
	?DNS_RCODE_REFUSED_NUMBER -> ?DNS_RCODE_REFUSED_ATOM;
	?DNS_RCODE_YXDOMAIN_NUMBER -> ?DNS_RCODE_YXDOMAIN_ATOM;
	?DNS_RCODE_YXRRSET_NUMBER -> ?DNS_RCODE_YXRRSET_ATOM;
	?DNS_RCODE_NXRRSET_NUMBER -> ?DNS_RCODE_NXRRSET_ATOM;
	?DNS_RCODE_NOTAUTH_NUMBER -> ?DNS_RCODE_NOTAUTH_ATOM;
	?DNS_RCODE_NOTZONE_NUMBER -> ?DNS_RCODE_NOTZONE_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of an rcode integer.
%% @spec rcode_to_int(Rcode :: atom()) -> integer()
rcode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_RCODE_NOERROR_ATOM -> ?DNS_RCODE_NOERROR_NUMBER;
	?DNS_RCODE_FORMERR_ATOM -> ?DNS_RCODE_FORMERR_NUMBER;
	?DNS_RCODE_SERVFAIL_ATOM -> ?DNS_RCODE_SERVFAIL_NUMBER;
	?DNS_RCODE_NXDOMAIN_ATOM -> ?DNS_RCODE_NXDOMAIN_NUMBER;
	?DNS_RCODE_NOTIMP_ATOM -> ?DNS_RCODE_NOTIMP_NUMBER;
	?DNS_RCODE_REFUSED_ATOM -> ?DNS_RCODE_REFUSED_NUMBER;
	?DNS_RCODE_YXDOMAIN_ATOM -> ?DNS_RCODE_YXDOMAIN_NUMBER;
	?DNS_RCODE_YXRRSET_ATOM -> ?DNS_RCODE_YXRRSET_NUMBER;
	?DNS_RCODE_NXRRSET_ATOM -> ?DNS_RCODE_NXRRSET_NUMBER;
	?DNS_RCODE_NOTAUTH_ATOM -> ?DNS_RCODE_NOTAUTH_NUMBER;
	?DNS_RCODE_NOTZONE_ATOM -> ?DNS_RCODE_NOTZONE_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of an opcode integer.
%% @spec opcode_to_atom(OpCode :: integer()) -> atom() | undefined
opcode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_OPCODE_QUERY_NUMBER -> ?DNS_OPCODE_QUERY_ATOM;
	?DNS_OPCODE_IQUERY_NUMBER -> ?DNS_OPCODE_IQUERY_ATOM;
	?DNS_OPCODE_STATUS_NUMBER -> ?DNS_OPCODE_STATUS_ATOM;
	?DNS_OPCODE_UPDATE_NUMBER -> ?DNS_OPCODE_UPDATE_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of an opcode integer.
%% @spec opcode_to_int(OpCode :: atom()) -> integer() | undefined
opcode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_OPCODE_QUERY_ATOM -> ?DNS_OPCODE_QUERY_NUMBER;
	?DNS_OPCODE_IQUERY_ATOM -> ?DNS_OPCODE_IQUERY_NUMBER;
	?DNS_OPCODE_STATUS_ATOM -> ?DNS_OPCODE_STATUS_NUMBER;
	?DNS_OPCODE_UPDATE_ATOM -> ?DNS_OPCODE_UPDATE_NUMBER;
	_ -> undefined
    end.

encode_tsigerr(Int) when is_integer(Int) -> Int;
encode_tsigerr(Atom) when is_atom(Atom) ->
    case tsigerr_to_int(Atom) of
	Int when is_integer(Int) -> Int;
	undefined -> erlang:error(badarg)
    end.

%% @doc Returns the atom representation of a TSIG error code integer.
%% @spec tsigerr_to_atom(TSIGRCode :: integer()) -> atom() | undefined
tsigerr_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_TSIGERR_NOERROR_NUMBER -> ?DNS_TSIGERR_NOERROR_ATOM;
	?DNS_TSIGERR_BADSIG_NUMBER -> ?DNS_TSIGERR_BADSIG_ATOM;
	?DNS_TSIGERR_BADKEY_NUMBER -> ?DNS_TSIGERR_BADKEY_ATOM;
	?DNS_TSIGERR_BADTIME_NUMBER -> ?DNS_TSIGERR_BADTIME_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a TSIG error code atom.
%% @spec tsigerr_to_int(TSIGRCode :: atom()) -> integer() | undefined
tsigerr_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_TSIGERR_NOERROR_ATOM -> ?DNS_TSIGERR_NOERROR_NUMBER;
	?DNS_TSIGERR_BADSIG_ATOM -> ?DNS_TSIGERR_BADSIG_NUMBER;
	?DNS_TSIGERR_BADKEY_ATOM -> ?DNS_TSIGERR_BADKEY_NUMBER;
	?DNS_TSIGERR_BADTIME_ATOM -> ?DNS_TSIGERR_BADTIME_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of an extended rcode integer.
%% @spec ercode_to_atom(ERcode :: integer()) -> atom() | undefined
ercode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_ERCODE_NOERROR_NUMBER -> ?DNS_ERCODE_NOERROR_ATOM;
	?DNS_ERCODE_BADVERS_NUMBER -> ?DNS_ERCODE_BADVERS_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of an extended rcode integer.
%% @spec ercode_to_int(EOptCode :: atom()) -> integer() | undefined
ercode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_ERCODE_NOERROR_ATOM -> ?DNS_ERCODE_NOERROR_NUMBER;
	?DNS_ERCODE_BADVERS_ATOM -> ?DNS_ERCODE_BADVERS_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of an extended option code integer.
%% @spec eoptcode_to_atom(EOptCode :: integer()) -> atom() | undefined
eoptcode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_EOPTCODE_LLQ_NUMBER -> ?DNS_EOPTCODE_LLQ_ATOM;
	?DNS_EOPTCODE_UL_NUMBER -> ?DNS_EOPTCODE_UL_ATOM;
	?DNS_EOPTCODE_NSID_NUMBER -> ?DNS_EOPTCODE_NSID_ATOM;
	?DNS_EOPTCODE_OWNER_NUMBER -> ?DNS_EOPTCODE_OWNER_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of an extended option code atom.
%% @spec eoptcode_to_int(EOptCode :: atom()) -> integer() | undefined
eoptcode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_EOPTCODE_LLQ_ATOM -> ?DNS_EOPTCODE_LLQ_NUMBER;
	?DNS_EOPTCODE_UL_ATOM -> ?DNS_EOPTCODE_UL_NUMBER;
	?DNS_EOPTCODE_NSID_ATOM -> ?DNS_EOPTCODE_NSID_NUMBER;
	?DNS_EOPTCODE_OWNER_ATOM -> ?DNS_EOPTCODE_OWNER_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of a LLQ opcode integer.
%% @spec llqopcode_to_atom(LLQOpCode :: integer()) -> atom() | undefined
llqopcode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_LLQOPCODE_SETUP_NUMBER -> ?DNS_LLQOPCODE_SETUP_ATOM;
	?DNS_LLQOPCODE_REFRESH_NUMBER -> ?DNS_LLQOPCODE_REFRESH_ATOM;
	?DNS_LLQOPCODE_EVENT_NUMBER -> ?DNS_LLQOPCODE_EVENT_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a LLQ opcode atom.
%% @spec llqopcode_to_int(LLQOpCode :: atom()) -> integer() | undefined
llqopcode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_LLQOPCODE_SETUP_ATOM -> ?DNS_LLQOPCODE_SETUP_NUMBER;
	?DNS_LLQOPCODE_REFRESH_ATOM -> ?DNS_LLQOPCODE_REFRESH_NUMBER;
	?DNS_LLQOPCODE_EVENT_ATOM -> ?DNS_LLQOPCODE_EVENT_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of a LLQ error code integer.
%% @spec llqerrcode_to_atom(LLQErrCode :: integer()) -> atom() | undefined
llqerrcode_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_LLQERRCODE_NOERROR_NUMBER -> ?DNS_LLQERRCODE_NOERROR_ATOM;
	?DNS_LLQERRCODE_SERVFULL_NUMBER -> ?DNS_LLQERRCODE_SERVFULL_ATOM;
	?DNS_LLQERRCODE_STATIC_NUMBER -> ?DNS_LLQERRCODE_STATIC_ATOM;
	?DNS_LLQERRCODE_FORMATERR_NUMBER -> ?DNS_LLQERRCODE_FORMATERR_ATOM;
	?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER -> ?DNS_LLQERRCODE_NOSUCHLLQ_ATOM;
	?DNS_LLQERRCODE_BADVERS_NUMBER -> ?DNS_LLQERRCODE_BADVERS_ATOM;
	?DNS_LLQERRCODE_UNKNOWNERR_NUMBER -> ?DNS_LLQERRCODE_UNKNOWNERR_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a LLQ error code integer.
%% @spec llqerrcode_to_int(LLQErrCode :: atom()) -> integer() | undefined
llqerrcode_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_LLQERRCODE_NOERROR_ATOM -> ?DNS_LLQERRCODE_NOERROR_NUMBER;
	?DNS_LLQERRCODE_SERVFULL_ATOM -> ?DNS_LLQERRCODE_SERVFULL_NUMBER;
	?DNS_LLQERRCODE_STATIC_ATOM -> ?DNS_LLQERRCODE_STATIC_NUMBER;
	?DNS_LLQERRCODE_FORMATERR_ATOM -> ?DNS_LLQERRCODE_FORMATERR_NUMBER;
	?DNS_LLQERRCODE_NOSUCHLLQ_ATOM -> ?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER;
	?DNS_LLQERRCODE_BADVERS_ATOM -> ?DNS_LLQERRCODE_BADVERS_NUMBER;
	?DNS_LLQERRCODE_UNKNOWNERR_ATOM -> ?DNS_LLQERRCODE_UNKNOWNERR_NUMBER;
	_ -> undefined
    end.

%% @doc Returns the atom representation of a DNS algorithm integer.
%% @spec alg_to_atom(Alg :: integer()) -> atom() | undefined
alg_to_atom(Int) when is_integer(Int) ->
    case Int of
	?DNS_ALG_DSA_NUMBER -> ?DNS_ALG_DSA_ATOM;
	?DNS_ALG_NSEC3DSA_NUMBER -> ?DNS_ALG_NSEC3DSA_ATOM;
	?DNS_ALG_RSASHA1_NUMBER -> ?DNS_ALG_RSASHA1_ATOM;
	?DNS_ALG_NSEC3RSASHA1_NUMBER -> ?DNS_ALG_NSEC3RSASHA1_ATOM;
	?DNS_ALG_RSASHA256_NUMBER -> ?DNS_ALG_RSASHA256_ATOM;
	?DNS_ALG_RSASHA512_NUMBER -> ?DNS_ALG_RSASHA512_ATOM;
	_ -> undefined
    end.

%% @doc Returns the integer representation of a DNS algorithm atom.
%% @spec alg_to_int(Alg :: atom()) -> integer() | undefined
alg_to_int(Atom) when is_atom(Atom) ->
    case Atom of
	?DNS_ALG_DSA_ATOM -> ?DNS_ALG_DSA_NUMBER;
	?DNS_ALG_NSEC3DSA_ATOM -> ?DNS_ALG_NSEC3DSA_NUMBER;
	?DNS_ALG_RSASHA1_ATOM -> ?DNS_ALG_RSASHA1_NUMBER;
	?DNS_ALG_NSEC3RSASHA1_ATOM -> ?DNS_ALG_NSEC3RSASHA1_NUMBER;
	?DNS_ALG_RSASHA256_ATOM -> ?DNS_ALG_RSASHA256_NUMBER;
	?DNS_ALG_RSASHA512_ATOM -> ?DNS_ALG_RSASHA512_NUMBER;
	_ -> undefined
    end.


%%%===================================================================
%%% Time functions
%%%===================================================================

%% @doc Return current unix time.
%% @spec unix_time() -> unix_time()
unix_time() ->
    unix_time(now()).

%% @doc Return the unix time from a now or universal time.
%% @spec unix_time(tuple()) -> unix_time()
unix_time({_MegaSecs, _Secs, _MicroSecs} = NowTime) ->
    UniversalTime = calendar:now_to_universal_time(NowTime),
    unix_time(UniversalTime);
unix_time({{_, _, _}, {_, _, _}} = UniversalTime) ->
    Epoch = {{1970,1,1},{0,0,0}},
    (calendar:datetime_to_gregorian_seconds(UniversalTime) -
	 calendar:datetime_to_gregorian_seconds(Epoch)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_bool(0) -> false;
decode_bool(1) -> true.

encode_bool(0) -> 0;
encode_bool(1) -> 1;
encode_bool(false) -> 0;
encode_bool(true) -> 1.

term_or_arg(Fun, Arg) when is_function(Fun) ->
    case Fun(Arg) of
	undefined -> Arg;
	NewTerm -> NewTerm
    end.

int_or_badarg(_Fun, Int) when is_integer(Int) -> Int;
int_or_badarg(Fun, Arg) when is_function(Fun) ->
    case Fun(Arg) of
	Int when is_integer(Int) -> Int;
	_ -> erlang:error(badarg)
    end.

decode_txt(<<>>) -> [];
decode_txt(Bin) when is_binary(Bin) ->
    {RB, String} = decode_string(Bin),
    [String|decode_txt(RB)].

encode_txt(String) when is_list(String) andalso is_integer(hd(String)) ->
    encode_txt(<<>>, [String]);
encode_txt(Strings) ->
    encode_txt(<<>>, Strings).
encode_txt(Bin, []) -> Bin;
encode_txt(Bin, [S|Strings]) when is_binary(Bin) ->
    encode_txt(encode_string(Bin, iolist_to_binary(S)), Strings).

decode_string(<<Len, Bin:Len/binary, Rest/binary>>) -> {Rest, Bin}.

encode_string(Bin, StringBin)
  when byte_size(StringBin) < 256 ->
    Size = byte_size(StringBin),
    <<Bin/binary, Size, StringBin/binary>>.

%% @doc Compares two equal sized binaries over their entire length.
%%      Returns immediately if sizes do not match.
%% @spec const_compare(A :: binary(), B :: binary()) -> bool()
const_compare(A, B) when is_binary(A) andalso is_binary(B) ->
    if byte_size(A) =:= byte_size(B) -> const_compare(A, B, 0);
       true -> false end.

const_compare(<<>>, <<>>, Result) -> 0 =:= Result;
const_compare(<<C1:1, A/bitstring>>, <<C2:1, B/bitstring>>, Result) ->
    const_compare(A, B, Result bor (C1 bxor C2)).

round_pow(N, E) -> round(math:pow(N, E)).

unique_list(List) when is_list(List) ->
    lists:sort(sets:to_list(sets:from_list(List))).
