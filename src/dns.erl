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

%% API
-export([decode_message/1, encode_message/1]).
-export([verify_tsig/3, verify_tsig/4]).
-export([add_tsig/5, add_tsig/6]).

-export([compare_dname/2]).
-export([dname_to_upper/1, dname_to_lower/1]).
-export([dname_to_labels/1, labels_to_dname/1, escape_label/1]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-export([class_name/1, type_name/1, rcode_name/1, opcode_name/1, tsigerr_name/1,
	 ercode_name/1, eoptcode_name/1, llqopcode_name/1, llqerrcode_name/1,
	 alg_name/1]).

-export([const_compare/2]).

%% Private
-export([encode_rrdata/2, decode_rrdata/3]).
-export([encode_dname/1]).

-include("dns.hrl").

%% Types
-export_type([message/0, message_id/0, opcode/0, rcode/0, 'query'/0,
	      questions/0, rr/0, optrr/0, answers/0, authority/0, additional/0,
	      dname/0, class/0, type/0, ttl/0, rrdata/0]).
-type decode_error() :: 'formerr' | 'truncated' | 'trailing_garbage'.
-type message() :: #dns_message{}.
-type message_bin() :: <<_:64,_:_*8>>.
-type message_id() :: 0..65535.
-type opcode() :: 0..16.
-type rcode() :: 0..65535.
-type 'query'() :: #dns_query{}.
-type questions() :: ['query'()].
-type rr() :: #dns_rr{}.
-type optrr() :: #dns_optrr{}.
-type answers() :: [rr()].
-type authority() :: [rr()].
-type additional() :: [optrr()|rr()].
-type dname() :: binary().
-type label() :: binary().
-type class() :: 0..65535.
-type type() :: 0..65535.
-type ttl() :: 0..65535.
-type rrdata() :: binary()
		| #dns_rrdata_a{}
		| #dns_rrdata_aaaa{}
		| #dns_rrdata_afsdb{}
		| #dns_rrdata_cert{}
		| #dns_rrdata_cname{}
		| #dns_rrdata_dhcid{}
		| #dns_rrdata_dlv{}
		| #dns_rrdata_dname{}
		| #dns_rrdata_dnskey{}
		| #dns_rrdata_ds{}
		| #dns_rrdata_hinfo{}
		| #dns_rrdata_ipseckey{}
		| #dns_rrdata_isdn{}
		| #dns_rrdata_key{}
		| #dns_rrdata_kx{}
		| #dns_rrdata_loc{}
		| #dns_rrdata_mb{}
		| #dns_rrdata_md{}
		| #dns_rrdata_mf{}
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
		| #dns_rrdata_px{}
		| #dns_rrdata_rp{}
		| #dns_rrdata_rrsig{}
		| #dns_rrdata_rt{}
		| #dns_rrdata_soa{}
		| #dns_rrdata_spf{}
		| #dns_rrdata_srv{}
		| #dns_rrdata_sshfp{}
		| #dns_rrdata_tsig{}
		| #dns_rrdata_txt{}
		| #dns_rrdata_wks{}
		| #dns_rrdata_x25{}.
-type unix_time() :: 0..4294967295.
-type tsig_mac() :: binary().
-type tsig_error() :: 0 | 16..18.
-type tsig_opt() :: {'time', unix_time()} |
		    {'fudge', non_neg_integer()} |
		    {'mac', tsig_mac()}.
-type tsig_alg() :: binary().
-type alg() :: ?DNS_ALG_DSA | ?DNS_ALG_NSEC3DSA|
	       ?DNS_ALG_RSASHA1 | ?DNS_ALG_NSEC3RSASHA1 |
	       ?DNS_ALG_RSASHA256 | ?DNS_ALG_RSASHA512.
-type eoptcode() :: 0..65535.
-type ercode() :: 0 | 16.
-type llqerrcode() :: 0..6.
-type llqopcode() :: 1..3.

-include("dns_tests.hrl").

-define(DEFAULT_TSIG_FUDGE, 5 * 60).

%%%===================================================================
%%% Message body functions
%%%===================================================================

%% @doc Decode a binary DNS message.
-spec decode_message(message_bin()) ->
    {decode_error(), message() | 'undefined', binary()} | message().
decode_message(<<Id:16, QR:1, OC:4, AA:1, TC:1, RD:1, RA:1, 0:1, AD:1, CD:1,
		 RC:4, QC:16, ANC:16, AUC:16, ADC:16, Rest/binary>> = MsgBin) ->
    try #dns_message{id = Id,
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
		     adc = ADC} of
	#dns_message{} = Msg -> decode_message(questions, MsgBin, Rest, Msg)
    catch _ -> {formerr, undefined, MsgBin} end.

decode_message(questions, MsgBin, QBody, #dns_message{qc = QC} = Msg) ->
    case decode_message_questions(QBody, QC, MsgBin) of
	{Questions, Rest} ->
	    NewMsg = Msg#dns_message{questions = Questions},
	    decode_message(answers, MsgBin, Rest, NewMsg);
	{Error, Questions, Rest} ->
	    NewMsg = Msg#dns_message{questions = Questions},
	    {Error, NewMsg, Rest}
    end;
decode_message(Section, MsgBin, Body,
	       #dns_message{anc = ANC, auc = AUC, adc = ADC} = Msg)
  when Section =:= answers orelse
       Section =:= authority orelse
       Section =:= additional ->
    {C, Next} = case Section of
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
decode_message(finished, _MsgBin, <<>>, #dns_message{} = Msg) -> Msg;
decode_message(finished, _MsgBin, Bin, #dns_message{} = Msg)
  when is_binary(Bin) -> {trailing_garbage, Msg, Bin}.

decode_message_questions(DataBin, Count, MsgBin) ->
    decode_message_questions(DataBin, Count, MsgBin, []).

decode_message_questions(DataBin, 0, _MsgBin, Qs) ->
    {lists:reverse(Qs), DataBin};
decode_message_questions(<<>>, _Count, _MsgBin, Qs) ->
    {truncated, lists:reverse(Qs), <<>>};
decode_message_questions(DataBin, Count, MsgBin, Qs) ->
    case catch decode_dname(DataBin, MsgBin) of
	{Name, <<Type:16, Class:16, RB/binary>>} ->
	    Q = #dns_query{name = Name, type = Type, class = Class},
	    decode_message_questions(RB, Count - 1, MsgBin, [Q|Qs]);
	{_Name, _Bin} ->
	    {truncated, lists:reverse(Qs), DataBin};
	Error when is_atom(Error) ->
	    {Error, lists:reverse(Qs), DataBin};
	_ ->
	    {formerr, lists:reverse(Qs), DataBin}
    end.

decode_message_body(DataBin, Count, MsgBin) ->
    decode_message_body(DataBin, Count, MsgBin, []).

decode_message_body(<<>>, _Count, _MsgBin, RRs) ->
    {lists:reverse(RRs), <<>>};
decode_message_body(DataBin, 0, _MsgBin, RRs) ->
    {lists:reverse(RRs), DataBin};
decode_message_body(DataBin, Count, MsgBin, RRs) ->
    case catch decode_dname(DataBin, MsgBin) of
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
	{Name, <<Type:16/unsigned, Class:16/unsigned, TTL:32/signed, Len:16,
		 RdataBin:Len/binary, RemBin/binary>>} ->
	    RR = #dns_rr{name = Name,
			 type = Type,
			 class = Class,
			 ttl = TTL,
			 data = decode_rrdata(Class, Type, RdataBin, MsgBin)},
	    decode_message_body(RemBin, Count - 1, MsgBin, [RR|RRs]);
	{_Name, <<_Type:16/unsigned, _Class:16/unsigned, _TTL:32/signed, Len:16,
		  Data/binary>>} when byte_size(Data) < Len ->
	    {truncated, lists:reverse(RRs), DataBin};
	Error when is_atom(Error) ->
	    {Error, lists:reverse(RRs), DataBin};
	_ ->
	    {formerr, lists:reverse(RRs), DataBin}
    end.

add_rr_to_section(answers, #dns_message{} = Msg, RR) ->
    Msg#dns_message{answers = RR};
add_rr_to_section(authority, #dns_message{} = Msg, RR) ->
    Msg#dns_message{authority = RR};
add_rr_to_section(additional, #dns_message{} = Msg, RR) ->
    Msg#dns_message{additional = RR}.

%% @doc Encode a dns_message record.
-spec encode_message(message()) -> message_bin().
encode_message(#dns_message{id = Id, qr = QR, oc = OC, aa = AA, tc = TC,
			    rd = RD, ra = RA, ad = AD, cd = CD, rc = RC,
			    qc = QC, anc = ANC, auc = AUC, adc = ADC,
			    questions = Questions, answers = Answers,
			    authority = Authority, additional = Additional}) ->
    QRInt = encode_bool(QR),
    AAInt = encode_bool(AA),
    TCInt = encode_bool(TC),
    RDInt = encode_bool(RD),
    RAInt = encode_bool(RA),
    ADInt = encode_bool(AD),
    CDInt = encode_bool(CD),
    BinH = <<Id:16, QRInt:1, OC:4, AAInt:1, TCInt:1, RDInt:1, RAInt:1, 0:1,
	     ADInt:1, CDInt:1, RC:4, QC:16, ANC:16, AUC:16, ADC:16>>,
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
    NewBin = <<NameBin/binary, Type:16, Class:16>>,
    encode_message_questions(NewBin, NewCompMap, Questions).

encode_message_body(Bin, CompMap, []) -> {Bin, CompMap};
encode_message_body(Bin, CompMap, [#dns_rr{name = Name,
					   type = Type,
					   class = Class,
					   ttl = TTL,
					   data = Data}|Records]) ->
    {NameBin, NameCompMap} = encode_dname(CompMap, byte_size(Bin), Name),
    RRBinOffset = byte_size(Bin) + byte_size(NameBin) + 2 + 2 + 4 + 2,
    {RRBin, NewCompMap} = encode_rrdata(RRBinOffset, Class, Data, NameCompMap),
    RRBinSize = byte_size(RRBin),
    NewBin = <<Bin/binary, NameBin/binary, Type:16, Class:16, TTL:32,
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
-spec random_id() -> message_id().
random_id() -> crypto:rand_uniform(0, 65535).

%%%===================================================================
%%% TSIG functions
%%%===================================================================

%% @equiv verify_tsig(MsgBin, Name, Secret, [])
-spec verify_tsig(message_bin(), dname(), binary()) ->
			 {'ok', tsig_mac()} | {'error', tsig_error()}.
verify_tsig(MsgBin, Name, Secret) ->
    verify_tsig(MsgBin, Name, Secret, []).

%% @doc Verifies a TSIG message signature.
-spec verify_tsig(message_bin(), dname(), binary(), [tsig_opt()]) ->
			 {'ok', tsig_mac()} | {'error', tsig_error()}.
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
			    if Now < (Time - Fudge) ->
				    {error, ?DNS_TSIGERR_BADTIME};
			       Now > (Time + Fudge) ->
				    {error, ?DNS_TSIGERR_BADTIME};
			       true -> {ok, SMAC}
			    end;
			false -> {error, ?DNS_TSIGERR_BADSIG}
		    end;
		{error, Error} -> {error, Error}
	    end;
	false -> {error, ?DNS_TSIGERR_BADKEY}
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
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error(), [tsig_opt()]) ->
		      message().
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
    RR = #dns_rr{name = Name, class = ?DNS_CLASS_ANY, type = ?DNS_TYPE_TSIG,
		 ttl = 0, data = Data},
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
    {_Answers, TSIGBin} = decode_message_body(QRB, ANC + AUC + UnsignedADC,
					      MsgBin),
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
	       <<Time:48>>, <<Fudge:16>>, <<ErrorCode:16>>, <<OtherLen:16>>,
	       Other],
    case dname_to_lower(iolist_to_binary(Alg)) of
	?DNS_TSIG_ALG_MD5 -> {ok, crypto:md5_mac(Secret, MACData)};
	?DNS_TSIG_ALG_SHA1 -> {ok, crypto:sha_mac(Secret, MACData)};
	?DNS_TSIG_ALG_SHA224 -> {ok, sha2:hmac_sha224(Secret, MACData)};
	?DNS_TSIG_ALG_SHA256 -> {ok, sha2:hmac_sha256(Secret, MACData)};
	?DNS_TSIG_ALG_SHA384 -> {ok, sha2:hmac_sha384(Secret, MACData)};
	?DNS_TSIG_ALG_SHA512 -> {ok, sha2:hmac_sha512(Secret, MACData)};
	_ -> {error, ?DNS_TSIGERR_BADKEY}
    end.

%%%===================================================================
%%% Record data functions
%%%===================================================================

-define(CLASS_IS_IN(T), (T =:= ?DNS_CLASS_IN orelse T =:= ?DNS_CLASS_NONE)).


%% @private
decode_rrdata(Class, Type, Data) ->
    decode_rrdata(Class, Type, Data, <<>>).

decode_rrdata(_Class, _Type, <<>>, _MsgBin) -> <<>>;
decode_rrdata(Class, ?DNS_TYPE_A, <<A, B, C, D>>, _MsgBin)
  when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    #dns_rrdata_a{ip = list_to_binary(IP)};
decode_rrdata(Class, ?DNS_TYPE_AAAA,
	      <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>, _MsgBin)
  when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D,E,F,G,H}),
    #dns_rrdata_aaaa{ip = list_to_binary(IP)};
decode_rrdata(_Class, ?DNS_TYPE_AFSDB, <<Subtype:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_afsdb{subtype = Subtype,
		      hostname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_CERT, <<Type:16, KeyTag:16, Alg, Bin/binary>>,
	      _MsgBin) ->
    #dns_rrdata_cert{type = Type, key_tag = KeyTag, alg = Alg, cert = Bin};
decode_rrdata(_Class, ?DNS_TYPE_CNAME, Bin, MsgBin) ->
    #dns_rrdata_cname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(Class, ?DNS_TYPE_DHCID, Bin, _MsgBin) when ?CLASS_IS_IN(Class) ->
    #dns_rrdata_dhcid{data = Bin};
decode_rrdata(_Class, ?DNS_TYPE_DLV, <<KeyTag:16, Alg:8, DigestType:8,
				       Digest/binary>>, _MsgBin) ->
    #dns_rrdata_dlv{keytag = KeyTag, alg = Alg, digest_type = DigestType,
		    digest = Digest};
decode_rrdata(_Class, ?DNS_TYPE_DNAME, Bin, MsgBin) ->
    #dns_rrdata_dname{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8,
				PublicKey/binary>> = Bin, _MsgBin)
  when AlgNum =:= ?DNS_ALG_RSASHA1 orelse
       AlgNum =:= ?DNS_ALG_NSEC3RSASHA1 orelse
       AlgNum =:= ?DNS_ALG_RSASHA256 orelse
       AlgNum =:= ?DNS_ALG_RSASHA512 ->
    Key = case PublicKey of
	      <<0, Len:16, Exp:Len/unit:8, ModBin/binary>> ->
		  ModSize = byte_size(ModBin),
		  <<Mod:ModSize/unit:8>> = ModBin,
		  [crypto:mpint(Exp), crypto:mpint(Mod)];
	      <<Len:8, Exp:Len/unit:8, ModBin/binary>> ->
		  ModSize = byte_size(ModBin),
		  <<Mod:ModSize/unit:8>> = ModBin,
		  [crypto:mpint(Exp), crypto:mpint(Mod)]
	  end,
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = AlgNum,
		       public_key = Key, key_tag = KeyTag};
decode_rrdata(_Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8,
				T, Q:20/unit:8, KeyBin/binary>> = Bin, _MsgBin)
  when (AlgNum =:= ?DNS_ALG_DSA orelse AlgNum =:= ?DNS_ALG_NSEC3DSA)
       andalso T =< 8 ->
    S = 64 + T * 8,
    <<P:S/unit:8, G:S/unit:8, Y:S/unit:8>> = KeyBin,
    Key = [crypto:mpint(P),
	   crypto:mpint(Q),
	   crypto:mpint(G),
	   crypto:mpint(Y)],
    KeyTag = bin_to_key_tag(Bin),
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = AlgNum,
		       public_key = Key, key_tag = KeyTag};
decode_rrdata(_Class, ?DNS_TYPE_DNSKEY, <<Flags:16, Protocol:8, AlgNum:8,
				PublicKey/binary>> = Bin, _MsgBin) ->
    #dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = AlgNum,
		       public_key = PublicKey, key_tag = bin_to_key_tag(Bin)};
decode_rrdata(_Class, ?DNS_TYPE_DS, <<KeyTag:16, Alg:8, DigestType:8,
				      Digest/binary>>, _MsgBin) ->
    #dns_rrdata_ds{keytag = KeyTag, alg = Alg, digest_type = DigestType,
		   digest = Digest};
decode_rrdata(_Class, ?DNS_TYPE_HINFO, Bin, _BodyBin) ->
    [CPU, OS] = decode_txt(Bin),
    #dns_rrdata_hinfo{cpu = CPU, os = OS};
decode_rrdata(_Class, ?DNS_TYPE_IPSECKEY, <<Precedence:8, 0:8, Algorithm:8,
				  PublicKey/binary>>, _MsgBin) ->
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = none, public_key = PublicKey};
decode_rrdata(_Class, ?DNS_TYPE_IPSECKEY,
	      <<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8,
		PublicKey/binary>>, _MsgBin) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = ipv4, gateway = IP,
			 public_key = PublicKey};
decode_rrdata(_Class, ?DNS_TYPE_IPSECKEY,
	      <<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16,
		F:16, G:16, H:16, PublicKey/binary>>, _MsgBin) ->
    IP = inet_parse:ntoa({A,B,C,D,E,F,G,H}),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = ipv6, gateway = IP,
			 public_key = PublicKey};
decode_rrdata(_Class, ?DNS_TYPE_IPSECKEY, <<Precedence:8, 3:8, Algorithm:8,
					    Bin/binary>>, MsgBin) ->
    {Gateway, PublicKey} = decode_dname(Bin, MsgBin),
    #dns_rrdata_ipseckey{precedence = Precedence, alg = Algorithm,
			 gateway_type = dname, gateway = Gateway,
			 public_key = PublicKey};
decode_rrdata(_Class, ?DNS_TYPE_ISDN, <<Len, Addr:Len/binary>>, _MsgBin) ->
    #dns_rrdata_isdn{address = Addr, subaddress = undefined};
decode_rrdata(_Class, ?DNS_TYPE_ISDN, <<ALen, Addr:ALen/binary,
			      SLen, Subaddr:SLen/binary>>, _MsgBin) ->
    #dns_rrdata_isdn{address = Addr, subaddress = Subaddr};
decode_rrdata(_Class, ?DNS_TYPE_KEY,
	      <<Type:2, 0:1, XT:1, 0:2, NamType:2, 0:4, SIG:4, Protocol:8,
		Alg:8, PublicKey/binary>>, _MsgBin) ->
    #dns_rrdata_key{type = Type, xt = XT, name_type = NamType, sig = SIG,
		    protocol = Protocol, alg = Alg, public_key = PublicKey};
decode_rrdata(_Class, ?DNS_TYPE_KX, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_kx{preference = Preference,
		   exchange = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_LOC,
	      <<0:8, SizeB:4, SizeE:4, HorizB:4, HorizE:4, VertB:4, VertE:4,
		LatPre:32, LonPre:32, AltPre:32>>,
	      _MsgBin) when SizeE < 10 andalso HorizE < 10 andalso VertE < 10 ->
    #dns_rrdata_loc{size = SizeB * (round_pow(10, SizeE)),
		    horiz = HorizB * (round_pow(10, HorizE)),
		    vert = VertB * (round_pow(10, VertE)),
		    lat = decode_loc_point(LatPre),
		    lon = decode_loc_point(LonPre),
		    alt = AltPre - 10000000};
decode_rrdata(_Class, ?DNS_TYPE_MB, Bin, MsgBin) ->
    #dns_rrdata_mb{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MD, Bin, MsgBin) ->
    #dns_rrdata_md{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MF, Bin, MsgBin) ->
    #dns_rrdata_mf{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MG, Bin, MsgBin) ->
    #dns_rrdata_mg{madname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MINFO, Bin, MsgBin) when is_binary(Bin) ->
    {RMB, EMB} = decode_dname(Bin, MsgBin),
    #dns_rrdata_minfo{rmailbx = RMB, emailbx = decode_dnameonly(EMB, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MR, Bin, MsgBin) ->
    #dns_rrdata_mr{newname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_MX, <<Preference:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_mx{preference = Preference,
		   exchange = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_NAPTR, <<Order:16, Preference:16, Bin/binary>>,
	      MsgBin) ->
    {Bin1, Flags} = decode_string(Bin),
    {Bin2, Services} = decode_string(Bin1),
    {Bin3, RawRegexp} = decode_string(Bin2),
    Regexp = unicode:characters_to_binary(RawRegexp, utf8),
    #dns_rrdata_naptr{order = Order, preference = Preference, flags = Flags,
		      services = Services, regexp = Regexp,
		      replacement = decode_dnameonly(Bin3, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_NS, Bin, MsgBin) ->
    #dns_rrdata_ns{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_NSEC, Bin, MsgBin) ->
    {NextDName, TypeBMP} = decode_dname(Bin, MsgBin),
    Types = decode_nsec_types(TypeBMP),
    #dns_rrdata_nsec{next_dname = NextDName, types = Types};
decode_rrdata(_Class, ?DNS_TYPE_NSEC3,
	      <<HashAlg:8, _FlagsZ:7, OptOut:1, Iterations:16,
		SaltLen:8/unsigned, Salt:SaltLen/binary-unit:8,
		HashLen:8/unsigned, Hash:HashLen/binary-unit:8,
		TypeBMP/binary>>, _MsgBin) ->
    #dns_rrdata_nsec3{hash_alg = HashAlg, opt_out = decode_bool(OptOut),
		      iterations = Iterations, salt = Salt,
		      hash = Hash, types = decode_nsec_types(TypeBMP)};
decode_rrdata(_Class, ?DNS_TYPE_NSEC3PARAM, <<Alg:8, Flags:8, Iterations:16,
					      SaltLen:8, Salt:SaltLen/binary>>,
	      _MsgBin) ->
    #dns_rrdata_nsec3param{hash_alg = Alg, flags = Flags,
			   iterations = Iterations, salt = Salt};
decode_rrdata(_Class, ?DNS_TYPE_NXT, Bin, MsgBin) ->
    {NxtDName, BMP} = decode_dname(Bin, MsgBin),
    #dns_rrdata_nxt{dname = NxtDName, types = decode_nxt_bmp(BMP)};
decode_rrdata(_Class, ?DNS_TYPE_PTR, Bin, MsgBin) ->
    #dns_rrdata_ptr{dname = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_PX, <<Pref:16, Bin/binary>>, MsgBin) ->
    {Map822, Mapx400Bin} = decode_dname(Bin, MsgBin),
    Mapx400 = decode_dnameonly(Mapx400Bin, MsgBin),
    #dns_rrdata_px{preference = Pref, map822 = Map822, mapx400 = Mapx400};
decode_rrdata(_Class, ?DNS_TYPE_RP, Bin, MsgBin) ->
    {Mbox, TxtBin} = decode_dname(Bin, MsgBin),
    #dns_rrdata_rp{mbox = Mbox, txt = decode_dnameonly(TxtBin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_RRSIG, <<Type:16, Alg:8, Labels:8, TTL:32,
					 Expire:32, Inception:32, KeyTag:16,
					 Bin/binary>>, MsgBin) ->
    {SigName, Sig} = decode_dname(Bin, MsgBin),
    #dns_rrdata_rrsig{type_covered = Type, alg = Alg, labels = Labels,
		      original_ttl = TTL, expiration = Expire,
		      inception = Inception, key_tag = KeyTag,
		      signers_name = SigName, signature = Sig};
decode_rrdata(_Class, ?DNS_TYPE_RT, <<Pref:16, Bin/binary>>, MsgBin) ->
    #dns_rrdata_rt{preference = Pref, host = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_SOA, Bin, MsgBin) ->
    {MName, RNBin} = decode_dname(Bin, MsgBin),
    {RName, Rest} = decode_dname(RNBin, MsgBin),
    <<Ser:32, Ref:32, Ret:32, Exp:32, Min:32>> = Rest,
    #dns_rrdata_soa{mname = MName, rname = RName, serial = Ser, refresh = Ref,
		    retry = Ret, expire = Exp, minimum = Min};
decode_rrdata(_Class, ?DNS_TYPE_SPF, Bin, _MsgBin) ->
    #dns_rrdata_spf{spf = decode_txt(Bin)};
decode_rrdata(_Class, ?DNS_TYPE_SRV, <<Pri:16, Wght:16, Port:16, Bin/binary>>,
	      MsgBin) ->
    #dns_rrdata_srv{priority = Pri, weight = Wght, port = Port,
		    target = decode_dnameonly(Bin, MsgBin)};
decode_rrdata(_Class, ?DNS_TYPE_SSHFP, <<Alg:8, FPType:8, FingerPrint/binary>>,
	      _MsgBin) ->
    #dns_rrdata_sshfp{alg=Alg, fp_type=FPType, fp=FingerPrint};
decode_rrdata(_Class, ?DNS_TYPE_TSIG, Bin, MsgBin) ->
    {Alg, <<Time:48, Fudge:16, MS:16, MAC:MS/bytes, MsgID:16, ErrInt:16,
	    OtherLen:16, Other:OtherLen/binary>>} = decode_dname(Bin, MsgBin),
    #dns_rrdata_tsig{alg = Alg, time = Time, fudge = Fudge,
		     mac = MAC, msgid = MsgID, other = Other,
		     err = ErrInt};
decode_rrdata(_Class, ?DNS_TYPE_TXT, Bin, _MsgBin) ->
    #dns_rrdata_txt{txt = decode_txt(Bin)};
decode_rrdata(Class, ?DNS_TYPE_WKS, <<A, B, C, D, P, BMP/binary>>, _MsgBin)
  when ?CLASS_IS_IN(Class) ->
    IP = inet_parse:ntoa({A,B,C,D}),
    Address = list_to_binary(IP),
    #dns_rrdata_wks{address = Address, protocol = P, bitmap = BMP};
decode_rrdata(_Class, ?DNS_TYPE_X25, Bin, _MsgBin) ->
    #dns_rrdata_x25{psdn_address = list_to_integer(binary_to_list(Bin))};
decode_rrdata(_Class, _Type, Bin, _MsgBin) -> Bin.


%% @private
encode_rrdata(Class, Data) ->
    {Bin, undefined} = encode_rrdata(0, Class, Data, undefined),
    Bin.

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
encode_rrdata(_Pos, ?DNS_CLASS_IN, #dns_rrdata_dhcid{data=Bin}, CompMap) ->
    {Bin, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_dlv{keytag = KeyTag, alg = Alg,
					   digest_type = DigestType,
					   digest = Digest}, CompMap) ->
    {<<KeyTag:16, Alg:8, DigestType:8, Digest/binary>>, CompMap};
encode_rrdata(Pos, _Class, #dns_rrdata_dname{dname = Name}, CompMap) ->
    encode_dname(CompMap, Pos, Name);
encode_rrdata(_Pos, _Class, #dns_rrdata_dnskey{flags = Flags,
					       protocol = Protocol,
					       alg = Alg,
					       public_key = [E, M]}, CompMap)
  when Alg =:= ?DNS_ALG_RSASHA1 orelse
       Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
       Alg =:= ?DNS_ALG_RSASHA256 orelse
       Alg =:= ?DNS_ALG_RSASHA512 ->
    <<_MSize:32, MBin0/binary>> = M,
    MBin = strip_leading_zeros(MBin0),
    <<_ESize:32, EBin0/binary>> = E,
    EBin = strip_leading_zeros(EBin0),
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
    [<<_MSize:32, MBin/binary>>, _, _, _] = PKM,
    [P, Q, G, Y] = [ crypto:erlint(Mpint) || Mpint <- PKM ],
    M = byte_size(strip_leading_zeros(MBin)),
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
						 public_key = PublicKey},
	      CompMap) ->
    {<<Precedence:8, 0:8, Algorithm:8, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type=ipv4,
						 gateway = IP,
						 public_key = PublicKey},
	      CompMap) ->
    {ok, {A, B, C, D}} = parse_ip(IP),
    {<<Precedence:8, 1:8, Algorithm:8, A:8, B:8, C:8, D:8, PublicKey/binary>>,
     CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type = ipv6,
						 gateway = IP,
						 public_key = PublicKey},
	      CompMap) ->
    {ok, {A, B, C, D, E, F, G, H}} = parse_ip(IP),
    {<<Precedence:8, 2:8, Algorithm:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16,
       H:16, PublicKey/binary>>, CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_ipseckey{precedence = Precedence,
						 alg = Algorithm,
						 gateway_type = dname,
						 gateway = DName,
						 public_key = PublicKey},
	      CompMap) ->
    DNameBin = encode_dname(DName),
    {<<Precedence:8, 3:8, Algorithm:8, DNameBin/binary, PublicKey/binary>>,
     CompMap};
encode_rrdata(_Pos, _Class, #dns_rrdata_isdn{address = Addr,
					     subaddress = undefined},
	      CompMap) ->
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
    {<<0:8, SizeEnc:1/binary, HorizEnc:1/binary, VertEnc:1/binary, LatEnc:32,
       LonEnc:32, (Alt+10000000):32>>, CompMap};
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
    SignersNameBin = encode_dname(SignersName),
    {<<TypeCovered:16, Alg:8, Labels:8, OriginalTTL:32, SigExpire:32,
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
    AlgBin = encode_dname(Alg),
    MACSize = byte_size(MAC),
    OtherLen = byte_size(Other),
    {<<AlgBin/binary, Time:48, Fudge:16, MACSize:16, MAC:MACSize/bytes,
       MsgID:16, Err:16, OtherLen:16, Other/binary>>, CompMap};
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
    decode_nsec_types(Num + 1, Rest, [Num|Types]).

encode_nsec_types([]) -> <<>>;
encode_nsec_types([_|_]=UnsortedTypes) ->
    [FirstType|_] = Types = lists:usort(UnsortedTypes),
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
    decode_nxt_bmp(Offset + 1, Rest, [Offset|Types]);
decode_nxt_bmp(Offset, <<0:1, Rest/bitstring>>, Types) ->
    decode_nxt_bmp(Offset + 1, Rest, Types).

encode_nxt_bmp(UnsortedTypes) when is_list(UnsortedTypes) ->
    Types = lists:usort(UnsortedTypes),
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

decode_optrrdata(<<>>) -> [];
decode_optrrdata(Bin) -> decode_optrrdata(Bin, []).

decode_optrrdata(<<EOptNum:16, EOptLen:16, EOptBin:EOptLen/binary,
		   Rest/binary>>, Opts) ->
    NewOpt = decode_optrrdata(EOptNum, EOptBin),
    NewOpts = [NewOpt|Opts],
    case Rest of
	<<>> -> lists:reverse(NewOpts);
	Rest -> decode_optrrdata(Rest, NewOpts)
    end;
decode_optrrdata(?DNS_EOPTCODE_LLQ, <<1:16, OC:16, EC:16, Id:64, LeaseLife:32>>) ->
    #dns_opt_llq{opcode = OC, errorcode = EC, id = Id, leaselife = LeaseLife};
decode_optrrdata(?DNS_EOPTCODE_NSID, Data) ->
    #dns_opt_nsid{data = Data};
decode_optrrdata(?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC:6/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC};
decode_optrrdata(?DNS_EOPTCODE_OWNER,
		 <<0:8, S:8, PMAC:6/binary, WMAC:6/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC};
decode_optrrdata(?DNS_EOPTCODE_OWNER, <<0:8, S:8, PMAC:6/binary, WMAC:6/binary,
					Password/binary>>) ->
    #dns_opt_owner{seq = S, primary_mac = PMAC, wakeup_mac = WMAC,
		   password = Password};
decode_optrrdata(?DNS_EOPTCODE_UL, <<Time:32>>) -> #dns_opt_ul{lease = Time};
decode_optrrdata(EOpt, Bin) -> #dns_opt_unknown{id = EOpt, bin = Bin}.

encode_optrrdata(Opts) when is_list(Opts) ->
    encode_optrrdata(lists:reverse(Opts), <<>>);
encode_optrrdata(#dns_opt_llq{opcode = OC, errorcode = EC, id = Id,
			      leaselife = Length}) ->
    Data = <<1:16, OC:16, EC:16, Id:64, Length:32>>,
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
-spec compare_dname(dname(), dname()) -> boolean().
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
decode_dname(<<0:2, Len:6, Label0:Len/binary, DataRemBin/binary>>,
	     MsgBin, RemBin, Dname, Count) ->
    Label = escape_label(Label0),
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

%% @doc Escapes dots in a DNS label
-spec escape_label(label()) -> label().
escape_label(Label) when is_binary(Label) -> escape_label(<<>>, Label).

escape_label(Label, <<>>) -> Label;
escape_label(Cur, <<$., Rest/binary>>) ->
    escape_label(<<Cur/binary, "\\.">>, Rest);
escape_label(Cur, <<C, Rest/binary>>) -> escape_label(<<Cur/binary, C>>, Rest).

decode_dnameonly(Bin, MsgBin) ->
    case decode_dname(Bin, MsgBin) of
	{Dname, <<>>} -> Dname;
	_ -> throw(trailing_garbage)
    end.

%% @private
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

%% @doc Splits a dname into a list of labels and removes unneeded escapes.
-spec dname_to_labels(dname()) -> [label()].
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

%% @doc Joins a list of DNS labels, escaping where necessary.
-spec labels_to_dname([label()]) -> dname().
labels_to_dname(Labels) ->
    <<$., Dname/binary>> = << <<$., (escape_label(Label))/binary>>
			      || Label <- Labels >>,
    Dname.

%% @doc Returns provided name with case-insensitive characters in uppercase.
-spec dname_to_upper(dname()) -> dname().
dname_to_upper(Bin) when is_binary(Bin) ->
    << <<(dname_to_upper(C))>> || <<C>> <= Bin >>;
dname_to_upper(List) when is_list(List) ->
    [ dname_to_upper(C) || C <- List ];
dname_to_upper(Int)
  when is_integer(Int) andalso  (Int >= $a) andalso (Int =< $z) -> Int - 32;
dname_to_upper(Int) when is_integer(Int) -> Int.

%% @doc Returns provided name with case-insensitive characters in lowercase.
-spec dname_to_lower(dname()) -> dname().
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

%% @doc Returns the name of the class as a binary string.
-spec class_name(class()) -> binary() | 'undefined'.
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
-spec type_name(type()) -> binary() | 'undefined'.
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
	?DNS_TYPE_SSHFP_NUMBER -> ?DNS_TYPE_SSHFP_BSTR;
	?DNS_TYPE_IPSECKEY_NUMBER -> ?DNS_TYPE_IPSECKEY_BSTR;
	?DNS_TYPE_RRSIG_NUMBER -> ?DNS_TYPE_RRSIG_BSTR;
	?DNS_TYPE_NSEC_NUMBER -> ?DNS_TYPE_NSEC_BSTR;
	?DNS_TYPE_DNSKEY_NUMBER -> ?DNS_TYPE_DNSKEY_BSTR;
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
-spec rcode_name(rcode()) -> binary() | 'undefined'.
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
-spec opcode_name(opcode()) -> binary() | 'undefined'.
opcode_name(Int) when is_integer(Int) ->
    case Int of
	?DNS_OPCODE_QUERY_NUMBER -> ?DNS_OPCODE_QUERY_BSTR;
	?DNS_OPCODE_IQUERY_NUMBER -> ?DNS_OPCODE_IQUERY_BSTR;
	?DNS_OPCODE_STATUS_NUMBER -> ?DNS_OPCODE_STATUS_BSTR;
	?DNS_OPCODE_UPDATE_NUMBER -> ?DNS_OPCODE_UPDATE_BSTR;
	_ -> undefined
    end.

%% @doc Returns the name of a TSIG error as a binary string.
-spec tsigerr_name(tsig_error()) -> binary() | 'undefined'.
tsigerr_name(Int) when is_integer(Int) ->
    case Int of
	?DNS_TSIGERR_NOERROR_NUMBER -> ?DNS_TSIGERR_NOERROR_BSTR;
	?DNS_TSIGERR_BADSIG_NUMBER -> ?DNS_TSIGERR_BADSIG_BSTR;
	?DNS_TSIGERR_BADKEY_NUMBER -> ?DNS_TSIGERR_BADKEY_BSTR;
	?DNS_TSIGERR_BADTIME_NUMBER -> ?DNS_TSIGERR_BADTIME_BSTR;
	_ -> undefined
    end.

%% @doc Returns the name of an extended rcode as a binary string.
-spec ercode_name(ercode()) -> binary() | 'undefined'.
ercode_name(Int) when is_integer(Int) ->
    case Int of
	?DNS_ERCODE_NOERROR_NUMBER -> ?DNS_ERCODE_NOERROR_BSTR;
	?DNS_ERCODE_BADVERS_NUMBER -> ?DNS_ERCODE_BADVERS_BSTR;
	_ -> undefined
    end.

%% @doc Returns the name of an extended option as a binary string.
-spec eoptcode_name(eoptcode()) -> binary() | 'undefined'.
eoptcode_name(Int) when is_integer(Int) ->
    case Int of
	?DNS_EOPTCODE_LLQ_NUMBER -> ?DNS_EOPTCODE_LLQ_BSTR;
	?DNS_EOPTCODE_UL_NUMBER -> ?DNS_EOPTCODE_UL_BSTR;
	?DNS_EOPTCODE_NSID_NUMBER -> ?DNS_EOPTCODE_NSID_BSTR;
	?DNS_EOPTCODE_OWNER_NUMBER -> ?DNS_EOPTCODE_OWNER_BSTR;
	_ -> undefined
    end.

%% @doc Returns the name of an LLQ opcode as a binary string.
-spec llqopcode_name(llqopcode()) -> binary() | 'undefined'.
llqopcode_name(Int) when is_integer(Int) ->
    case Int of
	?DNS_LLQOPCODE_SETUP_NUMBER -> ?DNS_LLQOPCODE_SETUP_BSTR;
	?DNS_LLQOPCODE_REFRESH_NUMBER -> ?DNS_LLQOPCODE_REFRESH_BSTR;
	?DNS_LLQOPCODE_EVENT_NUMBER -> ?DNS_LLQOPCODE_EVENT_BSTR;
	_ -> undefined
    end.

%% @doc Returns the name of an LLQ error code as a binary string.
-spec llqerrcode_name(llqerrcode()) -> binary() | 'undefined'.
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
-spec alg_name(alg()) -> binary() | 'undefined'.
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
    unix_time(now()).

%% @doc Return the unix time from a now or universal time.
-spec unix_time(erlang:now() | calendar:datetime1970()) -> unix_time().
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
-spec const_compare(dname(), dname()) -> boolean().
const_compare(A, B) when is_binary(A) andalso is_binary(B) ->
    if byte_size(A) =:= byte_size(B) -> const_compare(A, B, 0);
       true -> false end.

const_compare(<<>>, <<>>, Result) -> 0 =:= Result;
const_compare(<<C1, A/binary>>, <<C2, B/binary>>, Result) ->
    const_compare(A, B, Result bor (C1 bxor C2)).

round_pow(N, E) -> round(math:pow(N, E)).

strip_leading_zeros(<<0, Rest/binary>>) ->
    strip_leading_zeros(Rest);
strip_leading_zeros(Binary) -> Binary.
