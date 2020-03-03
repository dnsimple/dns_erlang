-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("rebar_version.hrl").

%%%===================================================================
%%% Message body functions
%%%===================================================================

message_empty_test() ->
    Msg = #dns_message{},
    Bin = encode_message(Msg),
    ?assertEqual(Msg, decode_message(Bin)).

message_query_test() ->
    Qs = [#dns_query{name = <<"example">>, type = ?DNS_TYPE_A}],
    QLen = length(Qs),
    Msg = #dns_message{qc = QLen, questions = Qs},
    Bin = encode_message(Msg),
    ?assertEqual(Msg, decode_message(Bin)).

message_other_test() ->
    QName = <<"i            .txt.example.org">>,
    Qs = [#dns_query{name = QName, type = ?DNS_TYPE_TXT}],
    As = [#dns_rr{name = QName, type = ?DNS_TYPE_TXT, ttl = 0,
		  data = #dns_rrdata_txt{txt = [QName]}}],
    QLen = length(Qs),
    ALen = length(As),
    Msg = #dns_message{qc = QLen, anc = ALen, questions = Qs, answers = As},
    Bin = encode_message(Msg),
    ?assertEqual(Msg, decode_message(Bin)).

message_edns_test() ->
    QName = <<"_http._tcp.example.org">>,
    Qs = [#dns_query{name = QName, type = ?DNS_TYPE_PTR}],
    Ans = [#dns_rr{name = QName, type = ?DNS_TYPE_PTR, ttl = 42,
		   data = #dns_rrdata_ptr{
		     dname = <<"Example\ Site._http._tcp.example.org">>
		    }}],
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = 42,
		       leaselife = 7200},
	ECS = #dns_opt_ecs{family = 1,
					   source_prefix_length = 24,
					   scope_prefix_length = 0,
					   address = <<1,1,1>>},
    Ads = [#dns_optrr{udp_payload_size = 4096, ext_rcode = 0, version = 0,
		      dnssec=false, data = [LLQ, ECS]}],
    QLen = length(Qs),
    AnsLen = length(Ans),
    AdsLen = length(Ads),
    Msg = #dns_message{qc = QLen, anc = AnsLen, adc = AdsLen,
		       questions = Qs, answers = Ans, additional = Ads},
    Bin = encode_message(Msg),
    ?assertEqual(Msg, decode_message(Bin)).

tsig_no_tsig_test() ->
    MsgBin = encode_message(#dns_message{}),
    Name = <<"name">>,
    Value = <<"value">>,
    ?assertException(throw, no_tsig, verify_tsig(MsgBin, Name, Value)).

tsig_bad_key_test() ->
    MsgId = random_id(),
    B64 = <<"abcdefgh">>,
    TSIGData = #dns_rrdata_tsig{alg = ?DNS_TSIG_ALG_MD5,
				time = unix_time(),
				fudge = 0,
				mac = B64,
				msgid = MsgId,
				err = 0,
				other = <<>>
			       },
    TSIG = #dns_rr{name = <<"name_a">>, type = ?DNS_TYPE_TSIG, ttl = 0,
		   data = TSIGData},
    Msg = #dns_message{id=MsgId, adc = 1, additional=[TSIG]},
    MsgBin = encode_message(Msg),
    Result = verify_tsig(MsgBin, <<"name_b">>, B64),
    ?assertEqual({error, ?DNS_TSIGERR_BADKEY}, Result).

tsig_bad_alg_test() ->
    Id = random_id(),
    Name = <<"keyname">>,
    Data = #dns_rrdata_tsig{alg = <<"null">>, time = unix_time(), fudge = 0,
			    mac = <<"MAC">>, msgid = Id, err = 0, other = <<>>},
    RR = #dns_rr{name = Name, type = ?DNS_TYPE_TSIG, ttl = 0, data = Data},
    Msg = #dns_message{id = Id, adc = 1, additional = [RR]},
    MsgBin = encode_message(Msg),
    Result = verify_tsig(MsgBin, Name, <<"secret">>),
    ?assertEqual({error, ?DNS_TSIGERR_BADKEY}, Result).

tsig_bad_sig_test() ->
    application:start(crypto),
    MsgId = random_id(),
    Name = <<"keyname">>,
    Value = crypto:strong_rand_bytes(20),
    Msg = #dns_message{id = MsgId},
    SignedMsg = add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Value, 0),
    [#dns_rr{data = TSIGData} = TSIG] = SignedMsg#dns_message.additional,
    BadTSIG = TSIG#dns_rr{data = TSIGData#dns_rrdata_tsig{mac = Value}},
    BadSignedMsg = Msg#dns_message{adc = 1, additional = [BadTSIG]},
    BadSignedMsgBin = encode_message(BadSignedMsg),
    Result = verify_tsig(BadSignedMsgBin, Name, Value),
    ?assertEqual({error, ?DNS_TSIGERR_BADSIG}, Result).

tsig_badtime_test_() ->
    application:start(crypto),
    MsgId = random_id(),
    Name = <<"keyname">>,
    Secret = crypto:strong_rand_bytes(20),
    Msg = #dns_message{id=MsgId},
    Fudge = 30,
    SignedMsg = add_tsig(Msg, ?DNS_TSIG_ALG_MD5, Name, Secret, 0),
    SignedMsgBin = encode_message(SignedMsg),
    Now = unix_time(),
    [ ?_test(
	 begin
	     BadNow = Now + (Throwoff * Fudge),
	     Options = [{fudge, 30}, {time, BadNow}],
	     Result = verify_tsig(SignedMsgBin, Name, Secret, Options),
	     ?assertEqual({error, ?DNS_TSIGERR_BADTIME}, Result)
	 end
	) || Throwoff <- [ -2, 2 ] ].

tsig_ok_test_() ->
    application:start(crypto),
    MsgId = random_id(),
    Name = <<"keyname">>,
    Secret = crypto:strong_rand_bytes(20),
    Algs = [ ?DNS_TSIG_ALG_MD5, ?DNS_TSIG_ALG_SHA1, ?DNS_TSIG_ALG_SHA224,
	     ?DNS_TSIG_ALG_SHA256, ?DNS_TSIG_ALG_SHA384, ?DNS_TSIG_ALG_SHA512 ],
    Msg = #dns_message{id=MsgId},
    Options = [{time, unix_time()}, {fudge, 30}],
    [ {Alg,
       ?_test(
	  begin
	      SignedMsg = add_tsig(Msg, Alg, Name, Secret, 0),
	      SignedMsgBin = encode_message(SignedMsg),
	      Result = case verify_tsig(SignedMsgBin, Name, Secret, Options) of
			   {ok, _MAC} -> ok;
			   Error -> Error
		       end,
	      ?assertEqual(ok, Result)
	  end
	 )} || Alg <- Algs ].

tsig_wire_test_() ->
    application:start(crypto),
    Now = 1292459455,
    Keyname = <<"key.name">>,
    Secret = base64:decode(<<"8F1BRL+xp3gNW1GfbSnlUuvUtxQ=">>),
    {ok, Cases} = file:consult(filename:join(prefix(), "tsig_wire_samples.txt")),
    [ {Alg,
       ?_test(
	  begin
	      Result = case verify_tsig(Msg, Keyname, Secret, [{time, Now}]) of
			   {ok, MAC} when is_binary(MAC) -> ok;
			   X -> X
		       end,
	      ?assertEqual(ok, Result)
	  end
	 )} || {Alg, Msg} <- Cases ].

%%%===================================================================
%%% Record data functions
%%%===================================================================

decode_encode_rrdata_wire_samples_test_() ->
    {ok, Cases} = file:consult(filename:join(prefix(), "rrdata_wire_samples.txt")),
    ToTestName = fun({Class, Type, Bin}) ->
			 Fmt = "~p/~p/~n~p",
			 Args = [Class, Type, Bin],
			 lists:flatten(io_lib:format(Fmt, Args))
		 end,
    [ {ToTestName(Case),
       ?_test(
	  begin
	      NewBin = case decode_rrdata(Class, Type, TestBin, TestBin) of
			   TestBin when Type =:= 999 -> TestBin;
			   TestBin -> throw(not_decoded);
			   Record ->
			       {Bin, _} = encode_rrdata(0, Class, Record,
							gb_trees:empty()),
			       Bin
		       end,
	      ?assertEqual(TestBin, NewBin)
	  end
	 )} || {Class, Type, TestBin} = Case <- Cases ].

decode_encode_rrdata_test_() ->
    %% For testing records that don't have wire samples
    Cases = [ {?DNS_TYPE_MB, #dns_rrdata_mb{madname = <<"example.com">>}},
	      {?DNS_TYPE_MG, #dns_rrdata_mg{madname = <<"example.com">>}},
	      {?DNS_TYPE_MINFO, #dns_rrdata_minfo{rmailbx = <<"a.b">>,
						  emailbx = <<"c.d">>}},
	      {?DNS_TYPE_MR, #dns_rrdata_mr{newname = <<"example.com">>}},
              {?DNS_TYPE_CAA, #dns_rrdata_caa{flags = 0, tag = <<"issue">>, value = <<"letsencrypt.org">>}}
            ],
    [ ?_test(
	 begin
	     {Encoded, _NewCompMap} = encode_rrdata(0, ?DNS_CLASS_IN, Data,
						    gb_trees:empty()),
	     Decoded = decode_rrdata(?DNS_CLASS_IN, Type, Encoded, Encoded),
	     ?assertEqual(Data, Decoded)
	 end
	)
      || {Type, Data} <- Cases ].

%%%===================================================================
%%% EDNS data functions
%%%===================================================================

decode_encode_optdata_test_() ->
    Cases = [ #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
			   errorcode = ?DNS_LLQERRCODE_NOERROR,
			   id = 123,
			   leaselife = 456},
	      #dns_opt_ul{lease = 789},
	      #dns_opt_nsid{data = <<"hi">>},
		  #dns_opt_ecs{family = 1,
					   source_prefix_length = 24,
					   scope_prefix_length = 0,
					   address = <<1,1,1>>},
	      #dns_opt_unknown{id = 999, bin = <<"hi">>} ],
    [ ?_assertEqual([Case], decode_optrrdata(encode_optrrdata([Case])))
      || Case <- Cases ].

decode_encode_optdata_owner_test_() ->
    application:start(crypto),
    Cases = [ #dns_opt_owner{seq = rand:uniform(255),
			     primary_mac = crypto:strong_rand_bytes(6),
			     wakeup_mac = crypto:strong_rand_bytes(6),
			     password = crypto:strong_rand_bytes(6)},
	      #dns_opt_owner{seq = rand:uniform(255),
			     primary_mac = crypto:strong_rand_bytes(6),
			     wakeup_mac = crypto:strong_rand_bytes(6),
			     password = crypto:strong_rand_bytes(4)},
	      #dns_opt_owner{seq = rand:uniform(255),
			     primary_mac = crypto:strong_rand_bytes(6),
			     wakeup_mac = crypto:strong_rand_bytes(6),
			     _ = <<>>},
	      #dns_opt_owner{seq = rand:uniform(255),
			     primary_mac = crypto:strong_rand_bytes(6),
			     _ = <<>>} ],
    [ ?_assertEqual([Case], decode_optrrdata(encode_optrrdata([Case])))
      || Case <- Cases ].

%%%===================================================================
%%% Domain name functions
%%%===================================================================

decode_dname_2_ptr_test_() ->
    Cases = [ {<<7,101,120,97,109,112,108,101,0>>, <<3:2, 0:14>>} ],
    [ ?_assertEqual({<<"example">>, <<>>}, decode_dname(DataBin, MsgBin))
      || {MsgBin, DataBin} <- Cases ].

decode_dname_decode_loop_test() ->
    Bin = <<3:2, 0:14>>,
    ?assertException(throw, decode_loop, decode_dname(Bin, Bin)).

decode_dname_bad_pointer_test() ->
    Case = <<3:2, 42:14>>,
    ?assertException(throw, bad_pointer, decode_dname(Case, Case)).

encode_dname_1_test_() ->
    Cases = [ {"example", <<7,101,120,97,109,112,108,101,0>>},
	      {<<"example">>, <<7,101,120,97,109,112,108,101,0>>} ],
    [ ?_assertEqual(Expect, encode_dname(Input)) || {Input, Expect} <- Cases ].

encode_dname_3_test_() ->
    {Bin, _CompMap} = encode_dname(gb_trees:empty(), 0, <<"example">>),
    ?_assertEqual(<<7,101,120,97,109,112,108,101,0>>, Bin).

encode_dname_4_test_() ->
    {Bin0, CM0} = encode_dname(<<>>, gb_trees:empty(), 0, <<"example">>),
    {Bin1, _} = encode_dname(Bin0, CM0, byte_size(Bin0), <<"example">>),
    {Bin2, _} = encode_dname(Bin0, CM0, byte_size(Bin0), <<"EXAMPLE">>),
    MP = (1 bsl 14),
    MPB = <<0:MP/unit:8>>,
    {_, CM1} = encode_dname(MPB, gb_trees:empty(), MP, <<"example">>),
    Cases = [ {<<7,101,120,97,109,112,108,101,0>>, Bin0},
	      {<<7,101,120,97,109,112,108,101,0,192,0>>, Bin1},
	      {Bin1, Bin2},
	      {gb_trees:empty(), CM1}
	    ],
    [ ?_assertEqual(Expect, Result) || {Expect, Result} <- Cases ].

dname_to_labels_test_() ->
    Cases = [ {"", []}, {".", []}, {<<>>, []}, {<<".">>, []},
	      {"a.b.c", [<<"a">>, <<"b">>, <<"c">>]},
	      {<<"a.b.c">>, [<<"a">>, <<"b">>, <<"c">>]},
	      {"a.b.c.", [<<"a">>, <<"b">>, <<"c">>]},
	      {<<"a.b.c.">>, [<<"a">>, <<"b">>, <<"c">>]},
	      {"a\\.b.c", [<<"a.b">>, <<"c">>]},
	      {<<"a\\.b.c">>, [<<"a.b">>, <<"c">>]} ],
    [ ?_assertEqual(Expect, dname_to_labels(Arg)) || {Arg, Expect} <- Cases ].

labels_to_dname_test_() ->
    Cases = [{[<<"a">>, <<"b">>, <<"c">>], <<"a.b.c">>},
	     {[<<"a.b">>, <<"c">>], <<"a\\.b.c">>}],
    [ ?_assertEqual(Expect, labels_to_dname(Arg)) || {Arg, Expect} <- Cases ].

dname_to_upper_test_() ->
    Cases = [ {"Y", "Y"}, {"y", "Y"}, {<<"Y">>, <<"Y">>}, {<<"y">>, <<"Y">>} ],
    [ ?_assertEqual(Expect, dname_to_upper(Arg)) || {Arg, Expect} <-  Cases ].

dname_to_lower_test_() ->
    Cases = [ {"Y", "y"}, {"y", "y"}, {<<"Y">>, <<"y">>}, {<<"y">>, <<"y">>} ],
    [ ?_assertEqual(Expect, dname_to_lower(Arg)) || {Arg, Expect} <-  Cases ].

dname_preserve_dot_test_() ->
    Query = #dns_query{name = <<"example\\.com">>, class = 1, type = 1},
    Message =#dns_message{qc = 1, questions = [Query]},
    Encoded = dns:encode_message(Message),
    Decoded = dns:decode_message(Encoded),
    ReEncoded = dns:encode_message(Decoded),
    ReDecoded = dns:decode_message(ReEncoded),
    [ ?_assertEqual(Message, Decoded),
      ?_assertEqual(Encoded, ReEncoded),
      ?_assertEqual(Message, ReDecoded)].

%%%===================================================================
%%% Term functions
%%%===================================================================

class_name_test_() ->
    {ok, Cases} = file:consult(filename:join(prefix(), "rrdata_wire_samples.txt")),
    Classes = sets:to_list(sets:from_list([ C || {C,_,_} <- Cases ])),
    [ ?_assertEqual(true, is_binary(dns:class_name(C))) || C <- Classes ].

type_name_test_() ->
    {ok, Cases} = file:consult(filename:join(prefix(), "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([ T || {_,T,_} <- Cases ])),
    [ ?_assertEqual(T =/= 999, is_binary(dns:type_name(T))) || T <- Types ].

alg_terms_test_() ->
    Cases = [ ?DNS_ALG_DSA, ?DNS_ALG_NSEC3DSA, ?DNS_ALG_RSASHA1,
	      ?DNS_ALG_NSEC3RSASHA1, ?DNS_ALG_RSASHA256, ?DNS_ALG_RSASHA512 ],
    [ ?_assertEqual(true, is_binary(dns:alg_name(Alg))) || Alg <- Cases ].

%%%===================================================================

-endif.
