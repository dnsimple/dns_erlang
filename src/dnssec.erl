%% -------------------------------------------------------------------
%%
%% Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.
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
-module(dnssec).

%% API
-export([gen_nsec/1, gen_nsec/3, gen_nsec/4]).
-export([gen_nsec3/1, gen_nsec3/6, gen_nsec3/7]).
-export([sign_rr/5, sign_rr/6]).
-export([sign_rrset/5, sign_rrset/6]).
-export([verify_rrsig/4]).
-export([add_keytag_to_dnskey/1, add_keytag_to_cdnskey/1]).
-export([canonical_rrdata_form/1]).
-export([ih/4]).

-include("dns.hrl").
-include("DNS-ASN1.hrl").

-export_type([sigalg/0, nsec3_hashalg/0, nsec3_salt/0, nsec3_iterations/0,
	      keytag/0, key/0]).
%% this isn't a redefinition of dns:alg() - the algorithms here may only be used
%% for signing zones. dns:alg() may contain other algorithms.
-type sigalg() :: ?DNS_ALG_DSA | ?DNS_ALG_NSEC3DSA|
		  ?DNS_ALG_RSASHA1 | ?DNS_ALG_NSEC3RSASHA1 |
		  ?DNS_ALG_RSASHA256 | ?DNS_ALG_RSASHA512.
-type nsec3_hashalg() :: ?DNSSEC_NSEC3_ALG_SHA1.
-type nsec3_salt() :: binary().
-type nsec3_iterations() :: non_neg_integer().
-type gen_nsec_opt() :: {'base_types', [dns:type()]}.
-type gen_nsec3_opt() :: gen_nsec_opt().
-type keytag() :: integer().
-type key() :: [binary()].
-type sign_rr_opt() :: {'inception' | 'expiration', dns:unix_time()}.
-type verify_rrsig_opt() :: {'now', dns:unix_time()}.

-include("dnssec_tests.hrl").

-define(RSASHA1_PREFIX, <<16#30, 16#21, 16#30, 16#09, 16#06, 16#05, 16#2B,
			  16#0E, 16#03, 16#02, 16#1A, 16#05, 16#00, 16#04,
			  16#14>>).
-define(RSASHA256_PREFIX, <<16#30, 16#31, 16#30, 16#0d, 16#06, 16#09, 16#60,
			    16#86, 16#48, 16#01, 16#65, 16#03, 16#04, 16#02,
			    16#01, 16#05, 16#00, 16#04, 16#20>>).
-define(RSASHA512_PREFIX, <<16#30, 16#51, 16#30, 16#0d, 16#06, 16#09, 16#60,
			    16#86, 16#48, 16#01, 16#65, 16#03, 16#04, 16#02,
			    16#03, 16#05, 16#00, 16#04, 16#40 >>).

%% @doc Generate NSEC records from a list of #dns_rr{}.
%%      The list must contain a SOA #dns_rr{} which is used to determine
%%      zone name and TTL.
-spec gen_nsec([dns:rr()]) -> [dns:rr()].
gen_nsec(RR) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RR) of
	false -> erlang:error(badarg);
	#dns_rr{name = ZoneName, data = #dns_rrdata_soa{minimum = TTL }} ->
	    gen_nsec(ZoneName, RR, TTL)
    end.

%% @equiv gen_nsec(ZoneName, RR, TTL, [])
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl()) -> [dns:rr()].
gen_nsec(ZoneName, RR, TTL) ->
    gen_nsec(ZoneName, RR, TTL, []).

%% @doc Generate NSEC records.
-spec gen_nsec(dns:dname(), [dns:rr()], dns:ttl(), [gen_nsec_opt()]) ->
		      [dns:rr()].
gen_nsec(ZoneNameM, RR, TTL, Opts) ->
    ZoneName = normalise_dname(ZoneNameM),
    BaseTypes = proplists:get_value(base_types, Opts, [?DNS_TYPE_NSEC,
						       ?DNS_TYPE_RRSIG]),
    Map = build_rrmap(RR, BaseTypes),
    Unsorted = [ #dns_rr{name = Name, class = Class, type = ?DNS_TYPE_NSEC,
			 ttl = TTL, data = #dns_rrdata_nsec{types = Types}}
		 || {{Name, Class}, Types} <- Map ],
    Sorted = name_order(Unsorted),
    add_next_dname(Sorted, ZoneName).

add_next_dname(RR, ZoneName) -> add_next_dname([], RR, ZoneName).

add_next_dname(Added, [#dns_rr{data = Data} = RR|
		       [#dns_rr{name = Next}|_] = ToAdd], ZoneName) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec{next_dname = Next}},
    NewAdded = [NewRR|Added],
    add_next_dname(NewAdded, ToAdd, ZoneName);
add_next_dname(Added, [#dns_rr{type = ?DNS_TYPE_NSEC, data = Data}=RR],
	       ZoneName) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec{next_dname = ZoneName}},
    lists:reverse([NewRR|Added]).

%% @doc Generate NSEC3 records from a list of #dns_rr{}.
%%      The list must contain a SOA #dns_rr{} to source the zone name and
%%      TTL from as well as as an NSEC3Param #dns_rr{} to source the
%%      hash algorithm, iterations and salt from.
-spec gen_nsec3([dns:rr()]) -> [dns:rr()].
gen_nsec3(RRs) ->
    case lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, RRs) of
	false -> erlang:error(badarg);
	#dns_rr{name = ZoneName, data = #dns_rrdata_soa{minimum = TTL}} ->
	    case lists:keyfind(?DNS_TYPE_NSEC3PARAM, #dns_rr.type, RRs) of
		false -> erlang:error(badarg);
		#dns_rr{class = Class,
			data = #dns_rrdata_nsec3param{
			  hash_alg = HashAlg,
			  iterations = Iter,
			  salt = Salt}} ->
		    gen_nsec3(RRs, ZoneName, HashAlg, Salt, Iter, TTL, Class)
	    end
    end.

%% @equiv gen_nsec3(RR, ZoneName, Alg, Salt, Iterations, TTL, in, [])
-spec gen_nsec3([dns:rr()], dns:dname(), nsec3_hashalg(), nsec3_salt(),
		nsec3_iterations(), dns:ttl()) -> [dns:rr()].
gen_nsec3(RR, ZoneName, Alg, Salt, Iterations, TTL) ->
    gen_nsec3(RR, ZoneName, Alg, Salt, Iterations, TTL, ?DNS_CLASS_IN, []).

%% @equiv gen_nsec3(RRs, ZoneName, Alg, Salt, Iterations, TTL, Class, [])
-spec gen_nsec3([dns:rr()], dns:dname(), nsec3_hashalg(), nsec3_salt(),
		nsec3_iterations(), dns:ttl(), dns:class()) -> [dns:rr()].
gen_nsec3(RRs, ZoneName, Alg, Salt, Iterations, TTL, Class) ->
    gen_nsec3(RRs, ZoneName, Alg, Salt, Iterations, TTL, Class, []).

%% @doc Generate NSEC3 records.
-spec gen_nsec3([dns:rr()], dns:dname(), nsec3_hashalg(), nsec3_salt(),
		nsec3_iterations(), dns:ttl(), dns:class(), [gen_nsec3_opt()]
	       ) -> [dns:rr()].
gen_nsec3(RRs, ZoneName, Alg, Salt, Iterations, TTL, Class, Opts) ->
    BaseTypes = proplists:get_value(base_types, Opts, [?DNS_TYPE_RRSIG]),
    Map = build_rrmap(RRs, BaseTypes, ZoneName),
    Unsorted = lists:foldl(
		 fun({{Name, SClass}, Types}, Acc) when SClass =:= Class ->
			 DName = dns:encode_dname(Name),
			 HashedName = ih(Alg, Salt, DName, Iterations),
			 HexdHashName = base32:encode(HashedName, [hex,nopad]),
			 NewName = <<HexdHashName/binary, $., ZoneName/binary>>,
			 Data = #dns_rrdata_nsec3{hash_alg = Alg,
						  opt_out = false,
						  iterations = Iterations,
						  salt = Salt,
						  hash = HashedName,
						  types = Types},
			 NewRR = #dns_rr{name = NewName, class = Class,
					 type = ?DNS_TYPE_NSEC3, ttl = TTL,
					 data = Data},
			 [{HashedName, NewRR}|Acc];
		    (_, Acc) -> Acc
		 end, [], Map),
    Sorted = [ RR || {_, RR} <- lists:keysort(1, Unsorted) ],
    add_next_hash(Sorted).

%% @doc NSEC3 iterative hash function
-spec ih(nsec3_hashalg() | fun((binary()) -> binary()), nsec3_salt(), binary(),
	 non_neg_integer()) -> binary().
ih(H, Salt, X, 0) when is_function(H, 1) -> H([X, Salt]);
ih(H, Salt, X, I) when is_function(H, 1) -> ih(H, Salt, H([X, Salt]), I - 1);
ih(?DNSSEC_NSEC3_ALG_SHA1, Salt, X, I) -> ih(fun (Data) -> crypto:hash(sha, Data) end, Salt, X, I).

add_next_hash([#dns_rr{data = #dns_rrdata_nsec3{hash = First}}|_] = Hashes) ->
    add_next_hash(Hashes, [], First).

add_next_hash([#dns_rr{data = Data} = RR], RRs, FirstHash) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec3{hash = FirstHash}},
    lists:reverse([NewRR|RRs]);
add_next_hash([#dns_rr{data = Data} = RR|
	       [#dns_rr{data = #dns_rrdata_nsec3{hash = NextHash}}|_] = Hashes],
	      RRs, FirstHash) ->
    NewRR = RR#dns_rr{data = Data#dns_rrdata_nsec3{hash = NextHash}},
    add_next_hash(Hashes, [NewRR|RRs], FirstHash).

normalise_rr(#dns_rr{name = Name} = RR) ->
    RR#dns_rr{name = dns:dname_to_lower(Name)}.

build_rrmap(RR, BaseTypes) ->
    Base = build_rrmap_gbt(RR, BaseTypes),
    gb_trees:to_list(Base).

build_rrmap(RR, BaseTypes, ZoneName) ->
    Base = build_rrmap_gbt(RR, BaseTypes),
    WithNonTerm = build_rrmap_nonterm(ZoneName, gb_trees:keys(Base), Base),
    gb_trees:to_list(WithNonTerm).

build_rrmap_nonterm(_, [], GBT) -> GBT;
build_rrmap_nonterm(ZoneName, [{Name, Class}|Rest], GBT)
  when is_binary(ZoneName) ->
    NameAncs = name_ancestors(Name, ZoneName),
    NewGBT = build_rrmap_nonterm(Class, NameAncs, GBT),
    build_rrmap_nonterm(ZoneName, Rest, NewGBT);
build_rrmap_nonterm(Class, [Name|Rest], GBT) ->
    Key = {Name, Class},
    case gb_trees:is_defined(Key, GBT) of
	true -> GBT;
	false ->
	    NewGBT = gb_trees:insert(Key, [], GBT),
	    build_rrmap_nonterm(Class, Rest, NewGBT)
    end.

build_rrmap_gbt(RR, BaseTypes) ->
    build_rrmap_gbt(RR, BaseTypes, gb_trees:empty()).

build_rrmap_gbt([], _BaseTypes, GBT) -> GBT;
build_rrmap_gbt([#dns_rr{} = RR|Rest], BaseTypes, GBT) ->
    #dns_rr{name = Name, class = Class, type = Type} = normalise_rr(RR),
    Key = {Name, Class},
    NewGBT = case gb_trees:lookup(Key, GBT) of
		 {value, Types} ->
		     case lists:member(Type, Types) of
			 true -> GBT;
			 false -> gb_trees:update(Key, [Type|Types], GBT)
		     end;
		 none ->
		     Types = [Type|BaseTypes],
		     gb_trees:insert(Key, Types, GBT)
	     end,
    build_rrmap_gbt(Rest, BaseTypes, NewGBT).

rrs_to_rrsets(RR) when is_list(RR) ->
    rrs_to_rrsets(gb_trees:empty(), dict:new(), RR).

rrs_to_rrsets(TTLMap, RRSets, []) ->
    [ rrs_to_rrsets(TTLMap, RRSet) || RRSet <- dict:to_list(RRSets) ];
rrs_to_rrsets(TTLMap, RRSets, [#dns_rr{} = RR | RRs]) ->
    #dns_rr{name = Name,
	    class = Class,
	    type = Type,
	    ttl = TTL,
	    data = Data} = normalise_rr(RR),
    Key = {Name, Class, Type},
    NewTTLMap = case gb_trees:lookup(Key, TTLMap) of
		    {value, LowerTTL} when LowerTTL =< TTL ->
			TTLMap;
		    {value, _LargerTTL} ->
			gb_trees:update(Key, TTL, TTLMap);
		    none ->
			gb_trees:insert(Key, TTL, TTLMap)
		end,
    NewRRSets = dict:append(Key, Data, RRSets),
    rrs_to_rrsets(NewTTLMap, NewRRSets, RRs).

rrs_to_rrsets(TTLMap, {{Name, Class, Type} = Key, Datas}) ->
    {value, TTL} = gb_trees:lookup(Key, TTLMap),
    [ #dns_rr{name = Name,
	      class = Class,
	      type = Type,
	      ttl = TTL,
	      data = Data} || Data <- Datas ].

%% @equiv sign_rr(RR, SignerName, KeyTag, Alg, Key, [])
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key()) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key) ->
    sign_rr(RR, SignerName, KeyTag, Alg, Key, []).

%% @doc Signs a list of #dns_rr{}.
-spec sign_rr([dns:rr()], dns:dname(), keytag(), sigalg(), key(),
	      [sign_rr_opt()]) -> [dns:rr()].
sign_rr(RR, SignerName, KeyTag, Alg, Key, Opts) when is_list(Opts) ->
    RRSets = rrs_to_rrsets(RR),
    [ sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, Opts)
      || RRSet <- RRSets ].

%% @equiv sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, [])
-spec sign_rrset([dns:rr(),...], dns:dname(), keytag(), sigalg(), key()) ->
			dns:rr().
sign_rrset(RRSet, SignerName, KeyTag, Alg, Key) ->
    sign_rrset(RRSet, SignerName, KeyTag, Alg, Key, []).

%% @doc Signs a list of #dns_rr{} of the same class and type.
-spec sign_rrset([dns:rr(),...], dns:dname(), keytag(), sigalg(), key(),
		 [sign_rr_opt()]) -> dns:rr().
sign_rrset([#dns_rr{name = Name, class = Class, ttl = TTL}|_] = RRs,
	   SignersName, KeyTag, Alg, Key, Opts) when is_integer(Alg) ->
    Now = dns:unix_time(),
    Incept = proplists:get_value(inception, Opts, Now),
    Expire = proplists:get_value(expiration, Opts, Now + (365 * 24 * 60 * 60)),
    {Data0, BaseSigInput} = build_sig_input(SignersName, KeyTag, Alg, Incept,
					    Expire, RRs),
    Signature = case Alg of
		    Alg when Alg =:= ?DNS_ALG_DSA orelse
			     Alg =:= ?DNS_ALG_NSEC3DSA ->
			Asn1Sig = crypto:sign(dss, sha, BaseSigInput, Key),
			{R, S} = decode_asn1_dss_sig(Asn1Sig),
			[ P, _Q, _G, _Y ] = Key,
			T = (byte_size(P) - 64) div 8,
			<<T, R:20/unit:8, S:20/unit:8>>;
		    Alg when Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
			     Alg =:= ?DNS_ALG_RSASHA1 orelse
			     Alg =:= ?DNS_ALG_RSASHA256 orelse
			     Alg =:= ?DNS_ALG_RSASHA512 ->
			crypto:private_encrypt(rsa, BaseSigInput, Key,
						rsa_pkcs1_padding)
		end,
    Data = Data0#dns_rrdata_rrsig{signature = Signature},
    #dns_rr{name = Name, type = ?DNS_TYPE_RRSIG, class = Class, ttl = TTL,
	    data = Data}.

%% @doc Provides primitive verification of an RR set.
-spec verify_rrsig(dns:rr(), [dns:rr()], [dns:rr()], [verify_rrsig_opt()]
		  ) -> boolean().
verify_rrsig(#dns_rr{type = ?DNS_TYPE_RRSIG, data = Data}, RRs, RRDNSKey,
	     Opts) ->
    Now = proplists:get_value(now, Opts, dns:unix_time()),
    #dns_rrdata_rrsig{original_ttl = OTTL,
		      key_tag = SigKeyTag,
		      alg = SigAlg,
		      inception = Incept,
		      expiration = Expire,
		      signers_name = SignersName,
		      signature = Sig} = Data,
    Keys0 = [ {KeyTag, Alg, PubKey}
	      || #dns_rr{name = Name,
			 type = ?DNS_TYPE_DNSKEY,
			 data = #dns_rrdata_dnskey{
			   protocol = 3,
			   alg = Alg,
			   key_tag = KeyTag,
			   public_key = PubKey
			 }} <- RRDNSKey,
		 Alg =:= SigAlg,
		 normalise_dname(Name) =:= normalise_dname(SignersName)
	    ],
    Keys = case lists:keytake(SigKeyTag, 1, Keys0) of
	       false -> Keys0;
	       {value, Match, RemKeys} -> [Match|RemKeys]
	   end,
    case Now of
	Now when Incept > Now -> false;
	Now when Expire < Now -> false;
	Now ->
	    {_SigTuple, SigInput} = build_sig_input(SignersName, SigKeyTag,
						    SigAlg, Incept, Expire,
						    RRs, OTTL),
	    lists:any(
	      fun({_, Alg, Key})
		    when Alg =:= ?DNS_ALG_DSA orelse
			 Alg =:= ?DNS_ALG_NSEC3DSA ->
		      <<_T, R:20/unit:8, S:20/unit:8>> = Sig,
		      AsnSig = encode_asn1_dss_sig(R, S),
		      AsnSigSize = byte_size(AsnSig),
		      AsnBin = <<AsnSigSize:32, AsnSig/binary>>,
		      crypto:verify(dss, sha, SigInput, AsnBin, Key);
		 ({_, Alg, Key})
		    when Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
			 Alg =:= ?DNS_ALG_RSASHA1 orelse
			 Alg =:= ?DNS_ALG_RSASHA256 orelse
			 Alg =:= ?DNS_ALG_RSASHA512 ->
		      SigPayload = try crypto:public_decrypt(
					 rsa, Sig, Key, rsa_pkcs1_padding)
				   catch error:decrypt_failed -> undefined end,
		      SigInput =:= SigPayload;
		 (_) -> false
	      end, Keys)
    end.

build_sig_input(SignersName, KeyTag, Alg, Incept, Expire,
		[#dns_rr{ttl = TTL}|_] = RRs) ->
    build_sig_input(SignersName, KeyTag, Alg, Incept, Expire, RRs, TTL).

build_sig_input(SignersName, KeyTag, Alg, Incept, Expire,
		[#dns_rr{name = Name,
			 class = Class,
			 type = Type,
			 ttl = TTL}|_] = RRs, TTL) when is_integer(Alg) ->
    Datas = lists:sort([ canonical_rrdata_bin(RR) ||RR <- RRs ]),
    NameBin = dns:encode_dname(dns:dname_to_lower(Name)),
    RecordBase = <<NameBin/binary, Type:16, Class:16, TTL:32>>,
    RRSetBin = [  <<RecordBase/binary, (byte_size(Data)):16, Data/binary>>
		      || Data <- Datas ],
    RRSigData0 = #dns_rrdata_rrsig{type_covered = Type,
				   alg = Alg,
				   labels = count_labels(Name),
				   original_ttl = TTL,
				   inception = Incept,
				   expiration = Expire,
				   key_tag = KeyTag,
				   signers_name = SignersName},
    RRSigRDataBin = rrsig_to_digestable(RRSigData0),
    SigInput0 = [RRSigRDataBin, RRSetBin],
    case Alg of
        Alg when Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA ->
            SigInput1 = iolist_to_binary(SigInput0),
            SigInput1Size = byte_size(SigInput1),
            {RRSigData0, <<SigInput1Size:32, SigInput1/binary>>};
        _ ->
            {Prefix, HashType} = case Alg of
                                     ?DNS_ALG_RSASHA1 ->
                                         {?RSASHA1_PREFIX, sha};
                                     ?DNS_ALG_NSEC3RSASHA1 ->
                                         {?RSASHA1_PREFIX, sha};
                                     ?DNS_ALG_RSASHA256 ->
                                         {?RSASHA256_PREFIX, sha256};
                                     ?DNS_ALG_RSASHA512 ->
                                         {?RSASHA512_PREFIX, sha512}
                                 end,
            Hash = crypto:hash(HashType, SigInput0),
            {RRSigData0, <<Prefix/binary, Hash/binary>>}
    end.

%% @doc Generates and appends a DNS Key records key tag.
-spec add_keytag_to_dnskey(dns:rr()) -> dns:rr().
add_keytag_to_dnskey(#dns_rr{type = ?DNS_TYPE_DNSKEY,
			     data = #dns_rrdata_dnskey{} = Data} = RR) ->
    KeyBin = dns:encode_rrdata(in, Data),
    NewData = dns:decode_rrdata(?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, KeyBin),
    RR#dns_rr{data = NewData}.

-spec add_keytag_to_cdnskey(dns:rr()) -> dns:rr().
add_keytag_to_cdnskey(#dns_rr{type = ?DNS_TYPE_CDNSKEY,
			     data = #dns_rrdata_cdnskey{} = Data} = RR) ->
    KeyBin = dns:encode_rrdata(in, Data),
    NewData = dns:decode_rrdata(?DNS_CLASS_IN, ?DNS_TYPE_CDNSKEY, KeyBin),
    RR#dns_rr{data = NewData}.

rrsig_to_digestable(#dns_rrdata_rrsig{} = Data) ->
    dns:encode_rrdata(?DNS_CLASS_IN, Data#dns_rrdata_rrsig{signature = <<>>}).

canonical_rrdata_bin(#dns_rr{class = Class, data = Data0}) ->
    dns:encode_rrdata(Class, canonical_rrdata_form(Data0)).

%% @doc Converts a resource record data record to DNSSEC canonical form.
-spec canonical_rrdata_form(dns:rrdata()) -> dns:rrdata().
canonical_rrdata_form(#dns_rrdata_afsdb{hostname = Hostname} = Data) ->
    Data#dns_rrdata_afsdb{hostname = dns:dname_to_lower(Hostname)};
canonical_rrdata_form(#dns_rrdata_cname{dname = Dname} = Data) ->
    Data#dns_rrdata_cname{dname = dns:dname_to_lower(Dname) };
canonical_rrdata_form(#dns_rrdata_dname{dname = Dname} = Data) ->
    Data#dns_rrdata_dname{dname = dns:dname_to_lower(Dname)};
canonical_rrdata_form(#dns_rrdata_kx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_kx{exchange = dns:dname_to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_mb{madname = MaDname} = Data) ->
    Data#dns_rrdata_mb{madname = dns:dname_to_lower(MaDname) };
canonical_rrdata_form(#dns_rrdata_mg{madname = MaDname} = Data) ->
    Data#dns_rrdata_mg{madname = dns:dname_to_lower(MaDname) };
canonical_rrdata_form(#dns_rrdata_minfo{rmailbx = RmailBx,
				 emailbx = EmailBx} = Data) ->
    Data#dns_rrdata_minfo{rmailbx = dns:dname_to_lower(RmailBx),
			  emailbx = dns:dname_to_lower(EmailBx)};
canonical_rrdata_form(#dns_rrdata_mr{newname = NewName} = Data) ->
    Data#dns_rrdata_mr{newname = dns:dname_to_lower(NewName) };
canonical_rrdata_form(#dns_rrdata_mx{exchange = Exchange} = Data) ->
    Data#dns_rrdata_mx{exchange = dns:dname_to_lower(Exchange)};
canonical_rrdata_form(#dns_rrdata_naptr{replacement = Replacement} = Data) ->
    Data#dns_rrdata_naptr{replacement = dns:dname_to_lower(Replacement)};
canonical_rrdata_form(#dns_rrdata_ns{dname = Dname} = Data) ->
    Data#dns_rrdata_ns{dname = dns:dname_to_lower(Dname)};
canonical_rrdata_form(#dns_rrdata_nsec{next_dname = NextDname} = Data) ->
    Data#dns_rrdata_nsec{next_dname = dns:dname_to_lower(NextDname)};
canonical_rrdata_form(#dns_rrdata_nxt{dname = Dname} = Data) ->
    Data#dns_rrdata_nxt{dname = dns:dname_to_lower(Dname)};
canonical_rrdata_form(#dns_rrdata_ptr{dname = Dname} = Data) ->
    Data#dns_rrdata_ptr{dname = dns:dname_to_lower(Dname) };
canonical_rrdata_form(#dns_rrdata_rp{mbox = Mbox, txt = Txt} = Data) ->
    Data#dns_rrdata_rp{mbox = dns:dname_to_lower(Mbox),
		       txt = dns:dname_to_lower(Txt)};
canonical_rrdata_form(#dns_rrdata_rrsig{signers_name = SignersName} = Data) ->
    Data#dns_rrdata_rrsig{signers_name = dns:dname_to_lower(SignersName)};
canonical_rrdata_form(#dns_rrdata_rt{host = Host} = Data) ->
    Data#dns_rrdata_rt{host = dns:dname_to_lower(Host)};
canonical_rrdata_form(#dns_rrdata_soa{mname = Mname, rname = Rname} = Data) ->
    Data#dns_rrdata_soa{mname = dns:dname_to_lower(Mname),
			rname = dns:dname_to_lower(Rname)};
canonical_rrdata_form(#dns_rrdata_srv{target = Target} = Data) ->
    Data#dns_rrdata_srv{target = dns:dname_to_lower(Target)};
canonical_rrdata_form(X) -> X.

name_ancestors(Name, ZoneName) ->
    NameLwr = dns:dname_to_lower(iolist_to_binary(Name)),
    ZoneNameLwr = dns:dname_to_lower(iolist_to_binary(ZoneName)),
    gen_name_ancestors(NameLwr, ZoneNameLwr).

gen_name_ancestors(ZoneName, ZoneName) when is_binary(ZoneName) -> [];
gen_name_ancestors(Name, ZoneName)
  when is_binary(Name) andalso
       is_binary(ZoneName) andalso
       (byte_size(Name) > byte_size(ZoneName) + 1) ->
    Offset = byte_size(Name) - byte_size(ZoneName) - 1,
    case Name of
	<<RelName:Offset/binary, $., ZoneName/binary>> ->
	    case dns:dname_to_labels(RelName) of
		[_] -> [];
		[_|Labels0] ->
		    [FirstLabel|Labels] = lists:reverse(Labels0),
		    gen_name_ancestors(Labels, [<<FirstLabel/binary, $.,
						  ZoneName/binary>>])
	    end;
	_ -> erlang:error(name_mismatch)
    end;
gen_name_ancestors([], Anc) -> Anc;
gen_name_ancestors([Label|Labels], [Parent|_]=Asc) ->
    NewName = <<Label/binary, $., Parent/binary>>,
    gen_name_ancestors(Labels, [NewName|Asc]).

name_order(RRs) when is_list(RRs) ->
    lists:sort(fun name_order/2, RRs).

name_order(X, X) -> true;
name_order(#dns_rr{name = X}, #dns_rr{name = X}) -> true;
name_order(#dns_rr{name = A}, #dns_rr{name = B}) ->
    LabelsA = lists:reverse(normalise_dname_to_labels(A)),
    LabelsB = lists:reverse(normalise_dname_to_labels(B)),
    name_order(LabelsA, LabelsB);
name_order([X|A], [X|B]) -> name_order(A,B);
name_order([], [_|_]) -> true;
name_order([_|_], []) -> false;
name_order([X|_], [Y|_]) -> X < Y.

count_labels(Name) ->
    Labels = normalise_dname_to_labels(Name),
    do_count_labels(Labels).

do_count_labels([<<"*">>|Labels]) -> length(Labels);
do_count_labels(List) when is_list(List) -> length(List).

normalise_dname(Name) -> dns:dname_to_lower(iolist_to_binary(Name)).

normalise_dname_to_labels(Name) -> dns:dname_to_labels(normalise_dname(Name)).

decode_asn1_dss_sig(Bin) when is_binary(Bin) ->
    {ok, #'DSS-Sig'{r = R, s = S}} = 'DNS-ASN1':decode('DSS-Sig', Bin),
    {R, S}.

encode_asn1_dss_sig(R, S) when is_integer(R) andalso is_integer(S) ->
    Rec = #'DSS-Sig'{r = R, s = S},
    {ok, List} = 'DNS-ASN1':encode('DSS-Sig', Rec),
    iolist_to_binary(List).
