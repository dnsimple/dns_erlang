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
-module(dns_record_info).
-include("dns_records.hrl").
-export([fields/1, size/1, atom_for_type/1, type_for_atom/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("rebar_version.hrl").
-endif.

%% @doc Returns the fields that make up a given record.
-spec fields(atom()) -> [atom()].
fields(dns_message) -> record_info(fields, dns_message);
fields(dns_query) -> record_info(fields, dns_query);
fields(dns_rr) -> record_info(fields, dns_rr);
fields(dns_rrdata_a) -> record_info(fields, dns_rrdata_a);
fields(dns_rrdata_afsdb) -> record_info(fields, dns_rrdata_afsdb);
fields(dns_rrdata_aaaa) -> record_info(fields, dns_rrdata_aaaa);
fields(dns_rrdata_caa) ->  record_info(fields, dns_rrdata_caa);
fields(dns_rrdata_cname) -> record_info(fields, dns_rrdata_cname);
fields(dns_rrdata_dhcid) -> record_info(fields, dns_rrdata_dhcid);
fields(dns_rrdata_dname) -> record_info(fields, dns_rrdata_dname);
fields(dns_rrdata_dnskey) -> record_info(fields, dns_rrdata_dnskey);
fields(dns_rrdata_cdnskey) -> record_info(fields, dns_rrdata_cdnskey);
fields(dns_rrdata_key) -> record_info(fields, dns_rrdata_key);
fields(dns_rrdata_mx) -> record_info(fields, dns_rrdata_mx);
fields(dns_rrdata_kx) -> record_info(fields, dns_rrdata_kx);
fields(dns_rrdata_ns) -> record_info(fields, dns_rrdata_ns);
fields(dns_rrdata_ptr) -> record_info(fields, dns_rrdata_ptr);
fields(dns_rrdata_rrsig) -> record_info(fields, dns_rrdata_rrsig);
fields(dns_rrdata_soa) -> record_info(fields, dns_rrdata_soa);
fields(dns_rrdata_srv) -> record_info(fields, dns_rrdata_srv);
fields(dns_rrdata_txt) -> record_info(fields, dns_rrdata_txt);
fields(dns_rrdata_hinfo) -> record_info(fields, dns_rrdata_hinfo);
fields(dns_rrdata_ipseckey) -> record_info(fields, dns_rrdata_ipseckey);
fields(dns_rrdata_loc) -> record_info(fields, dns_rrdata_loc);
fields(dns_rrdata_mb) -> record_info(fields, dns_rrdata_mb);
fields(dns_rrdata_mg) -> record_info(fields, dns_rrdata_mg);
fields(dns_rrdata_minfo) -> record_info(fields, dns_rrdata_minfo);
fields(dns_rrdata_mr) -> record_info(fields, dns_rrdata_mr);
fields(dns_rrdata_nsec) -> record_info(fields, dns_rrdata_nsec);
fields(dns_rrdata_nsec3) -> record_info(fields, dns_rrdata_nsec3);
fields(dns_rrdata_nsec3param) -> record_info(fields, dns_rrdata_nsec3param);
fields(dns_rrdata_nxt) -> record_info(fields, dns_rrdata_nxt);
fields(dns_rrdata_rp) -> record_info(fields, dns_rrdata_rp);
fields(dns_rrdata_rt) -> record_info(fields, dns_rrdata_rt);
fields(dns_rrdata_spf) -> record_info(fields, dns_rrdata_spf);
fields(dns_rrdata_sshfp) -> record_info(fields, dns_rrdata_sshfp);
fields(dns_rrdata_naptr) -> record_info(fields, dns_rrdata_naptr);
fields(dns_rrdata_ds) -> record_info(fields, dns_rrdata_ds);
fields(dns_rrdata_cds) -> record_info(fields, dns_rrdata_cds);
fields(dns_rrdata_dlv) -> record_info(fields, dns_rrdata_dlv);
fields(dns_rrdata_cert) -> record_info(fields, dns_rrdata_cert);
fields(dns_rrdata_tsig) -> record_info(fields, dns_rrdata_tsig);
fields(dns_optrr) -> record_info(fields, dns_optrr);
fields(dns_opt_llq) -> record_info(fields, dns_opt_llq);
fields(dns_opt_nsid) -> record_info(fields, dns_opt_nsid);
fields(dns_opt_owner) -> record_info(fields, dns_opt_owner);
fields(dns_opt_ul) -> record_info(fields, dns_opt_ul);
fields(dns_opt_ecs) -> record_info(fields, dns_opt_ecs);
fields(dns_opt_unknown) -> record_info(fields, dns_opt_unknown).

%% @doc Returns the size of a given record.
-spec size(atom()) -> non_neg_integer().
size(dns_message) -> record_info(size, dns_message);
size(dns_query) -> record_info(size, dns_query);
size(dns_rr) -> record_info(size, dns_rr);
size(dns_rrdata_a) -> record_info(size, dns_rrdata_a);
size(dns_rrdata_afsdb) -> record_info(size, dns_rrdata_afsdb);
size(dns_rrdata_aaaa) -> record_info(size, dns_rrdata_aaaa);
size(dns_rrdata_caa) -> record_info(size, dns_rrdata_caa);
size(dns_rrdata_cname) -> record_info(size, dns_rrdata_cname);
size(dns_rrdata_dhcid) -> record_info(size, dns_rrdata_dhcid);
size(dns_rrdata_dname) -> record_info(size, dns_rrdata_dname);
size(dns_rrdata_dnskey) -> record_info(size, dns_rrdata_dnskey);
size(dns_rrdata_cdnskey) -> record_info(size, dns_rrdata_cdnskey);
size(dns_rrdata_key) -> record_info(size, dns_rrdata_key);
size(dns_rrdata_mx) -> record_info(size, dns_rrdata_mx);
size(dns_rrdata_kx) -> record_info(size, dns_rrdata_kx);
size(dns_rrdata_ns) -> record_info(size, dns_rrdata_ns);
size(dns_rrdata_ptr) -> record_info(size, dns_rrdata_ptr);
size(dns_rrdata_rrsig) -> record_info(size, dns_rrdata_rrsig);
size(dns_rrdata_soa) -> record_info(size, dns_rrdata_soa);
size(dns_rrdata_srv) -> record_info(size, dns_rrdata_srv);
size(dns_rrdata_txt) -> record_info(size, dns_rrdata_txt);
size(dns_rrdata_hinfo) -> record_info(size, dns_rrdata_hinfo);
size(dns_rrdata_ipseckey) -> record_info(size, dns_rrdata_ipseckey);
size(dns_rrdata_loc) -> record_info(size, dns_rrdata_loc);
size(dns_rrdata_mb) -> record_info(size, dns_rrdata_mb);
size(dns_rrdata_mg) -> record_info(size, dns_rrdata_mg);
size(dns_rrdata_minfo) -> record_info(size, dns_rrdata_minfo);
size(dns_rrdata_mr) -> record_info(size, dns_rrdata_mr);
size(dns_rrdata_nsec) -> record_info(size, dns_rrdata_nsec);
size(dns_rrdata_nsec3) -> record_info(size, dns_rrdata_nsec3);
size(dns_rrdata_nsec3param) -> record_info(size, dns_rrdata_nsec3param);
size(dns_rrdata_nxt) -> record_info(size, dns_rrdata_nxt);
size(dns_rrdata_rp) -> record_info(size, dns_rrdata_rp);
size(dns_rrdata_rt) -> record_info(size, dns_rrdata_rt);
size(dns_rrdata_spf) -> record_info(size, dns_rrdata_spf);
size(dns_rrdata_sshfp) -> record_info(size, dns_rrdata_sshfp);
size(dns_rrdata_naptr) -> record_info(size, dns_rrdata_naptr);
size(dns_rrdata_ds) -> record_info(size, dns_rrdata_ds);
size(dns_rrdata_cds) -> record_info(size, dns_rrdata_cds);
size(dns_rrdata_dlv) -> record_info(size, dns_rrdata_dlv);
size(dns_rrdata_cert) -> record_info(size, dns_rrdata_cert);
size(dns_rrdata_tsig) -> record_info(size, dns_rrdata_tsig);
size(dns_optrr) -> record_info(size, dns_optrr);
size(dns_opt_llq) -> record_info(size, dns_opt_llq);
size(dns_opt_nsid) -> record_info(size, dns_opt_nsid);
size(dns_opt_owner) -> record_info(size, dns_opt_owner);
size(dns_opt_ul) -> record_info(size, dns_opt_ul);
size(dns_opt_ecs) -> record_info(size, dns_opt_ecs);
size(dns_opt_unknown) -> record_info(size, dns_opt_unknown).

%% @doc Returns the record tag atom for the given record type.
-spec atom_for_type(dns:type()) -> atom() | 'undefined'.
atom_for_type(?DNS_TYPE_A) -> dns_rrdata_a;
atom_for_type(?DNS_TYPE_AFSDB) -> dns_rrdata_afsdb;
atom_for_type(?DNS_TYPE_AAAA) -> dns_rrdata_aaaa;
atom_for_type(?DNS_TYPE_CAA) -> dns_rrdata_caa;
atom_for_type(?DNS_TYPE_CNAME) -> dns_rrdata_cname;
atom_for_type(?DNS_TYPE_DHCID) -> dns_rrdata_dhcid;
atom_for_type(?DNS_TYPE_DNAME) -> dns_rrdata_dname;
atom_for_type(?DNS_TYPE_DNSKEY) -> dns_rrdata_dnskey;
atom_for_type(?DNS_TYPE_CDNSKEY) -> dns_rrdata_cdnskey;
atom_for_type(?DNS_TYPE_KEY) -> dns_rrdata_key;
atom_for_type(?DNS_TYPE_MX) -> dns_rrdata_mx;
atom_for_type(?DNS_TYPE_KX) -> dns_rrdata_kx;
atom_for_type(?DNS_TYPE_NS) -> dns_rrdata_ns;
atom_for_type(?DNS_TYPE_PTR) -> dns_rrdata_ptr;
atom_for_type(?DNS_TYPE_RRSIG) -> dns_rrdata_rrsig;
atom_for_type(?DNS_TYPE_SOA) -> dns_rrdata_soa;
atom_for_type(?DNS_TYPE_SRV) -> dns_rrdata_srv;
atom_for_type(?DNS_TYPE_TXT) -> dns_rrdata_txt;
atom_for_type(?DNS_TYPE_HINFO) -> dns_rrdata_hinfo;
atom_for_type(?DNS_TYPE_IPSECKEY) -> dns_rrdata_ipseckey;
atom_for_type(?DNS_TYPE_LOC) -> dns_rrdata_loc;
atom_for_type(?DNS_TYPE_MB) -> dns_rrdata_mb;
atom_for_type(?DNS_TYPE_MD) -> dns_rrdata_md;
atom_for_type(?DNS_TYPE_MF) -> dns_rrdata_mf;
atom_for_type(?DNS_TYPE_MG) -> dns_rrdata_mg;
atom_for_type(?DNS_TYPE_MINFO) -> dns_rrdata_minfo;
atom_for_type(?DNS_TYPE_MR) -> dns_rrdata_mr;
atom_for_type(?DNS_TYPE_NSEC) -> dns_rrdata_nsec;
atom_for_type(?DNS_TYPE_NSEC3) -> dns_rrdata_nsec3;
atom_for_type(?DNS_TYPE_NSEC3PARAM) -> dns_rrdata_nsec3param;
atom_for_type(?DNS_TYPE_NXT) -> dns_rrdata_nxt;
atom_for_type(?DNS_TYPE_RP) -> dns_rrdata_rp;
atom_for_type(?DNS_TYPE_RT) -> dns_rrdata_rt;
atom_for_type(?DNS_TYPE_SPF) -> dns_rrdata_spf;
atom_for_type(?DNS_TYPE_SSHFP) -> dns_rrdata_sshfp;
atom_for_type(?DNS_TYPE_NAPTR) -> dns_rrdata_naptr;
atom_for_type(?DNS_TYPE_DS) -> dns_rrdata_ds;
atom_for_type(?DNS_TYPE_CDS) -> dns_rrdata_cds;
atom_for_type(?DNS_TYPE_DLV) -> dns_rrdata_dlv;
atom_for_type(?DNS_TYPE_CERT) -> dns_rrdata_cert;
atom_for_type(?DNS_TYPE_TSIG) -> dns_rrdata_tsig;
atom_for_type(_) -> undefined.

%% @doc Returns the record type for the given record tag atom.
-spec type_for_atom(atom()) -> dns:type() | 'undefined'.
type_for_atom(dns_rrdata_a) -> ?DNS_TYPE_A;
type_for_atom(dns_rrdata_afsdb) -> ?DNS_TYPE_AFSDB;
type_for_atom(dns_rrdata_aaaa) -> ?DNS_TYPE_AAAA;
type_for_atom(dns_rrdata_caa) -> ?DNS_TYPE_CAA;
type_for_atom(dns_rrdata_cname) -> ?DNS_TYPE_CNAME;
type_for_atom(dns_rrdata_dhcid) -> ?DNS_TYPE_DHCID;
type_for_atom(dns_rrdata_dname) -> ?DNS_TYPE_DNAME;
type_for_atom(dns_rrdata_dnskey) -> ?DNS_TYPE_DNSKEY;
type_for_atom(dns_rrdata_cdnskey) -> ?DNS_TYPE_CDNSKEY;
type_for_atom(dns_rrdata_key) -> ?DNS_TYPE_KEY;
type_for_atom(dns_rrdata_mx) -> ?DNS_TYPE_MX;
type_for_atom(dns_rrdata_kx) -> ?DNS_TYPE_KX;
type_for_atom(dns_rrdata_ns) -> ?DNS_TYPE_NS;
type_for_atom(dns_rrdata_ptr) -> ?DNS_TYPE_PTR;
type_for_atom(dns_rrdata_rrsig) -> ?DNS_TYPE_RRSIG;
type_for_atom(dns_rrdata_soa) -> ?DNS_TYPE_SOA;
type_for_atom(dns_rrdata_srv) -> ?DNS_TYPE_SRV;
type_for_atom(dns_rrdata_txt) -> ?DNS_TYPE_TXT;
type_for_atom(dns_rrdata_hinfo) -> ?DNS_TYPE_HINFO;
type_for_atom(dns_rrdata_ipseckey) -> ?DNS_TYPE_IPSECKEY;
type_for_atom(dns_rrdata_loc) -> ?DNS_TYPE_LOC;
type_for_atom(dns_rrdata_mb) -> ?DNS_TYPE_MB;
type_for_atom(dns_rrdata_md) -> ?DNS_TYPE_MD;
type_for_atom(dns_rrdata_mf) -> ?DNS_TYPE_MF;
type_for_atom(dns_rrdata_mg) -> ?DNS_TYPE_MG;
type_for_atom(dns_rrdata_minfo) -> ?DNS_TYPE_MINFO;
type_for_atom(dns_rrdata_mr) -> ?DNS_TYPE_MR;
type_for_atom(dns_rrdata_nsec) -> ?DNS_TYPE_NSEC;
type_for_atom(dns_rrdata_nsec3) -> ?DNS_TYPE_NSEC3;
type_for_atom(dns_rrdata_nsec3param) -> ?DNS_TYPE_NSEC3PARAM;
type_for_atom(dns_rrdata_nxt) -> ?DNS_TYPE_NXT;
type_for_atom(dns_rrdata_rp) -> ?DNS_TYPE_RP;
type_for_atom(dns_rrdata_rt) -> ?DNS_TYPE_RT;
type_for_atom(dns_rrdata_spf) -> ?DNS_TYPE_SPF;
type_for_atom(dns_rrdata_sshfp) -> ?DNS_TYPE_SSHFP;
type_for_atom(dns_rrdata_naptr) -> ?DNS_TYPE_NAPTR;
type_for_atom(dns_rrdata_ds) -> ?DNS_TYPE_DS;
type_for_atom(dns_rrdata_cds) -> ?DNS_TYPE_CDS;
type_for_atom(dns_rrdata_dlv) -> ?DNS_TYPE_DLV;
type_for_atom(dns_rrdata_cert) -> ?DNS_TYPE_CERT;
type_for_atom(dns_rrdata_tsig) -> ?DNS_TYPE_TSIG;
type_for_atom(_) -> undefined.

-ifdef(TEST).

type_rec_test_() ->
    {ok, Cases} = file:consult(filename:join(prefix(), "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([T || {_,T,_} <- Cases, T =/= 999])),
    [ ?_assertEqual(Type, type_for_atom(atom_for_type(Type)))
      || Type <- Types ].

recinfo_test_() ->
    {ok, Cases} = file:consult(filename:join(prefix(), "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([T || {_, T ,_} <- Cases, T =/= 999])),
    Tags = [dns_rr|[ atom_for_type(Type) || Type <- Types ]],
    [ {atom_to_list(Tag),
       ?_assertEqual(length(fields(Tag)),
		     ?MODULE:size(Tag) - 1)}
      || Tag <- Tags ].

-endif.
