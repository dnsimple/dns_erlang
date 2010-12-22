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
-endif.

%% @doc Returns the fields that make up a given record.
%% @spec fields(RecordTag :: atom()) -> [atom()]
fields(dns_rr) -> record_info(fields, dns_rr);
fields(dns_rrdata_a) -> record_info(fields, dns_rrdata_a);
fields(dns_rrdata_afsdb) -> record_info(fields, dns_rrdata_afsdb);
fields(dns_rrdata_aaaa) -> record_info(fields, dns_rrdata_aaaa);
fields(dns_rrdata_cname) -> record_info(fields, dns_rrdata_cname);
fields(dns_rrdata_dhcid) -> record_info(fields, dns_rrdata_dhcid);
fields(dns_rrdata_dname) -> record_info(fields, dns_rrdata_dname);
fields(dns_rrdata_dnskey) -> record_info(fields, dns_rrdata_dnskey);
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
fields(dns_rrdata_md) -> record_info(fields, dns_rrdata_md);
fields(dns_rrdata_mf) -> record_info(fields, dns_rrdata_mf);
fields(dns_rrdata_mg) -> record_info(fields, dns_rrdata_mg);
fields(dns_rrdata_minfo) -> record_info(fields, dns_rrdata_minfo);
fields(dns_rrdata_mr) -> record_info(fields, dns_rrdata_mr);
fields(dns_rrdata_nsec) -> record_info(fields, dns_rrdata_nsec);
fields(dns_rrdata_nsec3) -> record_info(fields, dns_rrdata_nsec3);
fields(dns_rrdata_nsec3param) -> record_info(fields, dns_rrdata_nsec3param);
fields(dns_rrdata_nxt) -> record_info(fields, dns_rrdata_nxt);
fields(dns_rrdata_x25) -> record_info(fields, dns_rrdata_x25);
fields(dns_rrdata_wks) -> record_info(fields, dns_rrdata_wks);
fields(dns_rrdata_rp) -> record_info(fields, dns_rrdata_rp);
fields(dns_rrdata_rt) -> record_info(fields, dns_rrdata_rt);
fields(dns_rrdata_px) -> record_info(fields, dns_rrdata_px);
fields(dns_rrdata_spf) -> record_info(fields, dns_rrdata_spf);
fields(dns_rrdata_sshfp) -> record_info(fields, dns_rrdata_sshfp);
fields(dns_rrdata_naptr) -> record_info(fields, dns_rrdata_naptr);
fields(dns_rrdata_ds) -> record_info(fields, dns_rrdata_ds);
fields(dns_rrdata_dlv) -> record_info(fields, dns_rrdata_dlv);
fields(dns_rrdata_isdn) -> record_info(fields, dns_rrdata_isdn);
fields(dns_rrdata_cert) -> record_info(fields, dns_rrdata_cert).

%% @doc Returns the size of a given record.
%% @spec size(RecordTag :: atom()) -> integer()
size(dns_rr) -> record_info(size, dns_rr);
size(dns_rrdata_a) -> record_info(size, dns_rrdata_a);
size(dns_rrdata_afsdb) -> record_info(size, dns_rrdata_afsdb);
size(dns_rrdata_aaaa) -> record_info(size, dns_rrdata_aaaa);
size(dns_rrdata_cname) -> record_info(size, dns_rrdata_cname);
size(dns_rrdata_dhcid) -> record_info(size, dns_rrdata_dhcid);
size(dns_rrdata_dname) -> record_info(size, dns_rrdata_dname);
size(dns_rrdata_dnskey) -> record_info(size, dns_rrdata_dnskey);
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
size(dns_rrdata_md) -> record_info(size, dns_rrdata_md);
size(dns_rrdata_mf) -> record_info(size, dns_rrdata_mf);
size(dns_rrdata_mg) -> record_info(size, dns_rrdata_mg);
size(dns_rrdata_minfo) -> record_info(size, dns_rrdata_minfo);
size(dns_rrdata_mr) -> record_info(size, dns_rrdata_mr);
size(dns_rrdata_nsec) -> record_info(size, dns_rrdata_nsec);
size(dns_rrdata_nsec3) -> record_info(size, dns_rrdata_nsec3);
size(dns_rrdata_nsec3param) -> record_info(size, dns_rrdata_nsec3param);
size(dns_rrdata_nxt) -> record_info(size, dns_rrdata_nxt);
size(dns_rrdata_x25) -> record_info(size, dns_rrdata_x25);
size(dns_rrdata_wks) -> record_info(size, dns_rrdata_wks);
size(dns_rrdata_rp) -> record_info(size, dns_rrdata_rp);
size(dns_rrdata_rt) -> record_info(size, dns_rrdata_rt);
size(dns_rrdata_px) -> record_info(size, dns_rrdata_px);
size(dns_rrdata_spf) -> record_info(size, dns_rrdata_spf);
size(dns_rrdata_sshfp) -> record_info(size, dns_rrdata_sshfp);
size(dns_rrdata_naptr) -> record_info(size, dns_rrdata_naptr);
size(dns_rrdata_ds) -> record_info(size, dns_rrdata_ds);
size(dns_rrdata_dlv) -> record_info(size, dns_rrdata_dlv);
size(dns_rrdata_isdn) -> record_info(size, dns_rrdata_isdn);
size(dns_rrdata_cert) -> record_info(size, dns_rrdata_cert).

%% @doc Returns the record tag atom for the given record type.
%% @spec atom_for_type(RecordTag :: atom()) -> atom() | undefined
atom_for_type(a) -> dns_rrdata_a;
atom_for_type(afsdb) -> dns_rrdata_afsdb;
atom_for_type(aaaa) -> dns_rrdata_aaaa;
atom_for_type(cname) -> dns_rrdata_cname;
atom_for_type(dhcid) -> dns_rrdata_dhcid;
atom_for_type(dname) -> dns_rrdata_dname;
atom_for_type(dnskey) -> dns_rrdata_dnskey;
atom_for_type(key) -> dns_rrdata_key;
atom_for_type(mx) -> dns_rrdata_mx;
atom_for_type(kx) -> dns_rrdata_kx;
atom_for_type(ns) -> dns_rrdata_ns;
atom_for_type(ptr) -> dns_rrdata_ptr;
atom_for_type(rrsig) -> dns_rrdata_rrsig;
atom_for_type(soa) -> dns_rrdata_soa;
atom_for_type(srv) -> dns_rrdata_srv;
atom_for_type(txt) -> dns_rrdata_txt;
atom_for_type(hinfo) -> dns_rrdata_hinfo;
atom_for_type(ipseckey) -> dns_rrdata_ipseckey;
atom_for_type(loc) -> dns_rrdata_loc;
atom_for_type(mb) -> dns_rrdata_mb;
atom_for_type(md) -> dns_rrdata_md;
atom_for_type(mf) -> dns_rrdata_mf;
atom_for_type(mg) -> dns_rrdata_mg;
atom_for_type(minfo) -> dns_rrdata_minfo;
atom_for_type(mr) -> dns_rrdata_mr;
atom_for_type(nsec) -> dns_rrdata_nsec;
atom_for_type(nsec3) -> dns_rrdata_nsec3;
atom_for_type(nsec3param) -> dns_rrdata_nsec3param;
atom_for_type(nxt) -> dns_rrdata_nxt;
atom_for_type(x25) -> dns_rrdata_x25;
atom_for_type(wks) -> dns_rrdata_wks;
atom_for_type(rp) -> dns_rrdata_rp;
atom_for_type(rt) -> dns_rrdata_rt;
atom_for_type(px) -> dns_rrdata_px;
atom_for_type(spf) -> dns_rrdata_spf;
atom_for_type(sshfp) -> dns_rrdata_sshfp;
atom_for_type(naptr) -> dns_rrdata_naptr;
atom_for_type(ds) -> dns_rrdata_ds;
atom_for_type(dlv) -> dns_rrdata_dlv;
atom_for_type(isdn) -> dns_rrdata_isdn;
atom_for_type(cert) -> dns_rrdata_cert;
atom_for_type(_) -> undefined.

%% @doc Returns the record type for the given record tag atom.
%% @spec type_for_atom(RecordTag :: atom()) -> atom() | undefined
type_for_atom(dns_rrdata_a) -> a;
type_for_atom(dns_rrdata_afsdb) -> afsdb;
type_for_atom(dns_rrdata_aaaa) -> aaaa;
type_for_atom(dns_rrdata_cname) -> cname;
type_for_atom(dns_rrdata_dhcid) -> dhcid;
type_for_atom(dns_rrdata_dname) -> dname;
type_for_atom(dns_rrdata_dnskey) -> dnskey;
type_for_atom(dns_rrdata_key) -> key;
type_for_atom(dns_rrdata_mx) -> mx;
type_for_atom(dns_rrdata_kx) -> kx;
type_for_atom(dns_rrdata_ns) -> ns;
type_for_atom(dns_rrdata_ptr) -> ptr;
type_for_atom(dns_rrdata_rrsig) -> rrsig;
type_for_atom(dns_rrdata_soa) -> soa;
type_for_atom(dns_rrdata_srv) -> srv;
type_for_atom(dns_rrdata_txt) -> txt;
type_for_atom(dns_rrdata_hinfo) -> hinfo;
type_for_atom(dns_rrdata_ipseckey) -> ipseckey;
type_for_atom(dns_rrdata_loc) -> loc;
type_for_atom(dns_rrdata_mb) -> mb;
type_for_atom(dns_rrdata_md) -> md;
type_for_atom(dns_rrdata_mf) -> mf;
type_for_atom(dns_rrdata_mg) -> mg;
type_for_atom(dns_rrdata_minfo) -> minfo;
type_for_atom(dns_rrdata_mr) -> mr;
type_for_atom(dns_rrdata_nsec) -> nsec;
type_for_atom(dns_rrdata_nsec3) -> nsec3;
type_for_atom(dns_rrdata_nsec3param) -> nsec3param;
type_for_atom(dns_rrdata_nxt) -> nxt;
type_for_atom(dns_rrdata_x25) -> x25;
type_for_atom(dns_rrdata_wks) -> wks;
type_for_atom(dns_rrdata_rp) -> rp;
type_for_atom(dns_rrdata_rt) -> rt;
type_for_atom(dns_rrdata_px) -> px;
type_for_atom(dns_rrdata_spf) -> spf;
type_for_atom(dns_rrdata_sshfp) -> sshfp;
type_for_atom(dns_rrdata_naptr) -> naptr;
type_for_atom(dns_rrdata_ds) -> ds;
type_for_atom(dns_rrdata_dlv) -> dlv;
type_for_atom(dns_rrdata_isdn) -> isdn;
type_for_atom(dns_rrdata_cert) -> cert;
type_for_atom(_) -> undefined.

-ifdef(TEST).

type_rec_test_() ->
    {ok, Cases} = file:consult("../priv/rrdata_wire_samples.txt"),
    Types = sets:to_list(sets:from_list([T || {_,T,_} <- Cases, is_atom(T)])),
    [ ?_assertEqual(Type, type_for_atom(atom_for_type(Type)))
      || Type <- Types ].

recinfo_test_() ->
    {ok, Cases} = file:consult("../priv/rrdata_wire_samples.txt"),
    Types = sets:to_list(sets:from_list([T || {_, T ,_} <- Cases, is_atom(T)])),
    Tags = [dns_rr|[ atom_for_type(Type) || Type <- Types ]],
    [ {atom_to_list(Tag),
       ?_assertEqual(length(fields(Tag)),
		     ?MODULE:size(Tag) - 1)}
      || Tag <- Tags ].

-endif.
