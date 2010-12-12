-ifndef('__dns_records.hrl__').
-define('__dns_records.hrl__', ok).

%%
%% @type bin_message() = binary().
%%
%% @type message() = #dns_message{id = message_id(),
%%                                qr = bool(),
%%                                oc = opcode(),
%%                                aa = bool(),
%%                                tc = bool(),
%%                                rd = bool(),
%%                                ra = bool(),
%%                                ad = bool(),
%%                                cd = bool(),
%%                                rc = rcode(),
%%                                qc = integer(),
%%                                anc = integer(),
%%                                auc = integer(),
%%                                adc = integer(),
%%                                questions = questions(),
%%                                answers = answers(),
%%                                authority = authority(),
%%                                additional = additional()}.
%% <ul>
%% <li>qr - Query Response</li>
%% <li>oc - Opcode</li>
%% <li>aa - Authoritative Answer</li>
%% <li>tc - Truncated</li>
%% <li>rd - Recursion Desired</li>
%% <li>ra - Recursion Available</li>
%% <li>ad - Authenticated Data</li>
%% <li>cd - Checking Disabled</li>
%% <li>rc - Response Code</li>
%% <li>qc - Query Count</li>
%% <li>anc - Answer Count</li>
%% <li>auc - Authority Count</li>
%% <li>adc - Additional Count</li>
%% </ul>
%%
%% @type opcode() = 'query' |
%%                  'iquery' |
%%                  'status' |
%%                  'update' |
%%                  integer().
%%
%% @type rcode() = 'noerror' |
%%                 'formerr' |
%%                 'servfail' | 
%%                 'nxdomain' |
%%                 'notimp' |
%%                 'refused' | 
%%                 'yxdomain' | 
%%                 'yxrrset' | 
%%                 'nxrrset' | 
%%                 'notauth' |
%%                 'notzone' | 
%%                 integer()
%%
%% @type message_id() = integer()
-record(dns_message, {id = dns:random_id(),
		      qr = false,
		      oc = 'query',
		      aa = false,
		      tc = false,
		      rd = false,
		      ra = false,
		      ad = false,
		      cd = false,
		      rc = 'noerror',
		      qc = 0,
		      anc = 0,
		      auc = 0,
		      adc = 0,
		      questions = [],
		      answers = [],
		      authority = [],
		      additional=[] }).
%%
%% @type questions() = [query()]
%% @type query() = #dns_query{name = dname(),
%%                            class = class(),
%%                            type = type()}
%%
-record(dns_query, {name, class = in, type}).
%%
%% @type answers() = [rr()]
%% @type authority() = [rr()]
%% @type additional() = [optrr() | rr()]
%%
%% @type rr() = #dns_rr{name = dname(),
%%                      class = class(),
%%                      type = type(),
%%                      ttl = ttl(),
%%                      data = rrdata()}
%% @type class() = 'in' | 'cs' | 'ch' | 'hs' | 'none' | 'any' | integer()
%% @type type() = 'a' |
%%                'ns' |
%%                'md' |
%%                'mf' |
%%                'cname' |
%%                'soa' |
%%                'mb' |
%%                'mg' | 
%%                'mr' |
%%                'null' |
%%                'wks' |
%%                'ptr' |
%%                'hinfo' |
%%                'minfo' |
%%                'mx' |
%%                'txt' |
%%                'rp' |
%%                'afsdb' |
%%                'x25' |
%%                'isdn' |
%%                'rt' |
%%                'nsap' |
%%                'sig' |
%%                'key' |
%%                'px' |
%%                'gpos' |
%%                'aaaa' |
%%                'loc' |
%%                'nxt' |
%%                'eid' |
%%                'nimloc' |
%%                'srv' |
%%                'atma' |
%%                'naptr' |
%%                'kx' |
%%                'cert' |
%%                'dname' |
%%                'sink' |
%%                'opt' |
%%                'apl' |
%%                'ds' |
%%                'sshfp' |
%%                'ipseckey' |
%%                'rrsig' |
%%                'nsec' |
%%                'dnskey' |
%%                'nsec3' |
%%                'nsec3param' |
%%                'dhcid' |
%%                'hip' |
%%                'ninfo' |
%%                'rkey' |
%%                'talink' |
%%                'spf' |
%%                'uinfo' |
%%                'uid' |
%%                'gid' |
%%                'unspec' |
%%                'tkey' |
%%                'tsig' |
%%                'ixfr' |
%%                'axfr' |
%%                'mailb' |
%%                'maila' |
%%                'dlv' |
%%                integer()
%%
-record(dns_rr, {name, class = in, type, ttl = 0, data}).
%%
%% @type optrr() = #dns_opt_rr{udp_payload_size = integer(),
%%                             ext_rcode = ext_rcode(),
%%                             version = integer(),
%%                             dnssec = bool(),
%%                             data = optrrdata()}
%% @type ext_rcode() = badvers | integer()
%%
-record(dns_optrr, {udp_payload_size = 4096,
		    ext_rcode = 0,
		    version = 0,
		    dnssec = false,
		    data = []}).
%%
%% @type dname() = binary() | string()
%%
%% @type rrdata() =  dns_rrdata_a() |
%%                   dns_rrdata_afsdb() |
%%                   dns_rrdata_aaaa() |
%%                   dns_rrdata_cname() |
%%                   dns_rrdata_dhcid() |
%%                   dns_rrdata_dname() |
%%                   dns_rrdata_dnskey() |
%%                   dns_rrdata_key() |
%%                   dns_rrdata_mx() |
%%                   dns_rrdata_kx() |
%%                   dns_rrdata_ns() |
%%                   dns_rrdata_ptr() |
%%                   dns_rrdata_rrsig() |
%%                   dns_rrdata_soa() |
%%                   dns_rrdata_srv() |
%%                   dns_rrdata_txt() |
%%                   dns_rrdata_hinfo() |
%%                   dns_rrdata_ipseckey() |
%%                   dns_rrdata_loc() |
%%                   dns_rrdata_mb() |
%%                   dns_rrdata_md() |
%%                   dns_rrdata_mf() |
%%                   dns_rrdata_mg() |
%%                   dns_rrdata_minfo() |
%%                   dns_rrdata_mr() |
%%                   dns_rrdata_nsec() |
%%                   dns_rrdata_nsec3() |
%%                   dns_rrdata_nsec3param() |
%%                   dns_rrdata_nxt() |
%%                   dns_rrdata_x25() |
%%                   dns_rrdata_wks() |
%%                   dns_rrdata_rp() |
%%                   dns_rrdata_rt() |
%%                   dns_rrdata_spf() |
%%                   dns_rrdata_sshfp() |
%%                   dns_rrdata_naptr() |
%%                   dns_rrdata_tsig() |
%%                   dns_rrdata_ds() |
%%                   dns_rrdata_dlv() |
%%                   dns_rrdata_isdn() |
%%                   dns_rrdata_cert() 
%%
-record(dns_rrdata_a, {ip}).
-record(dns_rrdata_afsdb, {subtype, hostname}).
-record(dns_rrdata_aaaa, {ip}).
-record(dns_rrdata_cname, {dname}).
-record(dns_rrdata_dhcid, {data}).
-record(dns_rrdata_dname, {dname}).
-record(dns_rrdata_dnskey, {flags, protocol, alg, public_key, key_tag}).
-record(dns_rrdata_key, {type, xt, name_type, sig, protocol, alg, public_key}).
-record(dns_rrdata_mx, {preference, exchange}).
-record(dns_rrdata_kx, {preference, exchange}).
-record(dns_rrdata_ns, {dname}).
-record(dns_rrdata_ptr, {dname}).
-record(dns_rrdata_rrsig, {type_covered, alg, labels, original_ttl, signature_expiration, signature_inception, key_tag, signers_name, signature}).
-record(dns_rrdata_soa, {mname, rname, serial, refresh, retry, expire, minimum}).
-record(dns_rrdata_srv, {priority, weight, port, target}).
-record(dns_rrdata_txt, {txt}).
-record(dns_rrdata_hinfo, {cpu, os}).
-record(dns_rrdata_ipseckey, {precedence, alg, gateway_type, gateway, public_key}).
-record(dns_rrdata_loc, {size, horiz, vert, lat, lon, alt}).
-record(dns_rrdata_mb, {madname}).
-record(dns_rrdata_md, {madname}).
-record(dns_rrdata_mf, {madname}).
-record(dns_rrdata_mg, {madname}).
-record(dns_rrdata_minfo, {rmailbx, emailbx}).
-record(dns_rrdata_mr, {newname}).
-record(dns_rrdata_nsec, {next_dname, types}).
-record(dns_rrdata_nsec3, {hash_alg, opt_out, iterations, salt, hash, types}).
-record(dns_rrdata_nsec3param, {hash_alg, flags, iterations, salt}).
-record(dns_rrdata_nxt, {dname, types}).
-record(dns_rrdata_x25, {psdn_address}).
-record(dns_rrdata_wks, {address, protocol, bitmap}).
-record(dns_rrdata_rp, {mbox, txt}).
-record(dns_rrdata_rt, {preference, host}).
-record(dns_rrdata_spf, {spf}).
-record(dns_rrdata_sshfp, {alg, fp_type, fp}).
-record(dns_rrdata_naptr, {order, preference, flags, services, regexp, replacement}).
-record(dns_rrdata_tsig, {alg, time, fudge, mac, msgid, err, other}).
-record(dns_opt_llq, {opcode, errorcode, id, leaselife}).
-record(dns_opt_ul, {lease}).
-record(dns_opt_nsid, {data}).
-record(dns_opt_owner, {seq = 0, primary_mac, wakeup_mac, password}).
-record(dns_opt_unknown, {id, bin}).
-record(dns_rrdata_ds, {keytag, alg, digest_type, digest}).
-record(dns_rrdata_dlv, {keytag, alg, digest_type, digest}).
-record(dns_rrdata_isdn, {address, subaddress}).
-record(dns_rrdata_cert, {type, key_tag, alg, cert}).

-endif.
