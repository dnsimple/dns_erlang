-ifndef('__dns_records.hrl__').
-define('__dns_records.hrl__', ok).
-include("dns_terms.hrl").

-record(dns_message, {id = dns:random_id() :: dns:message_id(),
		      qr = false :: 0..1 | boolean(),
		      oc = ?DNS_OPCODE_QUERY :: dns:opcode(),
		      aa = false :: 0..1 | boolean(),
		      tc = false :: 0..1 | boolean(),
		      rd = false :: 0..1 | boolean(),
		      ra = false :: 0..1 | boolean(),
		      ad = false :: 0..1 | boolean(),
		      cd = false :: 0..1 | boolean(),
		      rc = ?DNS_RCODE_NOERROR :: dns:rcode(),
		      qc = 0 :: 0..65535,
		      anc = 0 :: 0..65535,
		      auc = 0 :: 0..65535,
		      adc = 0 :: 0..65535,
		      questions = [] :: dns:questions(),
		      answers = [] :: dns:answers(),
		      authority = [] :: dns:authority(),
		      additional = [] :: dns:additional()}).

-record(dns_query, {name :: dns:dname(),
		    class = ?DNS_CLASS_IN :: dns:class(),
		    type :: dns:type()}).

-record(dns_rr, {name :: dns:dname(),
		 class = ?DNS_CLASS_IN :: dns:class(),
		 type :: dns:type(),
		 ttl = 0 :: dns:ttl(),
		 data :: dns:rrdata()}).
-record(dns_rrdata_a, {ip}).
-record(dns_rrdata_aaaa, {ip}).
-record(dns_rrdata_afsdb, {subtype, hostname}).
-record(dns_rrdata_caa, {flags, tag, value}).
-record(dns_rrdata_cert, {type, key_tag, alg, cert}).
-record(dns_rrdata_cname, {dname}).
-record(dns_rrdata_dhcid, {data}).
-record(dns_rrdata_dlv, {keytag, alg, digest_type, digest}).
-record(dns_rrdata_dname, {dname}).
-record(dns_rrdata_dnskey, {flags, protocol, alg, public_key, key_tag}).
-record(dns_rrdata_cdnskey, {flags, protocol, alg, public_key, key_tag}).
-record(dns_rrdata_ds, {keytag, alg, digest_type, digest}).
-record(dns_rrdata_cds, {keytag, alg, digest_type, digest}).
-record(dns_rrdata_hinfo, {cpu, os}).
-record(dns_rrdata_ipseckey, {precedence,
			      alg,
			      gateway,
			      public_key}).
-record(dns_rrdata_key, {type, xt, name_type, sig, protocol, alg, public_key}).
-record(dns_rrdata_kx, {preference, exchange}).
-record(dns_rrdata_loc, {size, horiz, vert, lat, lon, alt}).
-record(dns_rrdata_mb, {madname}).
-record(dns_rrdata_mg, {madname}).
-record(dns_rrdata_minfo, {rmailbx, emailbx}).
-record(dns_rrdata_mr, {newname}).
-record(dns_rrdata_mx, {preference, exchange}).
-record(dns_rrdata_naptr, {order,
			   preference,
			   flags,
			   services,
			   regexp,
			   replacement}).
-record(dns_rrdata_ns, {dname}).
-record(dns_rrdata_nsec, {next_dname, types}).
-record(dns_rrdata_nsec3, {hash_alg, opt_out, iterations, salt, hash, types}).
-record(dns_rrdata_nsec3param, {hash_alg, flags, iterations, salt}).
-record(dns_rrdata_nxt, {dname, types}).
-record(dns_rrdata_ptr, {dname}).
-record(dns_rrdata_rp, {mbox, txt}).
-record(dns_rrdata_rrsig, {type_covered,
			   alg,
			   labels,
			   original_ttl,
			   expiration,
			   inception,
			   key_tag,
			   signers_name,
			   signature}).
-record(dns_rrdata_rt, {preference, host}).
-record(dns_rrdata_soa, {mname,
			 rname,
			 serial,
			 refresh,
			 retry,
			 expire,
			 minimum}).
-record(dns_rrdata_spf, {spf}).
-record(dns_rrdata_srv, {priority, weight, port, target}).
-record(dns_rrdata_sshfp, {alg, fp_type, fp}).
-record(dns_rrdata_tsig, {alg, time, fudge, mac, msgid, err, other}).
-record(dns_rrdata_txt, {txt}).

-record(dns_optrr, {udp_payload_size = 4096,
		    ext_rcode = ?DNS_ERCODE_NOERROR,
		    version = 0,
		    dnssec = false,
		    data = []}).
-record(dns_opt_llq, {opcode, errorcode, id, leaselife}).
-record(dns_opt_nsid, {data}).
-record(dns_opt_owner, {seq = 0, primary_mac, wakeup_mac, password}).
-record(dns_opt_ul, {lease}).
-record(dns_opt_ecs, {
		      family,
		      source_prefix_length, 
		      scope_prefix_length,
		      address
		     }).
-record(dns_opt_unknown, {id, bin}).

-endif.
