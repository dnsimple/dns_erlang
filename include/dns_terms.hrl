-ifndef('DNS_TERMS').
-define('DNS_TERMS', ok).

-define(DNS_EDNS_MIN_VERSION, 0).
-define(DNS_EDNS_MAX_VERSION, 0).

-define(DNS_ALG_DSA, ?DNS_ALG_DSA_NUMBER).
-define(DNS_ALG_DSA_NUMBER, 3).
-define(DNS_ALG_DSA_BSTR, <<"DSA">>).

-define(DNS_ALG_NSEC3DSA, ?DNS_ALG_NSEC3DSA_NUMBER).
-define(DNS_ALG_NSEC3DSA_NUMBER, 6).
-define(DNS_ALG_NSEC3DSA_BSTR, <<"NSEC3DSA">>).

-define(DNS_ALG_RSASHA1, ?DNS_ALG_RSASHA1_NUMBER).
-define(DNS_ALG_RSASHA1_NUMBER, 5).
-define(DNS_ALG_RSASHA1_BSTR, <<"RSASHA1">>).

-define(DNS_ALG_NSEC3RSASHA1, ?DNS_ALG_NSEC3RSASHA1_NUMBER).
-define(DNS_ALG_NSEC3RSASHA1_NUMBER, 7).
-define(DNS_ALG_NSEC3RSASHA1_BSTR, <<"NSEC3RSASHA1">>).

-define(DNS_ALG_RSASHA256, ?DNS_ALG_RSASHA256_NUMBER).
-define(DNS_ALG_RSASHA256_NUMBER, 8).
-define(DNS_ALG_RSASHA256_BSTR, <<"RSASHA256">>).

-define(DNS_ALG_RSASHA512, ?DNS_ALG_RSASHA512_NUMBER).
-define(DNS_ALG_RSASHA512_NUMBER, 10).
-define(DNS_ALG_RSASHA512_BSTR, <<"RSASHA512">>).

-define(DNSSEC_NSEC3_ALG_SHA1, ?DNSSEC_NSEC3_ALG_SHA1_NUMBER).
-define(DNSSEC_NSEC3_ALG_SHA1_NUMBER, 1).
-define(DNSSEC_NSEC3_ALG_SHA1_BSTR, <<"SHA1">>).

-define(DNS_TSIG_ALG_MD5, <<"hmac-md5.sig-alg.reg.int">>).
-define(DNS_TSIG_ALG_SHA1, <<"hmac-sha1">>).
-define(DNS_TSIG_ALG_SHA224, <<"hmac-sha224">>).
-define(DNS_TSIG_ALG_SHA256, <<"hmac-sha256">>).
-define(DNS_TSIG_ALG_SHA384, <<"hmac-sha384">>).
-define(DNS_TSIG_ALG_SHA512, <<"hmac-sha512">>).

-define(DNS_CLASS_IN, ?DNS_CLASS_IN_NUMBER).
-define(DNS_CLASS_IN_NUMBER, 1).
-define(DNS_CLASS_IN_BSTR, <<"IN">>).
-define(DNS_CLASS_CS, ?DNS_CLASS_CS_NUMBER).
-define(DNS_CLASS_CS_NUMBER, 2).
-define(DNS_CLASS_CS_BSTR, <<"CS">>).
-define(DNS_CLASS_CH, ?DNS_CLASS_CH_NUMBER).
-define(DNS_CLASS_CH_NUMBER, 3).
-define(DNS_CLASS_CH_BSTR, <<"CH">>).
-define(DNS_CLASS_HS, ?DNS_CLASS_HS_NUMBER).
-define(DNS_CLASS_HS_NUMBER, 4).
-define(DNS_CLASS_HS_BSTR, <<"HS">>).
-define(DNS_CLASS_NONE, ?DNS_CLASS_NONE_NUMBER).
-define(DNS_CLASS_NONE_NUMBER, 254).
-define(DNS_CLASS_NONE_BSTR, <<"NONE">>).
-define(DNS_CLASS_ANY, ?DNS_CLASS_ANY_NUMBER).
-define(DNS_CLASS_ANY_NUMBER, 255).
-define(DNS_CLASS_ANY_BSTR, <<"ANY">>).
-define(DNS_TYPE_A, ?DNS_TYPE_A_NUMBER).
-define(DNS_TYPE_A_NUMBER, 1).
-define(DNS_TYPE_A_BSTR, <<"A">>).
-define(DNS_TYPE_NS, ?DNS_TYPE_NS_NUMBER).
-define(DNS_TYPE_NS_NUMBER, 2).
-define(DNS_TYPE_NS_BSTR, <<"NS">>).
-define(DNS_TYPE_MD, ?DNS_TYPE_MD_NUMBER).
-define(DNS_TYPE_MD_NUMBER, 3).
-define(DNS_TYPE_MD_BSTR, <<"MD">>).
-define(DNS_TYPE_MF, ?DNS_TYPE_MF_NUMBER).
-define(DNS_TYPE_MF_NUMBER, 4).
-define(DNS_TYPE_MF_BSTR, <<"MF">>).
-define(DNS_TYPE_CNAME, ?DNS_TYPE_CNAME_NUMBER).
-define(DNS_TYPE_CNAME_NUMBER, 5).
-define(DNS_TYPE_CNAME_BSTR, <<"CNAME">>).
-define(DNS_TYPE_SOA, ?DNS_TYPE_SOA_NUMBER).
-define(DNS_TYPE_SOA_NUMBER, 6).
-define(DNS_TYPE_SOA_BSTR, <<"SOA">>).
-define(DNS_TYPE_MB, ?DNS_TYPE_MB_NUMBER).
-define(DNS_TYPE_MB_NUMBER, 7).
-define(DNS_TYPE_MB_BSTR, <<"MB">>).
-define(DNS_TYPE_MG, ?DNS_TYPE_MG_NUMBER).
-define(DNS_TYPE_MG_NUMBER, 8).
-define(DNS_TYPE_MG_BSTR, <<"MG">>).
-define(DNS_TYPE_MR, ?DNS_TYPE_MR_NUMBER).
-define(DNS_TYPE_MR_NUMBER, 9).
-define(DNS_TYPE_MR_BSTR, <<"MR">>).
-define(DNS_TYPE_NULL, ?DNS_TYPE_NULL_NUMBER).
-define(DNS_TYPE_NULL_NUMBER, 10).
-define(DNS_TYPE_NULL_BSTR, <<"NULL">>).
-define(DNS_TYPE_WKS, ?DNS_TYPE_WKS_NUMBER).
-define(DNS_TYPE_WKS_NUMBER, 11).
-define(DNS_TYPE_WKS_BSTR, <<"WKS">>).
-define(DNS_TYPE_PTR, ?DNS_TYPE_PTR_NUMBER).
-define(DNS_TYPE_PTR_NUMBER, 12).
-define(DNS_TYPE_PTR_BSTR, <<"PTR">>).
-define(DNS_TYPE_HINFO, ?DNS_TYPE_HINFO_NUMBER).
-define(DNS_TYPE_HINFO_NUMBER, 13).
-define(DNS_TYPE_HINFO_BSTR, <<"HINFO">>).
-define(DNS_TYPE_MINFO, ?DNS_TYPE_MINFO_NUMBER).
-define(DNS_TYPE_MINFO_NUMBER, 14).
-define(DNS_TYPE_MINFO_BSTR, <<"MINFO">>).
-define(DNS_TYPE_MX, ?DNS_TYPE_MX_NUMBER).
-define(DNS_TYPE_MX_NUMBER, 15).
-define(DNS_TYPE_MX_BSTR, <<"MX">>).
-define(DNS_TYPE_TXT, ?DNS_TYPE_TXT_NUMBER).
-define(DNS_TYPE_TXT_NUMBER, 16).
-define(DNS_TYPE_TXT_BSTR, <<"TXT">>).
-define(DNS_TYPE_RP, ?DNS_TYPE_RP_NUMBER).
-define(DNS_TYPE_RP_NUMBER, 17).
-define(DNS_TYPE_RP_BSTR, <<"RP">>).
-define(DNS_TYPE_AFSDB, ?DNS_TYPE_AFSDB_NUMBER).
-define(DNS_TYPE_AFSDB_NUMBER, 18).
-define(DNS_TYPE_AFSDB_BSTR, <<"AFSDB">>).
-define(DNS_TYPE_X25, ?DNS_TYPE_X25_NUMBER).
-define(DNS_TYPE_X25_NUMBER, 19).
-define(DNS_TYPE_X25_BSTR, <<"X25">>).
-define(DNS_TYPE_ISDN, ?DNS_TYPE_ISDN_NUMBER).
-define(DNS_TYPE_ISDN_NUMBER, 20).
-define(DNS_TYPE_ISDN_BSTR, <<"ISDN">>).
-define(DNS_TYPE_RT, ?DNS_TYPE_RT_NUMBER).
-define(DNS_TYPE_RT_NUMBER, 21).
-define(DNS_TYPE_RT_BSTR, <<"RT">>).
-define(DNS_TYPE_NSAP, ?DNS_TYPE_NSAP_NUMBER).
-define(DNS_TYPE_NSAP_NUMBER, 22).
-define(DNS_TYPE_NSAP_BSTR, <<"NSAP">>).
-define(DNS_TYPE_SIG, ?DNS_TYPE_SIG_NUMBER).
-define(DNS_TYPE_SIG_NUMBER, 24).
-define(DNS_TYPE_SIG_BSTR, <<"SIG">>).
-define(DNS_TYPE_KEY, ?DNS_TYPE_KEY_NUMBER).
-define(DNS_TYPE_KEY_NUMBER, 25).
-define(DNS_TYPE_KEY_BSTR, <<"KEY">>).
-define(DNS_TYPE_PX, ?DNS_TYPE_PX_NUMBER).
-define(DNS_TYPE_PX_NUMBER, 26).
-define(DNS_TYPE_PX_BSTR, <<"PX">>).
-define(DNS_TYPE_GPOS, ?DNS_TYPE_GPOS_NUMBER).
-define(DNS_TYPE_GPOS_NUMBER, 27).
-define(DNS_TYPE_GPOS_BSTR, <<"GPOS">>).
-define(DNS_TYPE_AAAA, ?DNS_TYPE_AAAA_NUMBER).
-define(DNS_TYPE_AAAA_NUMBER, 28).
-define(DNS_TYPE_AAAA_BSTR, <<"AAAA">>).
-define(DNS_TYPE_LOC, ?DNS_TYPE_LOC_NUMBER).
-define(DNS_TYPE_LOC_NUMBER, 29).
-define(DNS_TYPE_LOC_BSTR, <<"LOC">>).
-define(DNS_TYPE_NXT, ?DNS_TYPE_NXT_NUMBER).
-define(DNS_TYPE_NXT_NUMBER, 30).
-define(DNS_TYPE_NXT_BSTR, <<"NXT">>).
-define(DNS_TYPE_EID, ?DNS_TYPE_EID_NUMBER).
-define(DNS_TYPE_EID_NUMBER, 31).
-define(DNS_TYPE_EID_BSTR, <<"EID">>).
-define(DNS_TYPE_NIMLOC, ?DNS_TYPE_NIMLOC_NUMBER).
-define(DNS_TYPE_NIMLOC_NUMBER, 32).
-define(DNS_TYPE_NIMLOC_BSTR, <<"NIMLOC">>).
-define(DNS_TYPE_SRV, ?DNS_TYPE_SRV_NUMBER).
-define(DNS_TYPE_SRV_NUMBER, 33).
-define(DNS_TYPE_SRV_BSTR, <<"SRV">>).
-define(DNS_TYPE_ATMA, ?DNS_TYPE_ATMA_NUMBER).
-define(DNS_TYPE_ATMA_NUMBER, 34).
-define(DNS_TYPE_ATMA_BSTR, <<"ATMA">>).
-define(DNS_TYPE_NAPTR, ?DNS_TYPE_NAPTR_NUMBER).
-define(DNS_TYPE_NAPTR_NUMBER, 35).
-define(DNS_TYPE_NAPTR_BSTR, <<"NAPTR">>).
-define(DNS_TYPE_KX, ?DNS_TYPE_KX_NUMBER).
-define(DNS_TYPE_KX_NUMBER, 36).
-define(DNS_TYPE_KX_BSTR, <<"KX">>).
-define(DNS_TYPE_CERT, ?DNS_TYPE_CERT_NUMBER).
-define(DNS_TYPE_CERT_NUMBER, 37).
-define(DNS_TYPE_CERT_BSTR, <<"CERT">>).
-define(DNS_TYPE_DNAME, ?DNS_TYPE_DNAME_NUMBER).
-define(DNS_TYPE_DNAME_NUMBER, 39).
-define(DNS_TYPE_DNAME_BSTR, <<"DNAME">>).
-define(DNS_TYPE_SINK, ?DNS_TYPE_SINK_NUMBER).
-define(DNS_TYPE_SINK_NUMBER, 40).
-define(DNS_TYPE_SINK_BSTR, <<"SINK">>).
-define(DNS_TYPE_OPT, ?DNS_TYPE_OPT_NUMBER).
-define(DNS_TYPE_OPT_NUMBER, 41).
-define(DNS_TYPE_OPT_BSTR, <<"OPT">>).
-define(DNS_TYPE_APL, ?DNS_TYPE_APL_NUMBER).
-define(DNS_TYPE_APL_NUMBER, 42).
-define(DNS_TYPE_APL_BSTR, <<"APL">>).
-define(DNS_TYPE_DS, ?DNS_TYPE_DS_NUMBER).
-define(DNS_TYPE_DS_NUMBER, 43).
-define(DNS_TYPE_DS_BSTR, <<"DS">>).
-define(DNS_TYPE_CDS, ?DNS_TYPE_CDS_NUMBER).
-define(DNS_TYPE_CDS_NUMBER, 59).
-define(DNS_TYPE_CDS_BSTR, <<"CDS">>).
-define(DNS_TYPE_SSHFP, ?DNS_TYPE_SSHFP_NUMBER).
-define(DNS_TYPE_SSHFP_NUMBER, 44).
-define(DNS_TYPE_SSHFP_BSTR, <<"SSHFP">>).
-define(DNS_TYPE_IPSECKEY, ?DNS_TYPE_IPSECKEY_NUMBER).
-define(DNS_TYPE_IPSECKEY_NUMBER, 45).
-define(DNS_TYPE_IPSECKEY_BSTR, <<"IPSECKEY">>).
-define(DNS_TYPE_RRSIG, ?DNS_TYPE_RRSIG_NUMBER).
-define(DNS_TYPE_RRSIG_NUMBER, 46).
-define(DNS_TYPE_RRSIG_BSTR, <<"RRSIG">>).
-define(DNS_TYPE_NSEC, ?DNS_TYPE_NSEC_NUMBER).
-define(DNS_TYPE_NSEC_NUMBER, 47).
-define(DNS_TYPE_NSEC_BSTR, <<"NSEC">>).
-define(DNS_TYPE_DNSKEY, ?DNS_TYPE_DNSKEY_NUMBER).
-define(DNS_TYPE_DNSKEY_NUMBER, 48).
-define(DNS_TYPE_DNSKEY_BSTR, <<"DNSKEY">>).
-define(DNS_TYPE_CDNSKEY, ?DNS_TYPE_CDNSKEY_NUMBER).
-define(DNS_TYPE_CDNSKEY_NUMBER, 60).
-define(DNS_TYPE_CDNSKEY_BSTR, <<"CDNSKEY">>).
-define(DNS_TYPE_NSEC3, ?DNS_TYPE_NSEC3_NUMBER).
-define(DNS_TYPE_NSEC3_NUMBER, 50).
-define(DNS_TYPE_NSEC3_BSTR, <<"NSEC3">>).
-define(DNS_TYPE_NSEC3PARAM, ?DNS_TYPE_NSEC3PARAM_NUMBER).
-define(DNS_TYPE_NSEC3PARAM_NUMBER, 51).
-define(DNS_TYPE_NSEC3PARAM_BSTR, <<"NSEC3PARAM">>).
-define(DNS_TYPE_DHCID, ?DNS_TYPE_DHCID_NUMBER).
-define(DNS_TYPE_DHCID_NUMBER, 49).
-define(DNS_TYPE_DHCID_BSTR, <<"DHCID">>).
-define(DNS_TYPE_HIP, ?DNS_TYPE_HIP_NUMBER).
-define(DNS_TYPE_HIP_NUMBER, 55).
-define(DNS_TYPE_HIP_BSTR, <<"HIP">>).
-define(DNS_TYPE_NINFO, ?DNS_TYPE_NINFO_NUMBER).
-define(DNS_TYPE_NINFO_NUMBER, 56).
-define(DNS_TYPE_NINFO_BSTR, <<"NINFO">>).
-define(DNS_TYPE_RKEY, ?DNS_TYPE_RKEY_NUMBER).
-define(DNS_TYPE_RKEY_NUMBER, 57).
-define(DNS_TYPE_RKEY_BSTR, <<"RKEY">>).
-define(DNS_TYPE_TALINK, ?DNS_TYPE_TALINK_NUMBER).
-define(DNS_TYPE_TALINK_NUMBER, 58).
-define(DNS_TYPE_TALINK_BSTR, <<"TALINK">>).
-define(DNS_TYPE_SVCB, ?DNS_TYPE_SVCB_NUMBER).
-define(DNS_TYPE_SVCB_NUMBER, 64).
-define(DNS_TYPE_SVCB_BSTR, <<"SVCB">>).
-define(DNS_TYPE_HTTPS, ?DNS_TYPE_HTTPS_NUMBER).
-define(DNS_TYPE_HTTPS_NUMBER, 65).
-define(DNS_TYPE_HTTPS_BSTR, <<"HTTPS">>).
-define(DNS_TYPE_SPF, ?DNS_TYPE_SPF_NUMBER).
-define(DNS_TYPE_SPF_NUMBER, 99).
-define(DNS_TYPE_SPF_BSTR, <<"SPF">>).
-define(DNS_TYPE_UINFO, ?DNS_TYPE_UINFO_NUMBER).
-define(DNS_TYPE_UINFO_NUMBER, 100).
-define(DNS_TYPE_UINFO_BSTR, <<"UINFO">>).
-define(DNS_TYPE_UID, ?DNS_TYPE_UID_NUMBER).
-define(DNS_TYPE_UID_NUMBER, 101).
-define(DNS_TYPE_UID_BSTR, <<"UID">>).
-define(DNS_TYPE_GID, ?DNS_TYPE_GID_NUMBER).
-define(DNS_TYPE_GID_NUMBER, 102).
-define(DNS_TYPE_GID_BSTR, <<"GID">>).
-define(DNS_TYPE_UNSPEC, ?DNS_TYPE_UNSPEC_NUMBER).
-define(DNS_TYPE_UNSPEC_NUMBER, 103).
-define(DNS_TYPE_UNSPEC_BSTR, <<"UNSPEC">>).
-define(DNS_TYPE_NXNAME, ?DNS_TYPE_NXNAME_NUMBER).
-define(DNS_TYPE_NXNAME_NUMBER, 128).
-define(DNS_TYPE_NXNAME_BSTR, <<"NXNAME">>).
-define(DNS_TYPE_TKEY, ?DNS_TYPE_TKEY_NUMBER).
-define(DNS_TYPE_TKEY_NUMBER, 249).
-define(DNS_TYPE_TKEY_BSTR, <<"TKEY">>).
-define(DNS_TYPE_TSIG, ?DNS_TYPE_TSIG_NUMBER).
-define(DNS_TYPE_TSIG_NUMBER, 250).
-define(DNS_TYPE_TSIG_BSTR, <<"TSIG">>).
-define(DNS_TYPE_IXFR, ?DNS_TYPE_IXFR_NUMBER).
-define(DNS_TYPE_IXFR_NUMBER, 251).
-define(DNS_TYPE_IXFR_BSTR, <<"IXFR">>).
-define(DNS_TYPE_AXFR, ?DNS_TYPE_AXFR_NUMBER).
-define(DNS_TYPE_AXFR_NUMBER, 252).
-define(DNS_TYPE_AXFR_BSTR, <<"AXFR">>).
-define(DNS_TYPE_MAILB, ?DNS_TYPE_MAILB_NUMBER).
-define(DNS_TYPE_MAILB_NUMBER, 253).
-define(DNS_TYPE_MAILB_BSTR, <<"MAILB">>).
-define(DNS_TYPE_MAILA, ?DNS_TYPE_MAILA_NUMBER).
-define(DNS_TYPE_MAILA_NUMBER, 254).
-define(DNS_TYPE_MAILA_BSTR, <<"MAILA">>).
-define(DNS_TYPE_ANY, ?DNS_TYPE_ANY_NUMBER).
-define(DNS_TYPE_ANY_BSTR, <<"ANY">>).
-define(DNS_TYPE_ANY_NUMBER, 255).
-define(DNS_TYPE_CAA, ?DNS_TYPE_CAA_NUMBER).
-define(DNS_TYPE_CAA_NUMBER, 257).
-define(DNS_TYPE_CAA_BSTR, <<"CAA">>).
-define(DNS_TYPE_DLV, ?DNS_TYPE_DLV_NUMBER).
-define(DNS_TYPE_DLV_NUMBER, 32769).
-define(DNS_TYPE_DLV_BSTR, <<"DLV">>).
-define(DNS_RCODE_NOERROR, ?DNS_RCODE_NOERROR_NUMBER).
-define(DNS_RCODE_NOERROR_NUMBER, 0).
-define(DNS_RCODE_NOERROR_BSTR, <<"NOERROR">>).
-define(DNS_RCODE_FORMERR, ?DNS_RCODE_FORMERR_NUMBER).
-define(DNS_RCODE_FORMERR_NUMBER, 1).
-define(DNS_RCODE_FORMERR_BSTR, <<"FORMERR">>).
-define(DNS_RCODE_SERVFAIL, ?DNS_RCODE_SERVFAIL_NUMBER).
-define(DNS_RCODE_SERVFAIL_NUMBER, 2).
-define(DNS_RCODE_SERVFAIL_BSTR, <<"SERVFAIL">>).
-define(DNS_RCODE_NXDOMAIN, ?DNS_RCODE_NXDOMAIN_NUMBER).
-define(DNS_RCODE_NXDOMAIN_NUMBER, 3).
-define(DNS_RCODE_NXDOMAIN_BSTR, <<"NXDOMAIN">>).
-define(DNS_RCODE_NOTIMP, ?DNS_RCODE_NOTIMP_NUMBER).
-define(DNS_RCODE_NOTIMP_NUMBER, 4).
-define(DNS_RCODE_NOTIMP_BSTR, <<"NOTIMP">>).
-define(DNS_RCODE_REFUSED, ?DNS_RCODE_REFUSED_NUMBER).
-define(DNS_RCODE_REFUSED_NUMBER, 5).
-define(DNS_RCODE_REFUSED_BSTR, <<"REFUSED">>).
-define(DNS_RCODE_YXDOMAIN, ?DNS_RCODE_YXDOMAIN_NUMBER).
-define(DNS_RCODE_YXDOMAIN_NUMBER, 6).
-define(DNS_RCODE_YXDOMAIN_BSTR, <<"YXDOMAIN">>).
-define(DNS_RCODE_YXRRSET, ?DNS_RCODE_YXRRSET_NUMBER).
-define(DNS_RCODE_YXRRSET_NUMBER, 7).
-define(DNS_RCODE_YXRRSET_BSTR, <<"YXRRSET">>).
-define(DNS_RCODE_NXRRSET, ?DNS_RCODE_NXRRSET_NUMBER).
-define(DNS_RCODE_NXRRSET_NUMBER, 8).
-define(DNS_RCODE_NXRRSET_BSTR, <<"NXRRSET">>).
-define(DNS_RCODE_NOTAUTH, ?DNS_RCODE_NOTAUTH_NUMBER).
-define(DNS_RCODE_NOTAUTH_NUMBER, 9).
-define(DNS_RCODE_NOTAUTH_BSTR, <<"NOTAUTH">>).
-define(DNS_RCODE_NOTZONE, ?DNS_RCODE_NOTZONE_NUMBER).
-define(DNS_RCODE_NOTZONE_NUMBER, 10).
-define(DNS_RCODE_NOTZONE_BSTR, <<"NOTZONE">>).
-define(DNS_OPCODE_QUERY, ?DNS_OPCODE_QUERY_NUMBER).
-define(DNS_OPCODE_QUERY_NUMBER, 0).
-define(DNS_OPCODE_QUERY_BSTR, <<"'QUERY'">>).
-define(DNS_OPCODE_IQUERY, ?DNS_OPCODE_IQUERY_NUMBER).
-define(DNS_OPCODE_IQUERY_NUMBER, 1).
-define(DNS_OPCODE_IQUERY_BSTR, <<"IQUERY">>).
-define(DNS_OPCODE_STATUS, ?DNS_OPCODE_STATUS_NUMBER).
-define(DNS_OPCODE_STATUS_NUMBER, 2).
-define(DNS_OPCODE_STATUS_BSTR, <<"STATUS">>).
-define(DNS_OPCODE_UPDATE, ?DNS_OPCODE_UPDATE_NUMBER).
-define(DNS_OPCODE_UPDATE_NUMBER, 5).
-define(DNS_OPCODE_UPDATE_BSTR, <<"UPDATE">>).
-define(DNS_TSIGERR_NOERROR, ?DNS_TSIGERR_NOERROR_NUMBER).
-define(DNS_TSIGERR_NOERROR_NUMBER, 0).
-define(DNS_TSIGERR_NOERROR_BSTR, <<"NOERROR">>).
-define(DNS_TSIGERR_BADSIG, ?DNS_TSIGERR_BADSIG_NUMBER).
-define(DNS_TSIGERR_BADSIG_NUMBER, 16).
-define(DNS_TSIGERR_BADSIG_BSTR, <<"BADSIG">>).
-define(DNS_TSIGERR_BADKEY, ?DNS_TSIGERR_BADKEY_NUMBER).
-define(DNS_TSIGERR_BADKEY_NUMBER, 17).
-define(DNS_TSIGERR_BADKEY_BSTR, <<"BADKEY">>).
-define(DNS_TSIGERR_BADTIME, ?DNS_TSIGERR_BADTIME_NUMBER).
-define(DNS_TSIGERR_BADTIME_NUMBER, 18).
-define(DNS_TSIGERR_BADTIME_BSTR, <<"BADTIME">>).
-define(DNS_ERCODE_NOERROR, ?DNS_ERCODE_NOERROR_NUMBER).
-define(DNS_ERCODE_NOERROR_NUMBER, (0 bsr 4)).
-define(DNS_ERCODE_NOERROR_BSTR, <<"NOERROR">>).
-define(DNS_ERCODE_BADVERS, ?DNS_ERCODE_BADVERS_NUMBER).
-define(DNS_ERCODE_BADVERS_NUMBER, (16 bsr 4)).
-define(DNS_ERCODE_BADVERS_BSTR, <<"BADVERS">>).
-define(DNS_ERCODE_BADCOOKIE, ?DNS_ERCODE_BADCOOKIE_NUMBER).
-define(DNS_ERCODE_BADCOOKIE_NUMBER, (23 bsr 4)).
-define(DNS_ERCODE_BADCOOKIE_BSTR, <<"BADCOOKIE">>).
-define(DNS_EOPTCODE_LLQ, ?DNS_EOPTCODE_LLQ_NUMBER).
-define(DNS_EOPTCODE_LLQ_NUMBER, 1).
-define(DNS_EOPTCODE_LLQ_BSTR, <<"LLQ">>).
-define(DNS_EOPTCODE_UL, ?DNS_EOPTCODE_UL_NUMBER).
-define(DNS_EOPTCODE_UL_NUMBER, 2).
-define(DNS_EOPTCODE_UL_BSTR, <<"UL">>).
-define(DNS_EOPTCODE_NSID, ?DNS_EOPTCODE_NSID_NUMBER).
-define(DNS_EOPTCODE_NSID_NUMBER, 3).
-define(DNS_EOPTCODE_NSID_BSTR, <<"NSID">>).
-define(DNS_EOPTCODE_OWNER, ?DNS_EOPTCODE_OWNER_NUMBER).
-define(DNS_EOPTCODE_OWNER_NUMBER, 4).
-define(DNS_EOPTCODE_OWNER_BSTR, <<"OWNER">>).
-define(DNS_EOPTCODE_ECS, ?DNS_EOPTCODE_ECS_NUMBER).
-define(DNS_EOPTCODE_ECS_NUMBER, 8).
-define(DNS_EOPTCODE_ECS_BSTR, <<"ECS">>).
-define(DNS_EOPTCODE_COOKIE, ?DNS_EOPTCODE_COOKIE_NUMBER).
-define(DNS_EOPTCODE_COOKIE_NUMBER, 10).
-define(DNS_EOPTCODE_COOKIE_BSTR, <<"COOKIE">>).
-define(DNS_LLQOPCODE_SETUP, ?DNS_LLQOPCODE_SETUP_NUMBER).
-define(DNS_LLQOPCODE_SETUP_NUMBER, 1).
-define(DNS_LLQOPCODE_SETUP_BSTR, <<"SETUP">>).
-define(DNS_LLQOPCODE_REFRESH, ?DNS_LLQOPCODE_REFRESH_NUMBER).
-define(DNS_LLQOPCODE_REFRESH_NUMBER, 2).
-define(DNS_LLQOPCODE_REFRESH_BSTR, <<"REFRESH">>).
-define(DNS_LLQOPCODE_EVENT, ?DNS_LLQOPCODE_EVENT_NUMBER).
-define(DNS_LLQOPCODE_EVENT_NUMBER, 3).
-define(DNS_LLQOPCODE_EVENT_BSTR, <<"EVENT">>).
-define(DNS_LLQERRCODE_NOERROR, ?DNS_LLQERRCODE_NOERROR_NUMBER).
-define(DNS_LLQERRCODE_NOERROR_NUMBER, 0).
-define(DNS_LLQERRCODE_NOERROR_BSTR, <<"NOERROR">>).
-define(DNS_LLQERRCODE_SERVFULL, ?DNS_LLQERRCODE_SERVFULL_NUMBER).
-define(DNS_LLQERRCODE_SERVFULL_NUMBER, 1).
-define(DNS_LLQERRCODE_SERVFULL_BSTR, <<"SERVFULL">>).
-define(DNS_LLQERRCODE_STATIC, ?DNS_LLQERRCODE_STATIC_NUMBER).
-define(DNS_LLQERRCODE_STATIC_NUMBER, 2).
-define(DNS_LLQERRCODE_STATIC_BSTR, <<"STATIC">>).
-define(DNS_LLQERRCODE_FORMATERR, ?DNS_LLQERRCODE_FORMATERR_NUMBER).
-define(DNS_LLQERRCODE_FORMATERR_NUMBER, 3).
-define(DNS_LLQERRCODE_FORMATERR_BSTR, <<"FORMATERR">>).
-define(DNS_LLQERRCODE_NOSUCHLLQ, ?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER).
-define(DNS_LLQERRCODE_NOSUCHLLQ_NUMBER, 4).
-define(DNS_LLQERRCODE_NOSUCHLLQ_BSTR, <<"NOSUCHLLQ">>).
-define(DNS_LLQERRCODE_BADVERS, ?DNS_LLQERRCODE_BADVERS_NUMBER).
-define(DNS_LLQERRCODE_BADVERS_NUMBER, 5).
-define(DNS_LLQERRCODE_BADVERS_BSTR, <<"BADVERS">>).
-define(DNS_LLQERRCODE_UNKNOWNERR, ?DNS_LLQERRCODE_UNKNOWNERR_NUMBER).
-define(DNS_LLQERRCODE_UNKNOWNERR_NUMBER, 6).
-define(DNS_LLQERRCODE_UNKNOWNERR_BSTR, <<"UNKNOWNERR">>).

-define(DNS_SVCB_PARAM_MANDATORY, ?DNS_SVCB_PARAM_MANDATORY_NUMBER).
-define(DNS_SVCB_PARAM_MANDATORY_NUMBER, 0).
-define(DNS_SVCB_PARAM_MANDATORY_BSTR, <<"mandatory">>).
-define(DNS_SVCB_PARAM_ALPN, ?DNS_SVCB_PARAM_ALPN_NUMBER).
-define(DNS_SVCB_PARAM_ALPN_NUMBER, 1).
-define(DNS_SVCB_PARAM_ALPN_BSTR, <<"alpn">>).
-define(DNS_SVCB_PARAM_NO_DEFAULT_ALPN, ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN_NUMBER).
-define(DNS_SVCB_PARAM_NO_DEFAULT_ALPN_NUMBER, 2).
-define(DNS_SVCB_PARAM_NO_DEFAULT_ALPN_BSTR, <<"no-default-alpn">>).
-define(DNS_SVCB_PARAM_PORT, ?DNS_SVCB_PARAM_PORT_NUMBER).
-define(DNS_SVCB_PARAM_PORT_NUMBER, 3).
-define(DNS_SVCB_PARAM_PORT_BSTR, <<"port">>).
-define(DNS_SVCB_PARAM_IPV4HINT, ?DNS_SVCB_PARAM_IPV4HINT_NUMBER).
-define(DNS_SVCB_PARAM_IPV4HINT_NUMBER, 4).
-define(DNS_SVCB_PARAM_IPV4HINT_BSTR, <<"ipv4hint">>).
-define(DNS_SVCB_PARAM_ECHCONFIG, ?DNS_SVCB_PARAM_ECHCONFIG_NUMBER).
-define(DNS_SVCB_PARAM_ECHCONFIG_NUMBER, 5).
-define(DNS_SVCB_PARAM_ECHCONFIG_BSTR, <<"echconfig">>).
-define(DNS_SVCB_PARAM_IPV6HINT, ?DNS_SVCB_PARAM_IPV6HINT_NUMBER).
-define(DNS_SVCB_PARAM_IPV6HINT_NUMBER, 6).
-define(DNS_SVCB_PARAM_IPV6HINT_BSTR, <<"ipv6hint">>).
-define(DNS_SVCB_PARAM_KEY65535, ?DNS_SVCB_PARAM_KEY65535_NUMBER).
-define(DNS_SVCB_PARAM_KEY65535_NUMBER, 65535).
-define(DNS_SVCB_PARAM_KEY65535_BSTR, <<"key65535">>).

-endif.
