-module(dns_names_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(UNKNOWN_INT, ((1 bsl 32) - 1)).

class_name_test_() ->
    {ok, Cases} = file:consult(filename:join("test", "rrdata_wire_samples.txt")),
    Classes = sets:to_list(sets:from_list([C || {C, _, _} <- Cases])),
    ExtraCases = [
        ?DNS_CLASS_IN_NUMBER,
        ?DNS_CLASS_CS_NUMBER,
        ?DNS_CLASS_CH_NUMBER,
        ?DNS_CLASS_HS_NUMBER,
        ?DNS_CLASS_NONE_NUMBER,
        ?DNS_CLASS_ANY_NUMBER
    ],
    [?_assertEqual(undefined, dns_names:class_name(?UNKNOWN_INT))] ++
        [?_assert(is_binary(dns_names:class_name(Alg))) || Alg <- ExtraCases] ++
        [?_assertEqual(true, is_binary(dns_names:class_name(C))) || C <- Classes].

type_name_test_() ->
    {ok, Cases} = file:consult(filename:join("test", "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([T || {_, T, _} <- Cases])),
    ExtraCases = [
        ?DNS_TYPE_A_NUMBER,
        ?DNS_TYPE_NS_NUMBER,
        ?DNS_TYPE_MD_NUMBER,
        ?DNS_TYPE_MF_NUMBER,
        ?DNS_TYPE_CNAME_NUMBER,
        ?DNS_TYPE_SOA_NUMBER,
        ?DNS_TYPE_MB_NUMBER,
        ?DNS_TYPE_MG_NUMBER,
        ?DNS_TYPE_MR_NUMBER,
        ?DNS_TYPE_NULL_NUMBER,
        ?DNS_TYPE_WKS_NUMBER,
        ?DNS_TYPE_PTR_NUMBER,
        ?DNS_TYPE_HINFO_NUMBER,
        ?DNS_TYPE_MINFO_NUMBER,
        ?DNS_TYPE_MX_NUMBER,
        ?DNS_TYPE_TXT_NUMBER,
        ?DNS_TYPE_RP_NUMBER,
        ?DNS_TYPE_AFSDB_NUMBER,
        ?DNS_TYPE_X25_NUMBER,
        ?DNS_TYPE_ISDN_NUMBER,
        ?DNS_TYPE_RT_NUMBER,
        ?DNS_TYPE_NSAP_NUMBER,
        ?DNS_TYPE_SIG_NUMBER,
        ?DNS_TYPE_KEY_NUMBER,
        ?DNS_TYPE_PX_NUMBER,
        ?DNS_TYPE_GPOS_NUMBER,
        ?DNS_TYPE_AAAA_NUMBER,
        ?DNS_TYPE_LOC_NUMBER,
        ?DNS_TYPE_NXT_NUMBER,
        ?DNS_TYPE_EID_NUMBER,
        ?DNS_TYPE_NIMLOC_NUMBER,
        ?DNS_TYPE_SRV_NUMBER,
        ?DNS_TYPE_ATMA_NUMBER,
        ?DNS_TYPE_NAPTR_NUMBER,
        ?DNS_TYPE_KX_NUMBER,
        ?DNS_TYPE_CERT_NUMBER,
        ?DNS_TYPE_DNAME_NUMBER,
        ?DNS_TYPE_SINK_NUMBER,
        ?DNS_TYPE_OPT_NUMBER,
        ?DNS_TYPE_APL_NUMBER,
        ?DNS_TYPE_DS_NUMBER,
        ?DNS_TYPE_CDS_NUMBER,
        ?DNS_TYPE_SSHFP_NUMBER,
        ?DNS_TYPE_CAA_NUMBER,
        ?DNS_TYPE_IPSECKEY_NUMBER,
        ?DNS_TYPE_RRSIG_NUMBER,
        ?DNS_TYPE_NSEC_NUMBER,
        ?DNS_TYPE_DNSKEY_NUMBER,
        ?DNS_TYPE_CDNSKEY_NUMBER,
        ?DNS_TYPE_NSEC3_NUMBER,
        ?DNS_TYPE_NSEC3PARAM_NUMBER,
        ?DNS_TYPE_DHCID_NUMBER,
        ?DNS_TYPE_HIP_NUMBER,
        ?DNS_TYPE_NINFO_NUMBER,
        ?DNS_TYPE_RKEY_NUMBER,
        ?DNS_TYPE_TALINK_NUMBER,
        ?DNS_TYPE_SPF_NUMBER,
        ?DNS_TYPE_UINFO_NUMBER,
        ?DNS_TYPE_UID_NUMBER,
        ?DNS_TYPE_GID_NUMBER,
        ?DNS_TYPE_UNSPEC_NUMBER,
        ?DNS_TYPE_NXNAME_NUMBER,
        ?DNS_TYPE_TKEY_NUMBER,
        ?DNS_TYPE_TSIG_NUMBER,
        ?DNS_TYPE_IXFR_NUMBER,
        ?DNS_TYPE_AXFR_NUMBER,
        ?DNS_TYPE_MAILB_NUMBER,
        ?DNS_TYPE_MAILA_NUMBER,
        ?DNS_TYPE_ANY_NUMBER,
        ?DNS_TYPE_DLV_NUMBER
    ],
    [?_assertEqual(undefined, dns_names:type_name(?UNKNOWN_INT))] ++
        [?_assert(is_binary(dns_names:type_name(Type))) || Type <- ExtraCases] ++
        [?_assertEqual(T =/= 999, is_binary(dns_names:type_name(T))) || T <- Types].

alg_terms_test_() ->
    Cases = [
        ?DNS_ALG_DSA,
        ?DNS_ALG_NSEC3DSA,
        ?DNS_ALG_RSASHA1,
        ?DNS_ALG_NSEC3RSASHA1,
        ?DNS_ALG_RSASHA256,
        ?DNS_ALG_RSASHA512
    ],
    L = [?_assert(is_binary(dns_names:alg_name(Alg))) || Alg <- Cases],
    [?_assertEqual(undefined, dns_names:alg_name(?UNKNOWN_INT)) | L].

rcode_terms_test_() ->
    Cases = [
        ?DNS_RCODE_NOERROR_NUMBER,
        ?DNS_RCODE_FORMERR_NUMBER,
        ?DNS_RCODE_SERVFAIL_NUMBER,
        ?DNS_RCODE_NXDOMAIN_NUMBER,
        ?DNS_RCODE_NOTIMP_NUMBER,
        ?DNS_RCODE_REFUSED_NUMBER,
        ?DNS_RCODE_YXDOMAIN_NUMBER,
        ?DNS_RCODE_YXRRSET_NUMBER,
        ?DNS_RCODE_NXRRSET_NUMBER,
        ?DNS_RCODE_NOTAUTH_NUMBER,
        ?DNS_RCODE_NOTZONE_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:rcode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:rcode_name(?UNKNOWN_INT)) | L].

optcode_terms_test_() ->
    Cases = [
        ?DNS_OPCODE_QUERY_NUMBER,
        ?DNS_OPCODE_IQUERY_NUMBER,
        ?DNS_OPCODE_STATUS_NUMBER,
        ?DNS_OPCODE_UPDATE_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:opcode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:opcode_name(?UNKNOWN_INT)) | L].

tsigerr_terms_test_() ->
    Cases = [
        ?DNS_TSIGERR_NOERROR_NUMBER,
        ?DNS_TSIGERR_BADSIG_NUMBER,
        ?DNS_TSIGERR_BADKEY_NUMBER,
        ?DNS_TSIGERR_BADTIME_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:tsigerr_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:tsigerr_name(?UNKNOWN_INT)) | L].

ercode_name_test_() ->
    Cases = [
        ?DNS_ERCODE_NOERROR_NUMBER,
        ?DNS_ERCODE_BADVERS_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:ercode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:ercode_name(?UNKNOWN_INT)) | L].

eoptcode_name_test_() ->
    Cases = [
        ?DNS_EOPTCODE_LLQ_NUMBER,
        ?DNS_EOPTCODE_UL_NUMBER,
        ?DNS_EOPTCODE_NSID_NUMBER,
        ?DNS_EOPTCODE_OWNER_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:eoptcode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:eoptcode_name(?UNKNOWN_INT)) | L].

llqopcode_name_test_() ->
    Cases = [
        ?DNS_LLQOPCODE_SETUP_NUMBER,
        ?DNS_LLQOPCODE_REFRESH_NUMBER,
        ?DNS_LLQOPCODE_EVENT_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:llqopcode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:llqopcode_name(?UNKNOWN_INT)) | L].

llqerrcode_name_test_() ->
    Cases = [
        ?DNS_LLQERRCODE_NOERROR_NUMBER,
        ?DNS_LLQERRCODE_SERVFULL_NUMBER,
        ?DNS_LLQERRCODE_STATIC_NUMBER,
        ?DNS_LLQERRCODE_FORMATERR_NUMBER,
        ?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER,
        ?DNS_LLQERRCODE_BADVERS_NUMBER,
        ?DNS_LLQERRCODE_UNKNOWNERR_NUMBER
    ],
    L = [?_assert(is_binary(dns_names:llqerrcode_name(Number))) || Number <- Cases],
    [?_assertEqual(undefined, dns_names:llqerrcode_name(?UNKNOWN_INT)) | L].
