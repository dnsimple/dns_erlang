-module(dns_names).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
Helpers to convert between DNS codes and their names.
""").

-include_lib("dns_erlang/include/dns.hrl").

-export([
    class_name/1,
    name_class/1,
    type_name/1,
    name_type/1,
    rcode_name/1,
    name_rcode/1,
    opcode_name/1,
    name_opcode/1,
    tsigerr_name/1,
    name_tsigerr/1,
    ercode_name/1,
    name_ercode/1,
    eoptcode_name/1,
    name_eoptcode/1,
    llqopcode_name/1,
    name_llqopcode/1,
    llqerrcode_name/1,
    name_llqerrcode/1,
    alg_name/1,
    name_alg/1,
    ede_code_text/1,
    ede_text_code/1,
    svcb_param_name/1,
    name_svcb_param/1
]).

%%%===================================================================
%%% DNS terms
%%%===================================================================

?DOC("Returns the name of the class as a binary string.").
-spec class_name(dns:class()) -> unicode:latin1_binary() | undefined.
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

?DOC("Returns the class type from a binary string.").
-spec name_class(unicode:latin1_binary()) -> dns:class() | undefined.
name_class(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_CLASS_IN_BSTR -> ?DNS_CLASS_IN_NUMBER;
        ?DNS_CLASS_CS_BSTR -> ?DNS_CLASS_CS_NUMBER;
        ?DNS_CLASS_CH_BSTR -> ?DNS_CLASS_CH_NUMBER;
        ?DNS_CLASS_HS_BSTR -> ?DNS_CLASS_HS_NUMBER;
        ?DNS_CLASS_NONE_BSTR -> ?DNS_CLASS_NONE_NUMBER;
        ?DNS_CLASS_ANY_BSTR -> ?DNS_CLASS_ANY_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of the type as a binary string.").
-spec type_name(dns:type()) -> unicode:latin1_binary() | undefined.
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
        ?DNS_TYPE_CDS_NUMBER -> ?DNS_TYPE_CDS_BSTR;
        ?DNS_TYPE_SSHFP_NUMBER -> ?DNS_TYPE_SSHFP_BSTR;
        ?DNS_TYPE_CAA_NUMBER -> ?DNS_TYPE_CAA_BSTR;
        ?DNS_TYPE_IPSECKEY_NUMBER -> ?DNS_TYPE_IPSECKEY_BSTR;
        ?DNS_TYPE_RRSIG_NUMBER -> ?DNS_TYPE_RRSIG_BSTR;
        ?DNS_TYPE_NSEC_NUMBER -> ?DNS_TYPE_NSEC_BSTR;
        ?DNS_TYPE_DNSKEY_NUMBER -> ?DNS_TYPE_DNSKEY_BSTR;
        ?DNS_TYPE_CDNSKEY_NUMBER -> ?DNS_TYPE_CDNSKEY_BSTR;
        ?DNS_TYPE_NSEC3_NUMBER -> ?DNS_TYPE_NSEC3_BSTR;
        ?DNS_TYPE_NSEC3PARAM_NUMBER -> ?DNS_TYPE_NSEC3PARAM_BSTR;
        ?DNS_TYPE_TLSA_NUMBER -> ?DNS_TYPE_TLSA_BSTR;
        ?DNS_TYPE_SMIMEA_NUMBER -> ?DNS_TYPE_SMIMEA_BSTR;
        ?DNS_TYPE_DHCID_NUMBER -> ?DNS_TYPE_DHCID_BSTR;
        ?DNS_TYPE_HIP_NUMBER -> ?DNS_TYPE_HIP_BSTR;
        ?DNS_TYPE_NINFO_NUMBER -> ?DNS_TYPE_NINFO_BSTR;
        ?DNS_TYPE_RKEY_NUMBER -> ?DNS_TYPE_RKEY_BSTR;
        ?DNS_TYPE_TALINK_NUMBER -> ?DNS_TYPE_TALINK_BSTR;
        ?DNS_TYPE_OPENPGPKEY_NUMBER -> ?DNS_TYPE_OPENPGPKEY_BSTR;
        ?DNS_TYPE_ZONEMD_NUMBER -> ?DNS_TYPE_ZONEMD_BSTR;
        ?DNS_TYPE_SVCB_NUMBER -> ?DNS_TYPE_SVCB_BSTR;
        ?DNS_TYPE_HTTPS_NUMBER -> ?DNS_TYPE_HTTPS_BSTR;
        ?DNS_TYPE_SPF_NUMBER -> ?DNS_TYPE_SPF_BSTR;
        ?DNS_TYPE_UINFO_NUMBER -> ?DNS_TYPE_UINFO_BSTR;
        ?DNS_TYPE_UID_NUMBER -> ?DNS_TYPE_UID_BSTR;
        ?DNS_TYPE_GID_NUMBER -> ?DNS_TYPE_GID_BSTR;
        ?DNS_TYPE_UNSPEC_NUMBER -> ?DNS_TYPE_UNSPEC_BSTR;
        ?DNS_TYPE_EUI48_NUMBER -> ?DNS_TYPE_EUI48_BSTR;
        ?DNS_TYPE_EUI64_NUMBER -> ?DNS_TYPE_EUI64_BSTR;
        ?DNS_TYPE_NXNAME_NUMBER -> ?DNS_TYPE_NXNAME_BSTR;
        ?DNS_TYPE_TKEY_NUMBER -> ?DNS_TYPE_TKEY_BSTR;
        ?DNS_TYPE_TSIG_NUMBER -> ?DNS_TYPE_TSIG_BSTR;
        ?DNS_TYPE_IXFR_NUMBER -> ?DNS_TYPE_IXFR_BSTR;
        ?DNS_TYPE_AXFR_NUMBER -> ?DNS_TYPE_AXFR_BSTR;
        ?DNS_TYPE_MAILB_NUMBER -> ?DNS_TYPE_MAILB_BSTR;
        ?DNS_TYPE_MAILA_NUMBER -> ?DNS_TYPE_MAILA_BSTR;
        ?DNS_TYPE_ANY_NUMBER -> ?DNS_TYPE_ANY_BSTR;
        ?DNS_TYPE_URI_NUMBER -> ?DNS_TYPE_URI_BSTR;
        ?DNS_TYPE_RESINFO_NUMBER -> ?DNS_TYPE_RESINFO_BSTR;
        ?DNS_TYPE_WALLET_NUMBER -> ?DNS_TYPE_WALLET_BSTR;
        ?DNS_TYPE_DLV_NUMBER -> ?DNS_TYPE_DLV_BSTR;
        _ -> undefined
    end.

?DOC("Converts from the string representation into the standard `t:dns:type/0` representation").
-spec name_type(unicode:latin1_binary()) -> dns:type() | undefined.
name_type(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_TYPE_A_BSTR -> ?DNS_TYPE_A_NUMBER;
        ?DNS_TYPE_NS_BSTR -> ?DNS_TYPE_NS_NUMBER;
        ?DNS_TYPE_MD_BSTR -> ?DNS_TYPE_MD_NUMBER;
        ?DNS_TYPE_MF_BSTR -> ?DNS_TYPE_MF_NUMBER;
        ?DNS_TYPE_CNAME_BSTR -> ?DNS_TYPE_CNAME_NUMBER;
        ?DNS_TYPE_SOA_BSTR -> ?DNS_TYPE_SOA_NUMBER;
        ?DNS_TYPE_MB_BSTR -> ?DNS_TYPE_MB_NUMBER;
        ?DNS_TYPE_MG_BSTR -> ?DNS_TYPE_MG_NUMBER;
        ?DNS_TYPE_MR_BSTR -> ?DNS_TYPE_MR_NUMBER;
        ?DNS_TYPE_NULL_BSTR -> ?DNS_TYPE_NULL_NUMBER;
        ?DNS_TYPE_WKS_BSTR -> ?DNS_TYPE_WKS_NUMBER;
        ?DNS_TYPE_PTR_BSTR -> ?DNS_TYPE_PTR_NUMBER;
        ?DNS_TYPE_HINFO_BSTR -> ?DNS_TYPE_HINFO_NUMBER;
        ?DNS_TYPE_MINFO_BSTR -> ?DNS_TYPE_MINFO_NUMBER;
        ?DNS_TYPE_MX_BSTR -> ?DNS_TYPE_MX_NUMBER;
        ?DNS_TYPE_TXT_BSTR -> ?DNS_TYPE_TXT_NUMBER;
        ?DNS_TYPE_RP_BSTR -> ?DNS_TYPE_RP_NUMBER;
        ?DNS_TYPE_AFSDB_BSTR -> ?DNS_TYPE_AFSDB_NUMBER;
        ?DNS_TYPE_X25_BSTR -> ?DNS_TYPE_X25_NUMBER;
        ?DNS_TYPE_ISDN_BSTR -> ?DNS_TYPE_ISDN_NUMBER;
        ?DNS_TYPE_RT_BSTR -> ?DNS_TYPE_RT_NUMBER;
        ?DNS_TYPE_NSAP_BSTR -> ?DNS_TYPE_NSAP_NUMBER;
        ?DNS_TYPE_SIG_BSTR -> ?DNS_TYPE_SIG_NUMBER;
        ?DNS_TYPE_KEY_BSTR -> ?DNS_TYPE_KEY_NUMBER;
        ?DNS_TYPE_PX_BSTR -> ?DNS_TYPE_PX_NUMBER;
        ?DNS_TYPE_GPOS_BSTR -> ?DNS_TYPE_GPOS_NUMBER;
        ?DNS_TYPE_AAAA_BSTR -> ?DNS_TYPE_AAAA_NUMBER;
        ?DNS_TYPE_LOC_BSTR -> ?DNS_TYPE_LOC_NUMBER;
        ?DNS_TYPE_NXT_BSTR -> ?DNS_TYPE_NXT_NUMBER;
        ?DNS_TYPE_EID_BSTR -> ?DNS_TYPE_EID_NUMBER;
        ?DNS_TYPE_NIMLOC_BSTR -> ?DNS_TYPE_NIMLOC_NUMBER;
        ?DNS_TYPE_SRV_BSTR -> ?DNS_TYPE_SRV_NUMBER;
        ?DNS_TYPE_ATMA_BSTR -> ?DNS_TYPE_ATMA_NUMBER;
        ?DNS_TYPE_NAPTR_BSTR -> ?DNS_TYPE_NAPTR_NUMBER;
        ?DNS_TYPE_KX_BSTR -> ?DNS_TYPE_KX_NUMBER;
        ?DNS_TYPE_CERT_BSTR -> ?DNS_TYPE_CERT_NUMBER;
        ?DNS_TYPE_DNAME_BSTR -> ?DNS_TYPE_DNAME_NUMBER;
        ?DNS_TYPE_SINK_BSTR -> ?DNS_TYPE_SINK_NUMBER;
        ?DNS_TYPE_OPT_BSTR -> ?DNS_TYPE_OPT_NUMBER;
        ?DNS_TYPE_APL_BSTR -> ?DNS_TYPE_APL_NUMBER;
        ?DNS_TYPE_DS_BSTR -> ?DNS_TYPE_DS_NUMBER;
        ?DNS_TYPE_CDS_BSTR -> ?DNS_TYPE_CDS_NUMBER;
        ?DNS_TYPE_SSHFP_BSTR -> ?DNS_TYPE_SSHFP_NUMBER;
        ?DNS_TYPE_CAA_BSTR -> ?DNS_TYPE_CAA_NUMBER;
        ?DNS_TYPE_IPSECKEY_BSTR -> ?DNS_TYPE_IPSECKEY_NUMBER;
        ?DNS_TYPE_RRSIG_BSTR -> ?DNS_TYPE_RRSIG_NUMBER;
        ?DNS_TYPE_NSEC_BSTR -> ?DNS_TYPE_NSEC_NUMBER;
        ?DNS_TYPE_DNSKEY_BSTR -> ?DNS_TYPE_DNSKEY_NUMBER;
        ?DNS_TYPE_CDNSKEY_BSTR -> ?DNS_TYPE_CDNSKEY_NUMBER;
        ?DNS_TYPE_NSEC3_BSTR -> ?DNS_TYPE_NSEC3_NUMBER;
        ?DNS_TYPE_NSEC3PARAM_BSTR -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
        ?DNS_TYPE_TLSA_BSTR -> ?DNS_TYPE_TLSA_NUMBER;
        ?DNS_TYPE_SMIMEA_BSTR -> ?DNS_TYPE_SMIMEA_NUMBER;
        ?DNS_TYPE_DHCID_BSTR -> ?DNS_TYPE_DHCID_NUMBER;
        ?DNS_TYPE_HIP_BSTR -> ?DNS_TYPE_HIP_NUMBER;
        ?DNS_TYPE_NINFO_BSTR -> ?DNS_TYPE_NINFO_NUMBER;
        ?DNS_TYPE_RKEY_BSTR -> ?DNS_TYPE_RKEY_NUMBER;
        ?DNS_TYPE_TALINK_BSTR -> ?DNS_TYPE_TALINK_NUMBER;
        ?DNS_TYPE_OPENPGPKEY_BSTR -> ?DNS_TYPE_OPENPGPKEY_NUMBER;
        ?DNS_TYPE_ZONEMD_BSTR -> ?DNS_TYPE_ZONEMD_NUMBER;
        ?DNS_TYPE_SVCB_BSTR -> ?DNS_TYPE_SVCB_NUMBER;
        ?DNS_TYPE_HTTPS_BSTR -> ?DNS_TYPE_HTTPS_NUMBER;
        ?DNS_TYPE_SPF_BSTR -> ?DNS_TYPE_SPF_NUMBER;
        ?DNS_TYPE_UINFO_BSTR -> ?DNS_TYPE_UINFO_NUMBER;
        ?DNS_TYPE_UID_BSTR -> ?DNS_TYPE_UID_NUMBER;
        ?DNS_TYPE_GID_BSTR -> ?DNS_TYPE_GID_NUMBER;
        ?DNS_TYPE_UNSPEC_BSTR -> ?DNS_TYPE_UNSPEC_NUMBER;
        ?DNS_TYPE_EUI48_BSTR -> ?DNS_TYPE_EUI48_NUMBER;
        ?DNS_TYPE_EUI64_BSTR -> ?DNS_TYPE_EUI64_NUMBER;
        ?DNS_TYPE_NXNAME_BSTR -> ?DNS_TYPE_NXNAME_NUMBER;
        ?DNS_TYPE_TKEY_BSTR -> ?DNS_TYPE_TKEY_NUMBER;
        ?DNS_TYPE_TSIG_BSTR -> ?DNS_TYPE_TSIG_NUMBER;
        ?DNS_TYPE_IXFR_BSTR -> ?DNS_TYPE_IXFR_NUMBER;
        ?DNS_TYPE_AXFR_BSTR -> ?DNS_TYPE_AXFR_NUMBER;
        ?DNS_TYPE_MAILB_BSTR -> ?DNS_TYPE_MAILB_NUMBER;
        ?DNS_TYPE_MAILA_BSTR -> ?DNS_TYPE_MAILA_NUMBER;
        ?DNS_TYPE_ANY_BSTR -> ?DNS_TYPE_ANY_NUMBER;
        ?DNS_TYPE_URI_BSTR -> ?DNS_TYPE_URI_NUMBER;
        ?DNS_TYPE_RESINFO_BSTR -> ?DNS_TYPE_RESINFO_NUMBER;
        ?DNS_TYPE_WALLET_BSTR -> ?DNS_TYPE_WALLET_NUMBER;
        ?DNS_TYPE_DLV_BSTR -> ?DNS_TYPE_DLV_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an rcode as a binary string.").
-spec rcode_name(dns:rcode()) -> unicode:latin1_binary() | undefined.
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

?DOC("Returns the name of an rcode as a binary string.").
-spec name_rcode(unicode:latin1_binary()) -> dns:rcode() | undefined.
name_rcode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_RCODE_NOERROR_BSTR -> ?DNS_RCODE_NOERROR_NUMBER;
        ?DNS_RCODE_FORMERR_BSTR -> ?DNS_RCODE_FORMERR_NUMBER;
        ?DNS_RCODE_SERVFAIL_BSTR -> ?DNS_RCODE_SERVFAIL_NUMBER;
        ?DNS_RCODE_NXDOMAIN_BSTR -> ?DNS_RCODE_NXDOMAIN_NUMBER;
        ?DNS_RCODE_NOTIMP_BSTR -> ?DNS_RCODE_NOTIMP_NUMBER;
        ?DNS_RCODE_REFUSED_BSTR -> ?DNS_RCODE_REFUSED_NUMBER;
        ?DNS_RCODE_YXDOMAIN_BSTR -> ?DNS_RCODE_YXDOMAIN_NUMBER;
        ?DNS_RCODE_YXRRSET_BSTR -> ?DNS_RCODE_YXRRSET_NUMBER;
        ?DNS_RCODE_NXRRSET_BSTR -> ?DNS_RCODE_NXRRSET_NUMBER;
        ?DNS_RCODE_NOTAUTH_BSTR -> ?DNS_RCODE_NOTAUTH_NUMBER;
        ?DNS_RCODE_NOTZONE_BSTR -> ?DNS_RCODE_NOTZONE_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an opcode as a binary string.").
-spec opcode_name(dns:opcode()) -> unicode:latin1_binary() | undefined.
opcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_OPCODE_QUERY_NUMBER -> ?DNS_OPCODE_QUERY_BSTR;
        ?DNS_OPCODE_IQUERY_NUMBER -> ?DNS_OPCODE_IQUERY_BSTR;
        ?DNS_OPCODE_STATUS_NUMBER -> ?DNS_OPCODE_STATUS_BSTR;
        ?DNS_OPCODE_UPDATE_NUMBER -> ?DNS_OPCODE_UPDATE_BSTR;
        _ -> undefined
    end.

?DOC("Returns the opcode from a binary string.").
-spec name_opcode(unicode:latin1_binary()) -> dns:opcode() | undefined.
name_opcode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_OPCODE_QUERY_BSTR -> ?DNS_OPCODE_QUERY_NUMBER;
        ?DNS_OPCODE_IQUERY_BSTR -> ?DNS_OPCODE_IQUERY_NUMBER;
        ?DNS_OPCODE_STATUS_BSTR -> ?DNS_OPCODE_STATUS_NUMBER;
        ?DNS_OPCODE_UPDATE_BSTR -> ?DNS_OPCODE_UPDATE_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of a DNS algorithm as a binary string.").
-spec alg_name(dns:alg()) -> unicode:latin1_binary() | undefined.
alg_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_ALG_DSA_NUMBER -> ?DNS_ALG_DSA_BSTR;
        ?DNS_ALG_NSEC3DSA_NUMBER -> ?DNS_ALG_NSEC3DSA_BSTR;
        ?DNS_ALG_RSASHA1_NUMBER -> ?DNS_ALG_RSASHA1_BSTR;
        ?DNS_ALG_NSEC3RSASHA1_NUMBER -> ?DNS_ALG_NSEC3RSASHA1_BSTR;
        ?DNS_ALG_RSASHA256_NUMBER -> ?DNS_ALG_RSASHA256_BSTR;
        ?DNS_ALG_RSASHA512_NUMBER -> ?DNS_ALG_RSASHA512_BSTR;
        ?DNS_ALG_ECDSAP256SHA256_NUMBER -> ?DNS_ALG_ECDSAP256SHA256_BSTR;
        ?DNS_ALG_ECDSAP384SHA384_NUMBER -> ?DNS_ALG_ECDSAP384SHA384_BSTR;
        ?DNS_ALG_ED25519_NUMBER -> ?DNS_ALG_ED25519_BSTR;
        ?DNS_ALG_ED448_NUMBER -> ?DNS_ALG_ED448_BSTR;
        _ -> undefined
    end.

?DOC("Returns the DNS algorithm from a binary string.").
-spec name_alg(unicode:latin1_binary()) -> dns:alg() | undefined.
name_alg(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_ALG_DSA_BSTR -> ?DNS_ALG_DSA_NUMBER;
        ?DNS_ALG_NSEC3DSA_BSTR -> ?DNS_ALG_NSEC3DSA_NUMBER;
        ?DNS_ALG_RSASHA1_BSTR -> ?DNS_ALG_RSASHA1_NUMBER;
        ?DNS_ALG_NSEC3RSASHA1_BSTR -> ?DNS_ALG_NSEC3RSASHA1_NUMBER;
        ?DNS_ALG_RSASHA256_BSTR -> ?DNS_ALG_RSASHA256_NUMBER;
        ?DNS_ALG_RSASHA512_BSTR -> ?DNS_ALG_RSASHA512_NUMBER;
        ?DNS_ALG_ECDSAP256SHA256_BSTR -> ?DNS_ALG_ECDSAP256SHA256_NUMBER;
        ?DNS_ALG_ECDSAP384SHA384_BSTR -> ?DNS_ALG_ECDSAP384SHA384_NUMBER;
        ?DNS_ALG_ED25519_BSTR -> ?DNS_ALG_ED25519_NUMBER;
        ?DNS_ALG_ED448_BSTR -> ?DNS_ALG_ED448_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an EDE code as a binary string.").
-spec ede_code_text(dns:uint16()) -> unicode:latin1_binary() | undefined.
ede_code_text(Int) when is_integer(Int) ->
    case Int of
        ?DNS_EDE_OTHER_ERROR_NUMBER -> ?DNS_EDE_OTHER_ERROR_BSTR;
        ?DNS_EDE_UNSUPPORTED_DNSKEY_ALG_NUMBER -> ?DNS_EDE_UNSUPPORTED_DNSKEY_ALG_BSTR;
        ?DNS_EDE_UNSUPPORTED_DS_DIGEST_NUMBER -> ?DNS_EDE_UNSUPPORTED_DS_DIGEST_BSTR;
        ?DNS_EDE_STALE_ANSWER_NUMBER -> ?DNS_EDE_STALE_ANSWER_BSTR;
        ?DNS_EDE_FORGED_ANSWER_NUMBER -> ?DNS_EDE_FORGED_ANSWER_BSTR;
        ?DNS_EDE_DNSSEC_INDETERMINATE_NUMBER -> ?DNS_EDE_DNSSEC_INDETERMINATE_BSTR;
        ?DNS_EDE_DNSSEC_BOGUS_NUMBER -> ?DNS_EDE_DNSSEC_BOGUS_BSTR;
        ?DNS_EDE_SIGNATURE_EXPIRED_NUMBER -> ?DNS_EDE_SIGNATURE_EXPIRED_BSTR;
        ?DNS_EDE_SIGNATURE_NOT_YET_VALID_NUMBER -> ?DNS_EDE_SIGNATURE_NOT_YET_VALID_BSTR;
        ?DNS_EDE_DNSKEY_MISSING_NUMBER -> ?DNS_EDE_DNSKEY_MISSING_BSTR;
        ?DNS_EDE_RRSIGS_MISSING_NUMBER -> ?DNS_EDE_RRSIGS_MISSING_BSTR;
        ?DNS_EDE_NO_ZONE_KEY_BIT_SET_NUMBER -> ?DNS_EDE_NO_ZONE_KEY_BIT_SET_BSTR;
        ?DNS_EDE_NSEC_MISSING_NUMBER -> ?DNS_EDE_NSEC_MISSING_BSTR;
        ?DNS_EDE_CACHED_ERROR_NUMBER -> ?DNS_EDE_CACHED_ERROR_BSTR;
        ?DNS_EDE_NOT_READY_NUMBER -> ?DNS_EDE_NOT_READY_BSTR;
        ?DNS_EDE_BLOCKED_NUMBER -> ?DNS_EDE_BLOCKED_BSTR;
        ?DNS_EDE_CENSORED_NUMBER -> ?DNS_EDE_CENSORED_BSTR;
        ?DNS_EDE_FILTERED_NUMBER -> ?DNS_EDE_FILTERED_BSTR;
        ?DNS_EDE_PROHIBITED_NUMBER -> ?DNS_EDE_PROHIBITED_BSTR;
        ?DNS_EDE_STALE_NXDOMAIN_ANSWER_NUMBER -> ?DNS_EDE_STALE_NXDOMAIN_ANSWER_BSTR;
        ?DNS_EDE_NOT_AUTHORITATIVE_NUMBER -> ?DNS_EDE_NOT_AUTHORITATIVE_BSTR;
        ?DNS_EDE_NOT_SUPPORTED_NUMBER -> ?DNS_EDE_NOT_SUPPORTED_BSTR;
        ?DNS_EDE_NO_REACHABLE_AUTHORITY_NUMBER -> ?DNS_EDE_NO_REACHABLE_AUTHORITY_BSTR;
        ?DNS_EDE_NETWORK_ERROR_NUMBER -> ?DNS_EDE_NETWORK_ERROR_BSTR;
        ?DNS_EDE_INVALID_DATA_NUMBER -> ?DNS_EDE_INVALID_DATA_BSTR;
        _ -> undefined
    end.

?DOC("Returns the EDE code from a binary string.").
-spec ede_text_code(unicode:latin1_binary()) -> dns:uint16() | undefined.
ede_text_code(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_EDE_OTHER_ERROR_BSTR -> ?DNS_EDE_OTHER_ERROR_NUMBER;
        ?DNS_EDE_UNSUPPORTED_DNSKEY_ALG_BSTR -> ?DNS_EDE_UNSUPPORTED_DNSKEY_ALG_NUMBER;
        ?DNS_EDE_UNSUPPORTED_DS_DIGEST_BSTR -> ?DNS_EDE_UNSUPPORTED_DS_DIGEST_NUMBER;
        ?DNS_EDE_STALE_ANSWER_BSTR -> ?DNS_EDE_STALE_ANSWER_NUMBER;
        ?DNS_EDE_FORGED_ANSWER_BSTR -> ?DNS_EDE_FORGED_ANSWER_NUMBER;
        ?DNS_EDE_DNSSEC_INDETERMINATE_BSTR -> ?DNS_EDE_DNSSEC_INDETERMINATE_NUMBER;
        ?DNS_EDE_DNSSEC_BOGUS_BSTR -> ?DNS_EDE_DNSSEC_BOGUS_NUMBER;
        ?DNS_EDE_SIGNATURE_EXPIRED_BSTR -> ?DNS_EDE_SIGNATURE_EXPIRED_NUMBER;
        ?DNS_EDE_SIGNATURE_NOT_YET_VALID_BSTR -> ?DNS_EDE_SIGNATURE_NOT_YET_VALID_NUMBER;
        ?DNS_EDE_DNSKEY_MISSING_BSTR -> ?DNS_EDE_DNSKEY_MISSING_NUMBER;
        ?DNS_EDE_RRSIGS_MISSING_BSTR -> ?DNS_EDE_RRSIGS_MISSING_NUMBER;
        ?DNS_EDE_NO_ZONE_KEY_BIT_SET_BSTR -> ?DNS_EDE_NO_ZONE_KEY_BIT_SET_NUMBER;
        ?DNS_EDE_NSEC_MISSING_BSTR -> ?DNS_EDE_NSEC_MISSING_NUMBER;
        ?DNS_EDE_CACHED_ERROR_BSTR -> ?DNS_EDE_CACHED_ERROR_NUMBER;
        ?DNS_EDE_NOT_READY_BSTR -> ?DNS_EDE_NOT_READY_NUMBER;
        ?DNS_EDE_BLOCKED_BSTR -> ?DNS_EDE_BLOCKED_NUMBER;
        ?DNS_EDE_CENSORED_BSTR -> ?DNS_EDE_CENSORED_NUMBER;
        ?DNS_EDE_FILTERED_BSTR -> ?DNS_EDE_FILTERED_NUMBER;
        ?DNS_EDE_PROHIBITED_BSTR -> ?DNS_EDE_PROHIBITED_NUMBER;
        ?DNS_EDE_STALE_NXDOMAIN_ANSWER_BSTR -> ?DNS_EDE_STALE_NXDOMAIN_ANSWER_NUMBER;
        ?DNS_EDE_NOT_AUTHORITATIVE_BSTR -> ?DNS_EDE_NOT_AUTHORITATIVE_NUMBER;
        ?DNS_EDE_NOT_SUPPORTED_BSTR -> ?DNS_EDE_NOT_SUPPORTED_NUMBER;
        ?DNS_EDE_NO_REACHABLE_AUTHORITY_BSTR -> ?DNS_EDE_NO_REACHABLE_AUTHORITY_NUMBER;
        ?DNS_EDE_NETWORK_ERROR_BSTR -> ?DNS_EDE_NETWORK_ERROR_NUMBER;
        ?DNS_EDE_INVALID_DATA_BSTR -> ?DNS_EDE_INVALID_DATA_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of a TSIG error as a binary string.").
-spec tsigerr_name(dns:tsig_error()) -> unicode:latin1_binary() | undefined.
tsigerr_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_TSIGERR_NOERROR_NUMBER -> ?DNS_TSIGERR_NOERROR_BSTR;
        ?DNS_TSIGERR_BADSIG_NUMBER -> ?DNS_TSIGERR_BADSIG_BSTR;
        ?DNS_TSIGERR_BADKEY_NUMBER -> ?DNS_TSIGERR_BADKEY_BSTR;
        ?DNS_TSIGERR_BADTIME_NUMBER -> ?DNS_TSIGERR_BADTIME_BSTR;
        _ -> undefined
    end.

?DOC("Returns the TSIG error from a binary string.").
-spec name_tsigerr(unicode:latin1_binary()) -> dns:tsig_error() | undefined.
name_tsigerr(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_TSIGERR_NOERROR_BSTR -> ?DNS_TSIGERR_NOERROR_NUMBER;
        ?DNS_TSIGERR_BADSIG_BSTR -> ?DNS_TSIGERR_BADSIG_NUMBER;
        ?DNS_TSIGERR_BADKEY_BSTR -> ?DNS_TSIGERR_BADKEY_NUMBER;
        ?DNS_TSIGERR_BADTIME_BSTR -> ?DNS_TSIGERR_BADTIME_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an extended rcode as a binary string.").
-spec ercode_name(dns:ercode()) -> unicode:latin1_binary() | undefined.
ercode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_ERCODE_NOERROR_NUMBER -> ?DNS_ERCODE_NOERROR_BSTR;
        ?DNS_ERCODE_BADVERS_NUMBER -> ?DNS_ERCODE_BADVERS_BSTR;
        ?DNS_ERCODE_BADCOOKIE_NUMBER -> ?DNS_ERCODE_BADCOOKIE_BSTR;
        _ -> undefined
    end.

?DOC("Returns the extended rcode from a binary string.").
-spec name_ercode(unicode:latin1_binary()) -> dns:ercode() | undefined.
name_ercode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_ERCODE_NOERROR_BSTR -> ?DNS_ERCODE_NOERROR_NUMBER;
        ?DNS_ERCODE_BADVERS_BSTR -> ?DNS_ERCODE_BADVERS_NUMBER;
        ?DNS_ERCODE_BADCOOKIE_BSTR -> ?DNS_ERCODE_BADCOOKIE_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an extended option as a binary string.").
-spec eoptcode_name(dns:eoptcode()) -> unicode:latin1_binary() | undefined.
eoptcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_EOPTCODE_LLQ_NUMBER -> ?DNS_EOPTCODE_LLQ_BSTR;
        ?DNS_EOPTCODE_UL_NUMBER -> ?DNS_EOPTCODE_UL_BSTR;
        ?DNS_EOPTCODE_NSID_NUMBER -> ?DNS_EOPTCODE_NSID_BSTR;
        ?DNS_EOPTCODE_OWNER_NUMBER -> ?DNS_EOPTCODE_OWNER_BSTR;
        _ -> undefined
    end.

?DOC("Returns the extended option from a binary string.").
-spec name_eoptcode(unicode:latin1_binary()) -> dns:eoptcode() | undefined.
name_eoptcode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_EOPTCODE_LLQ_BSTR -> ?DNS_EOPTCODE_LLQ_NUMBER;
        ?DNS_EOPTCODE_UL_BSTR -> ?DNS_EOPTCODE_UL_NUMBER;
        ?DNS_EOPTCODE_NSID_BSTR -> ?DNS_EOPTCODE_NSID_NUMBER;
        ?DNS_EOPTCODE_OWNER_BSTR -> ?DNS_EOPTCODE_OWNER_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an LLQ opcode as a binary string.").
-spec llqopcode_name(dns:llqopcode()) -> unicode:latin1_binary() | undefined.
llqopcode_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_LLQOPCODE_SETUP_NUMBER -> ?DNS_LLQOPCODE_SETUP_BSTR;
        ?DNS_LLQOPCODE_REFRESH_NUMBER -> ?DNS_LLQOPCODE_REFRESH_BSTR;
        ?DNS_LLQOPCODE_EVENT_NUMBER -> ?DNS_LLQOPCODE_EVENT_BSTR;
        _ -> undefined
    end.

?DOC("Returns LLQ opcode from a binary string.").
-spec name_llqopcode(unicode:latin1_binary()) -> dns:llqopcode() | undefined.
name_llqopcode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_LLQOPCODE_SETUP_BSTR -> ?DNS_LLQOPCODE_SETUP_NUMBER;
        ?DNS_LLQOPCODE_REFRESH_BSTR -> ?DNS_LLQOPCODE_REFRESH_NUMBER;
        ?DNS_LLQOPCODE_EVENT_BSTR -> ?DNS_LLQOPCODE_EVENT_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an LLQ error code as a binary string.").
-spec llqerrcode_name(dns:llqerrcode()) -> unicode:latin1_binary() | undefined.
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

?DOC("Returns the LLQ error code from a binary string.").
-spec name_llqerrcode(unicode:latin1_binary()) -> dns:llqerrcode() | undefined.
name_llqerrcode(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_LLQERRCODE_NOERROR_BSTR -> ?DNS_LLQERRCODE_NOERROR_NUMBER;
        ?DNS_LLQERRCODE_SERVFULL_BSTR -> ?DNS_LLQERRCODE_SERVFULL_NUMBER;
        ?DNS_LLQERRCODE_STATIC_BSTR -> ?DNS_LLQERRCODE_STATIC_NUMBER;
        ?DNS_LLQERRCODE_FORMATERR_BSTR -> ?DNS_LLQERRCODE_FORMATERR_NUMBER;
        ?DNS_LLQERRCODE_NOSUCHLLQ_BSTR -> ?DNS_LLQERRCODE_NOSUCHLLQ_NUMBER;
        ?DNS_LLQERRCODE_BADVERS_BSTR -> ?DNS_LLQERRCODE_BADVERS_NUMBER;
        ?DNS_LLQERRCODE_UNKNOWNERR_BSTR -> ?DNS_LLQERRCODE_UNKNOWNERR_NUMBER;
        _ -> undefined
    end.

?DOC("Returns the name of an SVCB parameter as a binary string.").
-spec svcb_param_name(dns:uint16()) -> unicode:latin1_binary() | undefined.
svcb_param_name(Int) when is_integer(Int) ->
    case Int of
        ?DNS_SVCB_PARAM_MANDATORY_NUMBER -> ?DNS_SVCB_PARAM_MANDATORY_BSTR;
        ?DNS_SVCB_PARAM_ALPN_NUMBER -> ?DNS_SVCB_PARAM_ALPN_BSTR;
        ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN_NUMBER -> ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN_BSTR;
        ?DNS_SVCB_PARAM_PORT_NUMBER -> ?DNS_SVCB_PARAM_PORT_BSTR;
        ?DNS_SVCB_PARAM_IPV4HINT_NUMBER -> ?DNS_SVCB_PARAM_IPV4HINT_BSTR;
        ?DNS_SVCB_PARAM_ECH_NUMBER -> ?DNS_SVCB_PARAM_ECH_BSTR;
        ?DNS_SVCB_PARAM_IPV6HINT_NUMBER -> ?DNS_SVCB_PARAM_IPV6HINT_BSTR;
        _ -> <<"key", (integer_to_binary(Int))/binary>>
    end.

?DOC("Returns the SVCB parameter from a binary string.").
-spec name_svcb_param(unicode:latin1_binary()) -> dns:uint16() | undefined.
name_svcb_param(Bin) when is_binary(Bin) ->
    case Bin of
        ?DNS_SVCB_PARAM_MANDATORY_BSTR ->
            ?DNS_SVCB_PARAM_MANDATORY_NUMBER;
        ?DNS_SVCB_PARAM_ALPN_BSTR ->
            ?DNS_SVCB_PARAM_ALPN_NUMBER;
        ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN_BSTR ->
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN_NUMBER;
        ?DNS_SVCB_PARAM_PORT_BSTR ->
            ?DNS_SVCB_PARAM_PORT_NUMBER;
        ?DNS_SVCB_PARAM_IPV4HINT_BSTR ->
            ?DNS_SVCB_PARAM_IPV4HINT_NUMBER;
        ?DNS_SVCB_PARAM_ECH_BSTR ->
            ?DNS_SVCB_PARAM_ECH_NUMBER;
        ?DNS_SVCB_PARAM_IPV6HINT_BSTR ->
            ?DNS_SVCB_PARAM_IPV6HINT_NUMBER;
        <<"key", KeyNum/binary>> ->
            try binary_to_integer(KeyNum) of
                KeyInt when KeyInt >= 0, KeyInt =< 65535 -> KeyInt;
                _ -> undefined
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.
