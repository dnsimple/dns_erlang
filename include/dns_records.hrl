-ifndef('DNS_RECORDS').
-define('DNS_RECORDS', ok).
-include("dns_terms.hrl").

%% DNS Message format. See RFC 1035: §4.1.1.
-record(dns_message, {
    id = dns:random_id() :: dns:message_id(),
    qr = false :: boolean(),
    oc = ?DNS_OPCODE_QUERY :: dns:opcode(),
    aa = false :: boolean(),
    tc = false :: boolean(),
    rd = false :: boolean(),
    ra = false :: boolean(),
    ad = false :: boolean(),
    cd = false :: boolean(),
    rc = ?DNS_RCODE_NOERROR :: dns:rcode(),
    qc = 0 :: dns:uint16(),
    anc = 0 :: dns:uint16(),
    auc = 0 :: dns:uint16(),
    adc = 0 :: dns:uint16(),
    questions = [] :: dns:questions(),
    answers = [] :: dns:answers(),
    authority = [] :: dns:authority(),
    additional = [] :: dns:additional()
}).

%% DNS Query format. See RFC 1035.
-record(dns_query, {
    name :: dns:dname(),
    class = ?DNS_CLASS_IN :: dns:class(),
    type :: dns:type()
}).

%% DNS Resource Record format. See RFC 1035.
-record(dns_rr, {
    name :: dns:dname(),
    type :: dns:type(),
    class = ?DNS_CLASS_IN :: dns:class(),
    ttl = 0 :: dns:ttl(),
    data :: dns:rrdata()
}).

%% A record for IPv4 addresses. See RFC 1035.
-record(dns_rrdata_a, {
    ip :: inet:ip4_address()
}).

%% AAAA record for IPv6 addresses. See RFC 3596.
-record(dns_rrdata_aaaa, {
    ip :: inet:ip6_address()
}).

%% AFSDB record for AFS database location. See RFC 1183.
-record(dns_rrdata_afsdb, {
    subtype :: dns:uint16(),
    hostname :: dns:dname()
}).

%% CAA record for Certificate Authority Authorization. See RFC 6844: §5.
-record(dns_rrdata_caa, {
    flags :: dns:uint8(),
    tag :: binary(),
    value :: binary()
}).

%% CERT record for storing certificates in DNS. See RFC 4398.
-record(dns_rrdata_cert, {
    type :: dns:uint16(),
    key_tag :: dns:uint16(),
    alg :: dns:uint8(),
    cert :: binary()
}).

%% CNAME record for canonical name. See RFC 1035: §3.3.1.
-record(dns_rrdata_cname, {
    dname :: dns:dname()
}).

%% DHCID record for DHCP Information. See RFC 4701: §3.1.
-record(dns_rrdata_dhcid, {
    data :: binary()
}).

%% DLV record for DNSSEC Lookaside Validation. See RFC 4431. As dns_rrdata_ds.
-record(dns_rrdata_dlv, {
    keytag :: dns:uint16(),
    alg :: dns:uint8(),
    digest_type :: dns:uint8(),
    digest :: binary()
}).

%% DNAME record for delegation of reverse mapping. See RFC 6672: §2.1.
-record(dns_rrdata_dname, {
    dname :: dns:dname()
}).

%% DNSKEY record for DNSSEC public key. See RFC 4034: §2.1.
-record(dns_rrdata_dnskey, {
    flags :: dns:uint16(),
    protocol :: dns:uint8(),
    alg :: dns:uint8(),
    public_key :: iodata(),
    key_tag :: integer()
}).

%% CDNSKEY record for Child DNSKEY. See RFC 7344.
-record(dns_rrdata_cdnskey, {
    flags :: dns:uint16(),
    protocol :: dns:uint8(),
    alg :: dns:uint8(),
    public_key :: iodata(),
    key_tag :: integer()
}).

%% DS record for Delegation Signer. See RFC 4034: §5.1.
-record(dns_rrdata_ds, {
    keytag :: dns:uint16(),
    alg :: dns:uint8(),
    digest_type :: dns:uint8(),
    digest :: binary()
}).

%% CDS record for Child DS. See RFC 7344.
-record(dns_rrdata_cds, {
    keytag :: dns:uint16(),
    alg :: dns:uint8(),
    digest_type :: dns:uint8(),
    digest :: binary()
}).

%% HINFO record for host information. See RFC 1035: §3.3.2.
-record(dns_rrdata_hinfo, {
    %% each binary is less than 255 bytes
    cpu :: binary(),
    os :: binary()
}).

%% IPSECKEY record for storing IPsec keying material. See RFC 4025: §2.
-record(dns_rrdata_ipseckey, {
    precedence :: dns:uint8(),
    alg :: dns:uint8(),
    gateway :: dns:dname() | inet:ip_address(),
    public_key :: binary()
}).

%% KEY record for storing public keys. See RFC 2535: §3.1.
-record(dns_rrdata_key, {
    type :: dns:uint2(),
    xt :: 0..1,
    name_type :: dns:uint2(),
    sig :: dns:uint4(),
    protocol :: dns:uint8(),
    alg :: dns:uint8(),
    public_key :: binary()
}).

%% KX record for Key Exchanger. See RFC 2230: §3.1.
-record(dns_rrdata_kx, {
    preference :: dns:uint16(),
    exchange :: dns:dname()
}).

%% LOC record for geographical location. See RFC 1876: §2.
-record(dns_rrdata_loc, {
    size :: integer(),
    horiz :: integer(),
    vert :: integer(),
    lat :: dns:uint32(),
    lon :: dns:uint32(),
    alt :: dns:uint32()
}).

%% MB record for mailbox domain name. See RFC 1035: §3.3.3.
-record(dns_rrdata_mb, {
    madname :: dns:dname()
}).

%% MG record for mail group member. See RFC 1035: §3.3.6.
-record(dns_rrdata_mg, {
    madname :: dns:dname()
}).

%% MINFO record for mailbox information. See RFC 1035: §3.3.7.
-record(dns_rrdata_minfo, {
    rmailbx :: dns:dname(),
    emailbx :: dns:dname()
}).

%% MR record for mail rename domain name. See RFC 1035: §3.3.8.
-record(dns_rrdata_mr, {
    newname :: dns:dname()
}).

%% MX record for mail exchange. See RFC 1035: §3.3.9.
-record(dns_rrdata_mx, {
    preference :: dns:uint16(),
    exchange :: dns:dname()
}).

%% NAPTR record for Naming Authority Pointer. See RFC 3403: §4.1.
-record(dns_rrdata_naptr, {
    order :: dns:uint16(),
    preference :: dns:uint16(),
    flags :: binary(),
    services :: binary(),
    regexp :: binary(),
    replacement :: dns:dname()
}).

%% NS record for authoritative name server. See RFC 1035.
-record(dns_rrdata_ns, {
    dname :: dns:dname()
}).

%% NSEC record for DNSSEC authenticated denial of existence. See RFC 4034: §4.1.
-record(dns_rrdata_nsec, {
    next_dname :: dns:dname(),
    types :: [non_neg_integer()]
}).

%% NSEC3 record for DNSSEC authenticated denial of existence. See RFC 5155: §4.2.
-record(dns_rrdata_nsec3, {
    hash_alg :: dns:uint8(),
    opt_out :: boolean(),
    iterations :: dns:uint16(),
    salt :: binary(),
    hash :: binary(),
    types :: [non_neg_integer()]
}).

%% NSEC3PARAM record for NSEC3 parameters. See RFC 5155.
-record(dns_rrdata_nsec3param, {
    hash_alg :: dns:uint8(),
    flags :: dns:uint8(),
    iterations :: dns:uint16(),
    salt :: binary()
}).

%% NXT record for next domain (obsoleted by NSEC). See RFC 2535.
-record(dns_rrdata_nxt, {
    dname :: dns:dname(),
    types :: [non_neg_integer()]
}).

%% PTR record for domain name pointer. See RFC 1035: §3.3.12.
-record(dns_rrdata_ptr, {
    dname :: dns:dname()
}).

%% RP record for responsible person. See RFC 1183: §2.2.
-record(dns_rrdata_rp, {
    mbox :: dns:dname(),
    txt :: dns:dname()
}).

%% RRSIG record for DNSSEC signature. See RFC 4034: §3.1.
-record(dns_rrdata_rrsig, {
    type_covered :: dns:uint16(),
    alg :: 3 | 5 | 6 | 7 | 8 | 10,
    labels :: dns:uint8(),
    original_ttl :: dns:uint32(),
    expiration :: dns:uint32(),
    inception :: dns:uint32(),
    key_tag :: dns:uint16(),
    signers_name :: dns:dname(),
    signature = <<>> :: binary()
}).

%% RT record for route through. See RFC 1183: §3.3.
-record(dns_rrdata_rt, {
    preference :: dns:uint16(),
    host :: dns:dname()
}).

%% SOA record for start of authority. See RFC 1035: §3.3.13.
-record(dns_rrdata_soa, {
    mname :: dns:dname(),
    rname :: dns:dname(),
    serial :: dns:uint32(),
    refresh :: dns:uint32(),
    retry :: dns:uint32(),
    expire :: dns:uint32(),
    minimum :: dns:uint32()
}).

%% SPF record for Sender Policy Framework. See RFC 4408.
-record(dns_rrdata_spf, {
    %% each binary is less than 255 bytes
    spf :: [binary()]
}).

%% SRV record for service location. See RFC 2782.
-record(dns_rrdata_srv, {
    priority :: dns:uint16(),
    weight :: dns:uint16(),
    port :: dns:uint16(),
    target :: dns:dname()
}).

%% SSHFP record for SSH key fingerprints. See RFC 4255: §3.1.
-record(dns_rrdata_sshfp, {
    alg :: dns:uint8(),
    fp_type :: dns:uint8(),
    fp :: binary()
}).

%% SVCB record for service binding. See RFC 9460.
-record(dns_rrdata_svcb, {
    svc_priority :: dns:uint16(),
    target_name :: dns:dname(),
    svc_params :: dns:svcb_svc_params()
}).

%% TSIG record for transaction signature. See RFC 2845: §2.3.
-record(dns_rrdata_tsig, {
    alg :: dns:tsig_alg(),
    time :: dns:uint48(),
    fudge :: dns:uint16(),
    mac :: binary(),
    msgid :: dns:uint16(),
    err :: dns:uint16(),
    other :: binary()
}).

%% TXT record for text strings. See RFC 1035: §3.3.14.
-record(dns_rrdata_txt, {
    %% each binary is less than 255 bytes
    txt :: [binary()]
}).

%% OPT pseudo-RR for EDNS. See RFC 6891: §6.1.2.
-record(dns_optrr, {
    udp_payload_size = 4096 :: integer(),
    ext_rcode = ?DNS_ERCODE_NOERROR :: dns:uint8(),
    version = 0 :: dns:uint8(),
    dnssec = false :: boolean(),
    data = [] :: [dns:optrr_elem()]
}).

%% LLQ EDNS option. See RFC 8764: §3.2.
-record(dns_opt_llq, {
    opcode :: dns:uint16(),
    errorcode :: dns:uint16(),
    id :: dns:uint64(),
    leaselife :: dns:uint32()
}).

%% NSID EDNS option. See RFC 5001.
-record(dns_opt_nsid, {
    data :: binary()
}).

%% OWNER EDNS option. See RFC draft-cheshire-edns0-owner-option-00: §3.1.
-record(dns_opt_owner, {
    seq = 0 :: dns:uint8(),
    primary_mac :: <<_:6 * 8>>,
    wakeup_mac :: <<>> | <<_:6 * 8>>,
    password :: <<>> | <<_:6 * 8>>
}).

%% UL EDNS option. See RFC draft-sekar-dns-ul-01: §4.
-record(dns_opt_ul, {
    lease :: dns:uint32()
}).

%% ECS EDNS Client Subnet option. See RFC 7871: $6:
-record(dns_opt_ecs, {
    family :: dns:uint16(),
    source_prefix_length :: dns:uint8(),
    scope_prefix_length :: dns:uint8(),
    address :: binary()
}).

%% Unknown EDNS option.
-record(dns_opt_unknown, {
    id :: integer(),
    bin :: binary()
}).

-endif.
