-ifndef('__dns_records.hrl__').
-define('__dns_records.hrl__', ok).
-include("dns_terms.hrl").

%% DNS Message format. See RFC 1035.
-record(dns_message, {
    id = dns:random_id() :: dns:message_id(),
    qr = false :: 0..1 | boolean(),
    oc = ?DNS_OPCODE_QUERY :: dns:opcode(),
    aa = false :: 0..1 | boolean(),
    tc = false :: 0..1 | boolean(),
    rd = false :: 0..1 | boolean(),
    ra = false :: 0..1 | boolean(),
    ad = false :: 0..1 | boolean(),
    cd = false :: 0..1 | boolean(),
    rc = ?DNS_RCODE_NOERROR :: dns:rcode(),
    qc = 0 :: char(),
    anc = 0 :: char(),
    auc = 0 :: char(),
    adc = 0 :: char(),
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
    class = ?DNS_CLASS_IN :: dns:class(),
    type :: dns:type(),
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
    subtype :: integer(),
    hostname :: dns:dname()
}).

%% CAA record for Certificate Authority Authorization. See RFC 6844.
-record(dns_rrdata_caa, {
    flags :: integer(),
    tag :: binary(),
    value :: binary()
}).

%% CERT record for storing certificates in DNS. See RFC 4398.
-record(dns_rrdata_cert, {
    type :: integer(),
    key_tag :: integer(),
    alg :: integer(),
    cert :: binary()
}).

%% CNAME record for canonical name. See RFC 1035.
-record(dns_rrdata_cname, {
    dname :: dns:dname()
}).

%% DHCID record for DHCP Information. See RFC 4701.
-record(dns_rrdata_dhcid, {
    data :: binary()
}).

%% DLV record for DNSSEC Lookaside Validation. See RFC 4431.
-record(dns_rrdata_dlv, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).

%% DNAME record for delegation of reverse mapping. See RFC 6672.
-record(dns_rrdata_dname, {
    dname :: dns:dname()
}).

%% DNSKEY record for DNSSEC public key. See RFC 4034.
-record(dns_rrdata_dnskey, {
    flags :: integer(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: iodata(),
    key_tag :: integer()
}).

%% CDNSKEY record for Child DNSKEY. See RFC 7344.
-record(dns_rrdata_cdnskey, {
    flags :: integer(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: iodata(),
    key_tag :: integer()
}).

%% DS record for Delegation Signer. See RFC 4034.
-record(dns_rrdata_ds, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).

%% CDS record for Child DS. See RFC 7344.
-record(dns_rrdata_cds, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).

%% HINFO record for host information. See RFC 1035.
-record(dns_rrdata_hinfo, {
    cpu :: binary(),
    os :: binary()
}).

%% HTTPS record for HTTPS service binding. See RFC 9460.
-record(dns_rrdata_https, {
    svc_priority :: integer(),
    target_name :: dns:dname(),
    svc_params :: binary()
}).

%% IPSECKEY record for storing IPsec keying material. See RFC 4025.
-record(dns_rrdata_ipseckey, {
    precedence :: integer(),
    alg :: integer(),
    gateway :: dns:dname() | inet:ip_address(),
    public_key :: binary()
}).

%% KEY record for storing public keys. See RFC 2535.
-record(dns_rrdata_key, {
    type :: integer(),
    xt :: integer(),
    name_type :: integer(),
    sig :: number(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: binary()
}).

%% KX record for Key Exchanger. See RFC 2230.
-record(dns_rrdata_kx, {
    preference :: integer(),
    exchange :: dns:dname()
}).

%% LOC record for geographical location. See RFC 1876.
-record(dns_rrdata_loc, {
    size :: integer(),
    horiz :: number(),
    vert :: number(),
    lat :: integer(),
    lon :: integer(),
    alt :: integer()
}).

%% MB record for mailbox domain name. See RFC 1035.
-record(dns_rrdata_mb, {
    madname :: dns:dname()
}).

%% MG record for mail group member. See RFC 1035.
-record(dns_rrdata_mg, {
    madname :: dns:dname()
}).

%% MINFO record for mailbox information. See RFC 1035.
-record(dns_rrdata_minfo, {
    rmailbx :: dns:dname(),
    emailbx :: dns:dname()
}).

%% MR record for mail rename domain name. See RFC 1035.
-record(dns_rrdata_mr, {
    newname :: dns:dname()
}).

%% MX record for mail exchange. See RFC 1035.
-record(dns_rrdata_mx, {
    preference :: integer(),
    exchange :: dns:dname()
}).

%% NAPTR record for Naming Authority Pointer. See RFC 3403.
-record(dns_rrdata_naptr, {
    order :: integer(),
    preference :: integer(),
    flags :: binary(),
    services :: binary(),
    regexp :: binary(),
    replacement :: dns:dname()
}).

%% NS record for authoritative name server. See RFC 1035.
-record(dns_rrdata_ns, {
    dname :: dns:dname()
}).

%% NSEC record for DNSSEC authenticated denial of existence. See RFC 4034.
-record(dns_rrdata_nsec, {
    next_dname :: undefined | dns:dname(),
    types :: term()
}).

%% NSEC3 record for DNSSEC authenticated denial of existence. See RFC 5155.
-record(dns_rrdata_nsec3, {
    hash_alg :: integer(),
    opt_out :: 0 | 1 | boolean(),
    iterations :: integer(),
    salt :: binary(),
    hash :: binary(),
    types :: [any()]
}).

%% NSEC3PARAM record for NSEC3 parameters. See RFC 5155.
-record(dns_rrdata_nsec3param, {
    hash_alg :: integer(),
    flags :: integer(),
    iterations :: integer(),
    salt :: binary()
}).

%% NXT record for next domain (obsoleted by NSEC). See RFC 2535.
-record(dns_rrdata_nxt, {
    dname :: dns:dname(),
    types :: [non_neg_integer()]
}).

%% PTR record for domain name pointer. See RFC 1035.
-record(dns_rrdata_ptr, {
    dname :: dns:dname()
}).

%% RP record for responsible person. See RFC 1183.
-record(dns_rrdata_rp, {
    mbox :: dns:dname(),
    txt :: dns:dname()
}).

%% RRSIG record for DNSSEC signature. See RFC 4034.
-record(dns_rrdata_rrsig, {
    type_covered :: integer(),
    alg :: 3 | 5 | 6 | 7 | 8 | 10,
    labels :: non_neg_integer(),
    original_ttl :: non_neg_integer(),
    expiration :: integer(),
    inception :: integer(),
    key_tag :: integer(),
    signers_name :: dns:dname(),
    signature = <<>> :: binary()
}).

%% RT record for route through. See RFC 1183.
-record(dns_rrdata_rt, {
    preference :: integer(),
    host :: dns:dname()
}).

%% SOA record for start of authority. See RFC 1035.
-record(dns_rrdata_soa, {
    mname :: dns:dname(),
    rname :: dns:dname(),
    serial :: integer(),
    refresh :: integer(),
    retry :: integer(),
    expire :: integer(),
    minimum :: integer()
}).

%% SPF record for Sender Policy Framework. See RFC 4408.
-record(dns_rrdata_spf, {
    spf :: [binary()]
}).

%% SRV record for service location. See RFC 2782.
-record(dns_rrdata_srv, {
    priority :: integer(),
    weight :: integer(),
    port :: integer(),
    target :: dns:dname()
}).

%% SSHFP record for SSH key fingerprints. See RFC 4255.
-record(dns_rrdata_sshfp, {
    alg :: integer(),
    fp_type :: integer(),
    fp :: binary()
}).

%% SVCB record for service binding. See RFC 9460.
-record(dns_rrdata_svcb, {
    svc_priority :: integer(),
    target_name :: dns:dname(),
    svc_params :: map()
}).

%% TSIG record for transaction signature. See RFC 2845.
-record(dns_rrdata_tsig, {
    alg :: dns:tsig_alg(),
    time :: integer(),
    fudge :: integer(),
    mac :: binary(),
    msgid :: dns:message_id(),
    err :: integer(),
    other :: binary()
}).

%% TXT record for text strings. See RFC 1035.
-record(dns_rrdata_txt, {
    txt :: [binary()]
}).

%% OPT pseudo-RR for EDNS. See RFC 6891.
-record(dns_optrr, {
    udp_payload_size = 4096 :: integer(),
    ext_rcode = ?DNS_ERCODE_NOERROR :: dns:rcode(),
    version = 0 :: integer(),
    dnssec = false :: boolean(),
    data = [] :: list()
}).

%% LLQ EDNS option. See RFC draft-sekar-dns-llq-01.
-record(dns_opt_llq, {
    opcode :: char(),
    errorcode :: char(),
    id :: non_neg_integer(),
    leaselife :: non_neg_integer()
}).

%% NSID EDNS option. See RFC 5001.
-record(dns_opt_nsid, {
    data :: binary()
}).

%% OWNER EDNS option. See RFC draft-cheshire-edns0-owner-option-00.
-record(dns_opt_owner, {
    seq = 0 :: byte(),
    primary_mac :: binary(),
    wakeup_mac :: binary(),
    password :: binary()
}).

%% UL EDNS option. See RFC draft-sekar-dns-ul-01.
-record(dns_opt_ul, {
    lease :: non_neg_integer()
}).

%% ECS EDNS Client Subnet option. See RFC 7871.
-record(dns_opt_ecs, {
    family :: integer(),
    source_prefix_length :: integer(),
    scope_prefix_length :: integer(),
    address :: binary()
}).

%% Unknown EDNS option.
-record(dns_opt_unknown, {
    id :: integer(),
    bin :: binary()
}).

-endif.
