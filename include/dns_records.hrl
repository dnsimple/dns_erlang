-ifndef('__dns_records.hrl__').
-define('__dns_records.hrl__', ok).
-include("dns_terms.hrl").

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

-record(dns_query, {
    name :: dns:dname(),
    class = ?DNS_CLASS_IN :: dns:class(),
    type :: dns:type()
}).
-record(dns_rr, {
    name :: dns:dname(),
    class = ?DNS_CLASS_IN :: dns:class(),
    type :: dns:type(),
    ttl = 0 :: dns:ttl(),
    data :: dns:rrdata()
}).
-record(dns_rrdata_a, {
    ip :: inet:ip4_address()
}).
-record(dns_rrdata_aaaa, {
    ip :: inet:ip6_address()
}).
-record(dns_rrdata_afsdb, {
    subtype :: integer(),
    hostname :: dns:dname()
}).
-record(dns_rrdata_caa, {
    flags :: integer(),
    tag :: binary(),
    value :: binary()
}).
-record(dns_rrdata_cert, {
    type :: integer(),
    key_tag :: integer(),
    alg :: integer(),
    cert :: binary()
}).
-record(dns_rrdata_cname, {
    dname :: dns:dname()
}).
-record(dns_rrdata_dhcid, {
    data :: binary()
}).
-record(dns_rrdata_dlv, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).
-record(dns_rrdata_dname, {
    dname :: dns:dname()
}).
-record(dns_rrdata_dnskey, {
    flags :: integer(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: iodata(),
    key_tag :: integer()
}).
-record(dns_rrdata_cdnskey, {
    flags :: integer(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: iodata(),
    key_tag :: integer()
}).
-record(dns_rrdata_ds, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).
-record(dns_rrdata_cds, {
    keytag :: integer(),
    alg :: integer(),
    digest_type :: integer(),
    digest :: binary()
}).
-record(dns_rrdata_hinfo, {
    cpu :: binary(),
    os :: binary()
}).
-record(dns_rrdata_https, {
    svc_priority :: integer(),
    target_name :: dns:dname(),
    svc_params :: binary()
}).
-record(dns_rrdata_ipseckey, {
    precedence :: integer(),
    alg :: integer(),
    gateway :: dns:dname() | inet:ip_address(),
    public_key :: binary()
}).
-record(dns_rrdata_key, {
    type :: integer(),
    xt :: integer(),
    name_type :: integer(),
    sig :: number(),
    protocol :: integer(),
    alg :: integer(),
    public_key :: binary()
}).
-record(dns_rrdata_kx, {
    preference :: integer(),
    exchange :: dns:dname()
}).
-record(dns_rrdata_loc, {
    size :: integer(),
    horiz :: number(),
    vert :: number(),
    lat :: integer(),
    lon :: integer(),
    alt :: integer()
}).
-record(dns_rrdata_mb, {
    madname :: dns:dname()
}).
-record(dns_rrdata_mg, {
    madname :: dns:dname()
}).
-record(dns_rrdata_minfo, {
    rmailbx :: dns:dname(),
    emailbx :: dns:dname()
}).
-record(dns_rrdata_mr, {
    newname :: dns:dname()
}).
-record(dns_rrdata_mx, {
    preference :: integer(),
    exchange :: dns:dname()
}).
-record(dns_rrdata_naptr, {
    order :: integer(),
    preference :: integer(),
    flags :: binary(),
    services :: binary(),
    regexp :: binary(),
    replacement :: dns:dname()
}).
-record(dns_rrdata_ns, {
    dname :: dns:dname()
}).
-record(dns_rrdata_nsec, {
    next_dname :: undefined | dns:dname(),
    types :: term()
}).
-record(dns_rrdata_nsec3, {
    hash_alg :: integer(),
    opt_out :: 0 | 1 | boolean(),
    iterations :: integer(),
    salt :: binary(),
    hash :: binary(),
    types :: [any()]
}).
-record(dns_rrdata_nsec3param, {
    hash_alg :: integer(),
    flags :: integer(),
    iterations :: integer(),
    salt :: binary()
}).
-record(dns_rrdata_nxt, {
    dname :: dns:dname(),
    types :: [non_neg_integer()]
}).
-record(dns_rrdata_ptr, {
    dname :: dns:dname()
}).
-record(dns_rrdata_rp, {
    mbox :: dns:dname(),
    txt :: dns:dname()
}).
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
-record(dns_rrdata_rt, {
    preference :: integer(),
    host :: dns:dname()
}).
-record(dns_rrdata_soa, {
    mname :: dns:dname(),
    rname :: dns:dname(),
    serial :: integer(),
    refresh :: integer(),
    retry :: integer(),
    expire :: integer(),
    minimum :: integer()
}).
-record(dns_rrdata_spf, {
    spf :: [binary()]
}).
-record(dns_rrdata_srv, {
    priority :: integer(),
    weight :: integer(),
    port :: integer(),
    target :: dns:dname()
}).
-record(dns_rrdata_sshfp, {
    alg :: integer(),
    fp_type :: integer(),
    fp :: binary()
}).
-record(dns_rrdata_svcb, {
    svc_priority :: integer(),
    target_name :: dns:dname(),
    svc_params :: map()
}).
-record(dns_rrdata_tsig, {
    alg :: dns:tsig_alg(),
    time :: integer(),
    fudge :: integer(),
    mac :: binary(),
    msgid :: dns:message_id(),
    err :: integer(),
    other :: binary()
}).
-record(dns_rrdata_txt, {
    txt :: [binary()]
}).
-record(dns_optrr, {
    udp_payload_size = 4096 :: integer(),
    ext_rcode = ?DNS_ERCODE_NOERROR :: dns:rcode(),
    version = 0 :: integer(),
    dnssec = false :: boolean(),
    data = [] :: list()
}).
-record(dns_opt_llq, {
    opcode :: char(),
    errorcode :: char(),
    id :: non_neg_integer(),
    leaselife :: non_neg_integer()
}).
-record(dns_opt_nsid, {
    data :: binary()
}).
-record(dns_opt_owner, {
    seq = 0 :: byte(),
    primary_mac :: binary(),
    wakeup_mac :: binary(),
    password :: binary()
}).
-record(dns_opt_ul, {
    lease :: non_neg_integer()
}).
-record(dns_opt_ecs, {
    family :: integer(),
    source_prefix_length :: integer(),
    scope_prefix_length :: integer(),
    address :: binary()
}).
-record(dns_opt_unknown, {
    id :: integer(),
    bin :: binary()
}).

-endif.
