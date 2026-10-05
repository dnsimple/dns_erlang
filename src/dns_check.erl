-module(dns_check).
-moduledoc false.

%% Checks for records built outside this library, run when they are loaded from
%% JSON or a zone file. The encoder trusts what it is given, keeping the query
%% path free of checks, and writes each field with bit syntax, which keeps only
%% the low bits of an integer too wide for its segment: MX preference 70000 would
%% go out as 4464, and -1 as 65535. A value that does not fit its field is refused
%% here instead, when it is loaded.

-include_lib("dns_erlang/include/dns.hrl").

-export([header/1, rr/1, rrdata/1, rrdata/2, query/1, optrr/1, opt/1]).

-define(IS_UINT(Bits, X), (is_integer(X) andalso 0 =< X andalso X < (1 bsl Bits))).
%% RFC1035§3.2.1: RDLENGTH is 16 bits, as is every length written inside RDATA,
%% so an RDATA that fits RDLENGTH also fits each of those
-define(MAX_RDLENGTH, 16#FFFF).
%% RFC1035§3.3: a <character-string> is one length octet and up to 255 octets
-define(MAX_STRING, 255).
%% RFC1876§2: latitude and longitude are offsets from 2^31, and altitude counts
%% centimetres from 100000 m below the reference spheroid
-define(LOC_REFERENCE_POINT, (1 bsl 31)).
-define(LOC_ALTITUDE_BASE, 10000000).

%% RFC1035§4.1.1: the header of a message. The records in its sections are not
%% looked at here, as they are checked one by one when they are built.
-spec header(dns:message()) -> boolean().
header(#dns_message{
    id = Id,
    qr = QR,
    oc = OC,
    aa = AA,
    tc = TC,
    rd = RD,
    ra = RA,
    ad = AD,
    cd = CD,
    rc = RC,
    qc = QC,
    anc = ANC,
    auc = AUC,
    adc = ADC
}) ->
    ?IS_UINT(16, Id) andalso ?IS_UINT(4, OC) andalso ?IS_UINT(4, RC) andalso
        lists:all(fun is_boolean/1, [QR, AA, TC, RD, RA, AD, CD]) andalso
        lists:all(fun is_uint16/1, [QC, ANC, AUC, ADC]).

%% RFC2181§8: a TTL is 31 bits, as `t:dns:ttl/0` has it, since a value with the top
%% bit set is read as zero
-spec rr(dns:rr()) -> boolean().
rr(#dns_rr{name = Name, type = Type, class = Class, ttl = TTL, data = Data}) ->
    ?IS_UINT(16, Type) andalso ?IS_UINT(16, Class) andalso ?IS_UINT(31, TTL) andalso
        dname(Name) andalso rrdata(Class, Data).

-spec query(dns:query()) -> boolean().
query(#dns_query{name = Name, type = Type, class = Class}) ->
    ?IS_UINT(16, Type) andalso ?IS_UINT(16, Class) andalso dname(Name).

-spec rrdata(dns:rrdata()) -> boolean().
rrdata(Data) ->
    rrdata(?DNS_CLASS_IN, Data).

%% Each field is checked against its width, then the RDATA is encoded once in the
%% record's class, which catches what the encoder refuses outright (a name too
%% long, a key of the wrong shape, a type in a class it is not written in, such as
%% A in CH) and an RDATA longer than RDLENGTH can announce. The names in the RDATA
%% are left to that encoding, as it writes each of them.
-spec rrdata(dns:class(), dns:rrdata()) -> boolean().
rrdata(Class, Data) ->
    try
        fits(Data) andalso byte_size(dns_encode:encode_rrdata(Class, Data)) =< ?MAX_RDLENGTH
    catch
        error:_ -> false
    end.

%% RFC6891§6.1.2: the OPT pseudo-RR's requestor's UDP payload size, extended RCODE
%% and version, then its options, which together are its RDATA
-spec optrr(dns:optrr()) -> boolean().
optrr(#dns_optrr{
    udp_payload_size = Size, ext_rcode = ExtRcode, version = Version, dnssec = DNSSEC, data = Opts
}) ->
    ?IS_UINT(16, Size) andalso ?IS_UINT(8, ExtRcode) andalso ?IS_UINT(8, Version) andalso
        is_boolean(DNSSEC) andalso is_list(Opts) andalso lists:all(fun opt/1, Opts) andalso
        lists:sum([4 + opt_size(Opt) || Opt <- Opts]) =< ?MAX_RDLENGTH.

-spec opt(dns:optrr_elem()) -> boolean().
opt(Opt) ->
    try
        opt_fits(Opt) andalso opt_size(Opt) =< ?MAX_RDLENGTH
    catch
        error:_ -> false
    end.

%% No catch-all clause for records: a type without one here is refused, so adding
%% a record type cannot leave it unchecked by mistake. Names are not checked here,
%% as encoding the RDATA writes each of them.
-spec fits(dns:rrdata()) -> boolean().
fits(#dns_rrdata_a{ip = IP}) ->
    inet:is_ipv4_address(IP);
fits(#dns_rrdata_aaaa{ip = IP}) ->
    inet:is_ipv6_address(IP);
fits(#dns_rrdata_afsdb{subtype = Subtype}) ->
    ?IS_UINT(16, Subtype);
fits(#dns_rrdata_amtrelay{
    precedence = Precedence, discovery_optional = D, relay_type = RelayType, relay = Relay
}) ->
    ?IS_UINT(8, Precedence) andalso is_boolean(D) andalso relay_fits(RelayType, Relay);
fits(#dns_rrdata_caa{flags = Flags, tag = Tag}) ->
    ?IS_UINT(8, Flags) andalso byte_size(Tag) =< ?MAX_STRING;
fits(#dns_rrdata_cdnskey{flags = Flags, protocol = Protocol, alg = Alg}) ->
    key_fits(Flags, Protocol, Alg);
fits(#dns_rrdata_cds{keytag = KeyTag, alg = Alg, digest_type = DigestType}) ->
    digest_fits(KeyTag, Alg, DigestType);
fits(#dns_rrdata_cert{type = Type, keytag = KeyTag, alg = Alg}) ->
    ?IS_UINT(16, Type) andalso ?IS_UINT(16, KeyTag) andalso ?IS_UINT(8, Alg);
fits(#dns_rrdata_csync{soa_serial = SOASerial, flags = Flags, types = Types}) ->
    ?IS_UINT(32, SOASerial) andalso ?IS_UINT(16, Flags) andalso types_fit(Types);
fits(#dns_rrdata_dlv{keytag = KeyTag, alg = Alg, digest_type = DigestType}) ->
    digest_fits(KeyTag, Alg, DigestType);
fits(#dns_rrdata_dnskey{flags = Flags, protocol = Protocol, alg = Alg}) ->
    key_fits(Flags, Protocol, Alg);
fits(#dns_rrdata_ds{keytag = KeyTag, alg = Alg, digest_type = DigestType}) ->
    digest_fits(KeyTag, Alg, DigestType);
fits(#dns_rrdata_dsync{rrtype = RRType, scheme = Scheme, port = Port}) ->
    ?IS_UINT(16, RRType) andalso ?IS_UINT(8, Scheme) andalso ?IS_UINT(16, Port);
fits(#dns_rrdata_eui48{address = Address}) ->
    6 =:= byte_size(Address);
fits(#dns_rrdata_eui64{address = Address}) ->
    8 =:= byte_size(Address);
%% RFC1035§3.3.2: CPU and OS are one <character-string> each, and the encoder
%% splits a longer one into several, leaving more than two
fits(#dns_rrdata_hinfo{cpu = CPU, os = OS}) ->
    byte_size(CPU) =< ?MAX_STRING andalso byte_size(OS) =< ?MAX_STRING;
fits(#dns_rrdata_https{svc_priority = Priority, svc_params = Params}) ->
    ?IS_UINT(16, Priority) andalso svc_params_fit(Params);
fits(#dns_rrdata_ipseckey{precedence = Precedence, alg = Alg, gateway = Gateway}) ->
    ?IS_UINT(8, Precedence) andalso ?IS_UINT(8, Alg) andalso gateway_fits(Gateway);
fits(#dns_rrdata_key{
    type = Type, xt = XT, name_type = NameType, sig = Sig, protocol = Protocol, alg = Alg
}) ->
    ?IS_UINT(2, Type) andalso ?IS_UINT(1, XT) andalso ?IS_UINT(2, NameType) andalso
        ?IS_UINT(4, Sig) andalso ?IS_UINT(8, Protocol) andalso ?IS_UINT(8, Alg);
fits(#dns_rrdata_kx{preference = Pref}) ->
    ?IS_UINT(16, Pref);
%% RFC6742§2.2: a Locator32 is spelled as an A record's address
fits(#dns_rrdata_l32{preference = Pref, locator32 = Locator32}) ->
    ?IS_UINT(16, Pref) andalso inet:is_ipv4_address(Locator32);
fits(#dns_rrdata_l64{preference = Pref, locator64 = Locator64}) ->
    ?IS_UINT(16, Pref) andalso 8 =:= byte_size(Locator64);
fits(#dns_rrdata_loc{lat = Lat, lon = Lon, alt = Alt}) ->
    ?IS_UINT(32, Lat + ?LOC_REFERENCE_POINT) andalso
        ?IS_UINT(32, Lon + ?LOC_REFERENCE_POINT) andalso
        ?IS_UINT(32, Alt + ?LOC_ALTITUDE_BASE);
fits(#dns_rrdata_lp{preference = Pref}) ->
    ?IS_UINT(16, Pref);
fits(#dns_rrdata_mx{preference = Pref}) ->
    ?IS_UINT(16, Pref);
fits(#dns_rrdata_naptr{order = Order, preference = Pref}) ->
    ?IS_UINT(16, Order) andalso ?IS_UINT(16, Pref);
fits(#dns_rrdata_nid{preference = Pref, node_id = NodeID}) ->
    ?IS_UINT(16, Pref) andalso 8 =:= byte_size(NodeID);
fits(#dns_rrdata_nsec{types = Types}) ->
    types_fit(Types);
fits(#dns_rrdata_nsec3{
    hash_alg = HashAlg, iterations = Iterations, salt = Salt, hash = Hash, types = Types
}) ->
    ?IS_UINT(8, HashAlg) andalso ?IS_UINT(16, Iterations) andalso
        byte_size(Salt) =< ?MAX_STRING andalso byte_size(Hash) =< ?MAX_STRING andalso
        types_fit(Types);
fits(#dns_rrdata_nsec3param{
    hash_alg = HashAlg, flags = Flags, iterations = Iterations, salt = Salt
}) ->
    ?IS_UINT(8, HashAlg) andalso ?IS_UINT(8, Flags) andalso ?IS_UINT(16, Iterations) andalso
        byte_size(Salt) =< ?MAX_STRING;
fits(#dns_rrdata_rrsig{
    type_covered = TypeCovered,
    alg = Alg,
    labels = Labels,
    original_ttl = OriginalTTL,
    expiration = Expiration,
    inception = Inception,
    keytag = KeyTag
}) ->
    ?IS_UINT(16, TypeCovered) andalso ?IS_UINT(8, Alg) andalso ?IS_UINT(8, Labels) andalso
        ?IS_UINT(32, OriginalTTL) andalso ?IS_UINT(32, Expiration) andalso
        ?IS_UINT(32, Inception) andalso ?IS_UINT(16, KeyTag);
fits(#dns_rrdata_rt{preference = Pref}) ->
    ?IS_UINT(16, Pref);
fits(#dns_rrdata_smimea{usage = Usage, selector = Selector, matching_type = MatchingType}) ->
    ?IS_UINT(8, Usage) andalso ?IS_UINT(8, Selector) andalso ?IS_UINT(8, MatchingType);
fits(#dns_rrdata_soa{
    serial = Serial, refresh = Refresh, retry = Retry, expire = Expire, minimum = Minimum
}) ->
    ?IS_UINT(32, Serial) andalso ?IS_UINT(32, Refresh) andalso ?IS_UINT(32, Retry) andalso
        ?IS_UINT(32, Expire) andalso ?IS_UINT(32, Minimum);
fits(#dns_rrdata_srv{priority = Priority, weight = Weight, port = Port}) ->
    ?IS_UINT(16, Priority) andalso ?IS_UINT(16, Weight) andalso ?IS_UINT(16, Port);
fits(#dns_rrdata_sshfp{alg = Alg, fp_type = FPType}) ->
    ?IS_UINT(8, Alg) andalso ?IS_UINT(8, FPType);
fits(#dns_rrdata_svcb{svc_priority = Priority, svc_params = Params}) ->
    ?IS_UINT(16, Priority) andalso svc_params_fit(Params);
fits(#dns_rrdata_tlsa{usage = Usage, selector = Selector, matching_type = MatchingType}) ->
    ?IS_UINT(8, Usage) andalso ?IS_UINT(8, Selector) andalso ?IS_UINT(8, MatchingType);
fits(#dns_rrdata_tsig{time = Time, fudge = Fudge, msgid = MsgId, err = Err}) ->
    ?IS_UINT(48, Time) andalso ?IS_UINT(16, Fudge) andalso ?IS_UINT(16, MsgId) andalso
        ?IS_UINT(16, Err);
fits(#dns_rrdata_uri{priority = Priority, weight = Weight}) ->
    ?IS_UINT(16, Priority) andalso ?IS_UINT(16, Weight);
fits(#dns_rrdata_zonemd{serial = Serial, scheme = Scheme, algorithm = Algorithm}) ->
    ?IS_UINT(32, Serial) andalso ?IS_UINT(8, Scheme) andalso ?IS_UINT(8, Algorithm);
fits(Bin) when is_binary(Bin) ->
    true;
%% These have no field of a fixed width, and their names, if any, are left to the
%% encoding. Listed one by one, rather than caught all, for the reason above.
fits(Data) when
    is_record(Data, dns_rrdata_cname);
    is_record(Data, dns_rrdata_dhcid);
    is_record(Data, dns_rrdata_dname);
    is_record(Data, dns_rrdata_mb);
    is_record(Data, dns_rrdata_mg);
    is_record(Data, dns_rrdata_minfo);
    is_record(Data, dns_rrdata_mr);
    is_record(Data, dns_rrdata_ns);
    is_record(Data, dns_rrdata_nxt);
    is_record(Data, dns_rrdata_openpgpkey);
    is_record(Data, dns_rrdata_ptr);
    is_record(Data, dns_rrdata_resinfo);
    is_record(Data, dns_rrdata_rp);
    is_record(Data, dns_rrdata_spf);
    is_record(Data, dns_rrdata_txt);
    is_record(Data, dns_rrdata_wallet)
->
    true.

-spec key_fits(dynamic(), dynamic(), dynamic()) -> boolean().
key_fits(Flags, Protocol, Alg) ->
    ?IS_UINT(16, Flags) andalso ?IS_UINT(8, Protocol) andalso ?IS_UINT(8, Alg).

-spec digest_fits(dynamic(), dynamic(), dynamic()) -> boolean().
digest_fits(KeyTag, Alg, DigestType) ->
    ?IS_UINT(16, KeyTag) andalso ?IS_UINT(8, Alg) andalso ?IS_UINT(8, DigestType).

%% RFC4034§4.1.2: a type bitmap window number is 8 bits, so type 65536 would land
%% in window 0 as type 0
-spec types_fit(dynamic()) -> boolean().
types_fit(Types) ->
    is_list(Types) andalso lists:all(fun is_uint16/1, Types).

%% RFC4025§2.5: no gateway, an IPv4 or IPv6 address, or a domain name
-spec gateway_fits(dynamic()) -> boolean().
gateway_fits({_, _, _, _} = IP) -> inet:is_ipv4_address(IP);
gateway_fits({_, _, _, _, _, _, _, _} = IP) -> inet:is_ipv6_address(IP);
gateway_fits(Name) -> is_binary(Name).

%% RFC8777§4.2.4: the relay is empty, an IPv4 or IPv6 address, or a domain name, as
%% its type announces. The encoder writes no relay for type 0, whatever the field
%% holds, so a type 0 relay must be empty.
-spec relay_fits(dynamic(), dynamic()) -> boolean().
relay_fits(0, Relay) -> Relay =:= <<>>;
relay_fits(1, Relay) -> inet:is_ipv4_address(Relay);
relay_fits(2, Relay) -> inet:is_ipv6_address(Relay);
relay_fits(RelayType, Relay) -> RelayType =:= 3 andalso is_binary(Relay).

%% RFC9460§2.2: keys, ports and mandatory keys are 16 bits and hints are
%% addresses. The encoder skips a hint that is not an address tuple.
-spec svc_params_fit(dynamic()) -> boolean().
svc_params_fit(Params) ->
    is_map(Params) andalso lists:all(fun svc_param_fits/1, maps:to_list(Params)).

-spec svc_param_fits({dynamic(), dynamic()}) -> boolean().
svc_param_fits({?DNS_SVCB_PARAM_MANDATORY, Keys}) ->
    is_list(Keys) andalso lists:all(fun is_uint16/1, Keys);
svc_param_fits({?DNS_SVCB_PARAM_PORT, Port}) ->
    is_uint16(Port);
svc_param_fits({?DNS_SVCB_PARAM_IPV4HINT, IPs}) ->
    is_list(IPs) andalso lists:all(fun inet:is_ipv4_address/1, IPs);
svc_param_fits({?DNS_SVCB_PARAM_IPV6HINT, IPs}) ->
    is_list(IPs) andalso lists:all(fun inet:is_ipv6_address/1, IPs);
svc_param_fits({Key, _Value}) ->
    is_uint16(Key).

-spec opt_fits(dns:optrr_elem()) -> boolean().
opt_fits(#dns_opt_llq{opcode = Opcode, errorcode = ErrorCode, id = Id, leaselife = LeaseLife}) ->
    ?IS_UINT(16, Opcode) andalso ?IS_UINT(16, ErrorCode) andalso ?IS_UINT(64, Id) andalso
        ?IS_UINT(32, LeaseLife);
opt_fits(#dns_opt_ul{lease = Lease}) ->
    ?IS_UINT(32, Lease);
opt_fits(#dns_opt_nsid{data = Data}) ->
    is_binary(Data);
%% The primary MAC, then optionally the wakeup MAC, then optionally a 4- or 6-byte
%% password, as the encoder writes them
opt_fits(#dns_opt_owner{
    seq = Seq, primary_mac = Primary, wakeup_mac = Wakeup, password = Password
}) ->
    ?IS_UINT(8, Seq) andalso 6 =:= byte_size(Primary) andalso
        ((Wakeup =:= <<>> andalso Password =:= <<>>) orelse
            (6 =:= byte_size(Wakeup) andalso lists:member(byte_size(Password), [0, 4, 6])));
opt_fits(#dns_opt_ecs{
    family = Family, source_prefix_length = Source, scope_prefix_length = Scope, address = Address
}) ->
    ?IS_UINT(16, Family) andalso ?IS_UINT(8, Source) andalso ?IS_UINT(8, Scope) andalso
        is_binary(Address);
%% RFC7873§4: an 8-byte client cookie, and a server cookie of 8 to 32 bytes
opt_fits(#dns_opt_cookie{client = Client, server = Server}) ->
    8 =:= byte_size(Client) andalso
        (Server =:= undefined orelse (8 =< byte_size(Server) andalso byte_size(Server) =< 32));
opt_fits(#dns_opt_ede{info_code = InfoCode, extra_text = ExtraText}) ->
    ?IS_UINT(16, InfoCode) andalso is_binary(ExtraText);
opt_fits(#dns_opt_unknown{id = Id, bin = Bin}) ->
    ?IS_UINT(16, Id) andalso is_binary(Bin).

%% The option's length, as written in its 16-bit OPTION-LENGTH
-spec opt_size(dns:optrr_elem()) -> non_neg_integer().
opt_size(#dns_opt_llq{}) ->
    18;
opt_size(#dns_opt_ul{}) ->
    4;
opt_size(#dns_opt_nsid{data = Data}) ->
    byte_size(Data);
opt_size(#dns_opt_owner{primary_mac = Primary, wakeup_mac = Wakeup, password = Password}) ->
    2 + byte_size(Primary) + byte_size(Wakeup) + byte_size(Password);
opt_size(#dns_opt_ecs{address = Address}) ->
    4 + byte_size(Address);
opt_size(#dns_opt_cookie{client = Client, server = undefined}) ->
    byte_size(Client);
opt_size(#dns_opt_cookie{client = Client, server = Server}) ->
    byte_size(Client) + byte_size(Server);
opt_size(#dns_opt_ede{extra_text = ExtraText}) ->
    2 + byte_size(ExtraText);
opt_size(#dns_opt_unknown{bin = Bin}) ->
    byte_size(Bin).

-spec is_uint16(dynamic()) -> boolean().
is_uint16(X) ->
    ?IS_UINT(16, X).

%% RFC1035§2.3.4: a label is 63 octets or less, and a name 255 or less on the wire,
%% which dns_domain:to_wire/1 refuses otherwise
-spec dname(dynamic()) -> boolean().
dname(Name) ->
    try dns_domain:to_wire(Name) of
        _ -> true
    catch
        error:_ -> false
    end.
