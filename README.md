# dns\_erlang

An Erlang DNS message library that supports most common record types, TSIG authenticated messages, EDNS0 and DNSSEC.

[![Build Status](https://github.com/dnsimple/dns_erlang/actions/workflows/ci.yml/badge.svg)](https://github.com/dnsimple/dns-erlang/actions/workflows/ci.yml)
[![Module Version](https://img.shields.io/hexpm/v/dns_erlang.svg)](https://hex.pm/packages/dns_erlang)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/dns_erlang/)
[![Hex Downloads](https://img.shields.io/hexpm/dt/dns_erlang.svg)](https://hex.pm/packages/dns_erlang)
[![Coverage Status](https://coveralls.io/repos/github/dnsimple/dns_erlang/badge.svg?branch=main)](https://coveralls.io/github/dnsimple/dns_erlang?branch=main)

## Usage

This library exposes types via `include/dns.hrl`, which in turn includes `include/dns_terms.hrl` and `include/dns_records.hrl`, as well as functions useful for constructing and deconstructing DNS packets with `src/dns.erl`

This is a library, not a DNS server. It is meant to be used by Erlang-based DNS servers for low level packet handling and RR processing.

If you'd like to see a full example of `dns_erlang` in use, please have a look at [erldns](https://github.com/dnsimple/erldns).

## Details

The following section explains what is contained in the library in greater detail.

For more details, see [Hex Docs](https://hexdocs.pm/dns_erlang/).

### dns\_terms.hrl

This file defines various terms, defined as Erlang macros, that are used in DNS packets. It includes a term for each DNS type, including one term for the numeric value and one term for the binary version. For example:

```erlang
-define(DNS_TYPE_A_NUMBER, 1).
-define(DNS_TYPE_A_BSTR, <<"A">>).
-define(DNS_TYPE_NS, ?DNS_TYPE_NS_NUMBER).
```

It also contains rcodes, opcodes, errcodes, etc.

### dns\_records.hrl

This file defines the record definitions for various Erlang record types that are useful for representing DNS constructs. For example, the `dns_message` record represents all of the elements that you would find in a single DNS message.

```erlang
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
```

Each of the record fields in `dns_message` corresponds to the elements defined in section 4 of [RFC 1035](https://tools.ietf.org/html/rfc1035). For example, `id` corresponds to the message header field `ID`, which is defined as:

> A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.

Other records defined include `dns_query`, which represents a single question in the `#dns_message.questions` field, `dns_rr` which corresponds to a single resource record (RR), which appears in the `answers`, `authority`, `additional` section of the `dns_message`, and so on.

Note that all support RR types must include a `dns_rrdata_` record definition, used to store the parts of the RDATA for that RR type.

## Supported RFCs

This library implements encoding and decoding of DNS packets according to the following RFCs. Note that this library focuses on packet encoding/decoding only and does not implement DNS server functionality such as socket handling or query resolution.

### Core DNS Protocol

- **[RFC 1035](https://tools.ietf.org/html/rfc1035)**: Domain Names - Implementation and Specification
  - DNS message format (§4.1.1)
  - DNS query format
  - Resource record format
  - Record types: A, CNAME, HINFO, MB, MG, MINFO, MR, MX, NS, PTR, SOA, TXT

### IPv6 Support

- **[RFC 3596](https://tools.ietf.org/html/rfc3596)**: DNS Extensions to Support IP Version 6
  - AAAA record type

### Additional Resource Records

- **[RFC 1183](https://tools.ietf.org/html/rfc1183)**: New DNS RR Definitions
  - AFSDB, RP, RT record types

- **[RFC 1876](https://tools.ietf.org/html/rfc1876)**: A Means for Expressing Location Information in the Domain Name System
  - LOC record type

- **[RFC 2230](https://tools.ietf.org/html/rfc2230)**: Key Exchange Delegation Record for the DNS
  - KX record type

- **[RFC 2782](https://tools.ietf.org/html/rfc2782)**: A DNS RR for specifying the location of services (DNS SRV)
  - SRV record type

- **[RFC 3403](https://tools.ietf.org/html/rfc3403)**: Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database
  - NAPTR record type

- **[RFC 4025](https://tools.ietf.org/html/rfc4025)**: A Method for Storing IPsec Keying Material in DNS
  - IPSECKEY record type

- **[RFC 4255](https://tools.ietf.org/html/rfc4255)**: Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
  - SSHFP record type

- **[RFC 4398](https://tools.ietf.org/html/rfc4398)**: Storing Certificates in the Domain Name System (DNS)
  - CERT record type

- **[RFC 4408](https://tools.ietf.org/html/rfc4408)**: Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1
  - SPF record type

- **[RFC 4701](https://tools.ietf.org/html/rfc4701)**: A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)
  - DHCID record type

- **[RFC 6672](https://tools.ietf.org/html/rfc6672)**: DNAME Redirection in the DNS
  - DNAME record type

- **[RFC 6698](https://tools.ietf.org/html/rfc6698)**: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
  - TLSA record type

- **[RFC 6844](https://tools.ietf.org/html/rfc6844)**: DNS Certification Authority Authorization (CAA) Resource Record
  - CAA record type

- **[RFC 9460](https://tools.ietf.org/html/rfc9460)**: Service Binding and Parameter Specification via the DNS (DNS SVCB and HTTPS Resource Records)
  - SVCB record type

### DNSSEC (DNS Security Extensions)

- **[RFC 2535](https://tools.ietf.org/html/rfc2535)**: Domain Name System Security Extensions
  - KEY record type (obsoleted by DNSKEY)
  - NXT record type (obsoleted by NSEC)

- **[RFC 4034](https://tools.ietf.org/html/rfc4034)**: Resource Records for the DNS Security Extensions
  - DNSKEY, DS, NSEC, RRSIG record types

- **[RFC 4431](https://tools.ietf.org/html/rfc4431)**: The DNSSEC Lookaside Validation (DLV) DNS Resource Record
  - DLV record type

- **[RFC 5155](https://tools.ietf.org/html/rfc5155)**: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
  - NSEC3, NSEC3PARAM record types

- **[RFC 6605](https://tools.ietf.org/html/rfc6605)**: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
  - ECDSA algorithms (ECDSAP256SHA256, ECDSAP384SHA384)

- **[RFC 7344](https://tools.ietf.org/html/rfc7344)**: Automating DNSSEC Delegation Trust Maintenance
  - CDNSKEY, CDS record types

- **[RFC 8080](https://tools.ietf.org/html/rfc8080)**: Ed25519 and Ed448 for DNSSEC
  - ED25519, ED448 algorithms

- **[RFC 9077](https://tools.ietf.org/html/rfc9077)**: NSEC and NSEC3 TTL Values
  - TTL handling for NSEC/NSEC3 records

### TSIG (Transaction Signature)

- **[RFC 2845](https://tools.ietf.org/html/rfc2845)**: Secret Key Transaction Authentication for DNS (TSIG)
  - TSIG record type
  - Supports MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 algorithms

### EDNS (Extension Mechanisms for DNS)

- **[RFC 6891](https://tools.ietf.org/html/rfc6891)**: Extension Mechanisms for DNS (EDNS(0))
  - OPT pseudo-RR for EDNS

- **[RFC 5001](https://tools.ietf.org/html/rfc5001)**: DNS Name Server Identifier (NSID) Option
  - NSID EDNS option

- **[RFC 7871](https://tools.ietf.org/html/rfc7871)**: Client Subnet in DNS Queries
  - EDNS Client Subnet (ECS) option

- **[RFC 7873](https://tools.ietf.org/html/rfc7873)**: Domain Name System (DNS) Cookies
  - EDNS Cookie option

- **[RFC 8764](https://tools.ietf.org/html/rfc8764)**: DNS Long-Lived Queries (LLQ)
  - LLQ EDNS option

- **[RFC 8914](https://tools.ietf.org/html/rfc8914)**: Extended DNS Errors
  - Extended DNS Error (EDE) option
