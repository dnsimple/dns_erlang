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
-define(DNS_TYPE_A_BSTR, ~"A").
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

`dns_erlang` implements and supports a wide range of DNS-related RFCs, including core DNS protocol specifications, DNSSEC extensions, EDNS, and more. For a comprehensive list of all supported RFCs and their implementation details, see [Supported RFCs](./SUPPORTED_RFCS.md).
