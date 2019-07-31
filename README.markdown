# dns\_erlang

An Erlang DNS message library that supports most common record types, TSIG authenticated messages, EDNS0 and DNSSEC.

## Usage

This library exposes types via `include/dns.hrl`, which in turn includes `include/dns_terms.hrl` and `include/dns_records.hrl`, as well as functions useful for constructing and deconstructing DNS packets with `src/dns.erl`

This is a library, not a DNS server. It is meant to be used by Erlang-based DNS servers for low level packet handling and RR processing.

If you'd like to see a full example of `dns_erlang` in use, please have a look at [erldns](https://github.com/dnsimple/erldns).

## Details

The following section explains what is contained in the library in greater detail.

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

### dns.erl

The `dns` module is the primary entry point for the functionality in this library. The module exports various types used in type specs, such as `message()`, which indicates a `#dns_message` record, `query()` which represents a single `#dns_query` record, `questions()`, which represents a list of queries, etc.

It also exports functions for encoding and decoding messages, TSIG supporting functions, and various utility functions for comparing domain names, converting domain names into different cases, converting to and from label lists, etc. 

### dns\_record.erl

The `dns_record` module exports `serialise` and `deserialise` functions for serialising and deserialising messages. You will generally not use these functions directly, rather you will use the functions for encoding and decoding messages exported by `dns.erl`.

### dns\_record\_info.erl

This module exports utility functions used to inspect records. You will generally not use these functions directly.

### dnssec.erl

The `dnssec` module exports functions used for generating NSEC responses, signing and verifying RRSIGs, and adding keytags to DNSKEY records.

For example, the `sign_rr/6` function can be given a collection of resource records, the signer name, keytag, signing algorithm, private key, and a collection of options and it will return a list of RRSIG records. Currently only DSA and RSA algorithms are supported for signing RRSETs.
