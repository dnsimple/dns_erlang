# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

- Add DNS zone file encoding functionality — convert DNS resource records to RFC 1035 zone file format

## 4.9.1

- Fix a bug that would incorrectly calculate pointers, introduced in 4.9.1

## 4.9.0

- Add extended support for SVCB and HTTPS Resource Records — [RFC9460](https://datatracker.ietf.org/doc/rfc9460/)
- Add support for OPENPGPKEY (Type 61) — [RFC 7929](https://datatracker.ietf.org/doc/rfc7929/)
- Add support for SMIMEA (Type 53) — [RFC 8162](https://datatracker.ietf.org/doc/rfc8162/)
- Add support for URI (Type 256) — [RFC 7553](https://datatracker.ietf.org/doc/rfc7553/)
- Add support for WALLET (Type 262) — IANA Registration
- Add support for EUI48 (Type 108) and EUI64 (Type 109) — [RFC 7043](https://datatracker.ietf.org/doc/rfc7043/)
- Add support for CSYNC (Type 62) — [RFC 7477](https://datatracker.ietf.org/doc/rfc7477/)
- Add support for DSYNC (Type 66) — [RFC 9859](https://datatracker.ietf.org/doc/rfc9859/)
- Add `dns:decode_query/1` function for strict query validation to prevent DoS attacks
- Performance improvements in message encoding (~5-15% faster for encode/1, ~0-20% faster for encode/2)

## 4.8.1

- Fix bad size for reserved OptRR record during encoding

## 4.8.0

- Fix Base64 lexing of zone files
- Add support for [RFC8976](https://datatracker.ietf.org/doc/rfc8914/): Message Digest for DNS Zones

## 4.7.0

- Extend support for [RFC8914](https://datatracker.ietf.org/doc/rfc8914/): Extended DNS Errors.

## 4.6.0

- Add support for DNS zone file parsing

## 4.5.0

- Add support for [RFC8080](https://datatracker.ietf.org/doc/rfc8080/): Ed22519/Ed448 for DNSSEC.
- Add support for [RFC8914](https://datatracker.ietf.org/doc/rfc8914/): Extended DNS Errors.

## 4.4.0

- Add support for [RFC6605](https://datatracker.ietf.org/doc/rfc6605/): ECDSA for DNSSEC.
- Add support for [RFC9077](https://datatracker.ietf.org/doc/rfc9077/): NSEC/NSEC3 TTLs.

## 4.3.0

- Add support for TLSA records.

## 4.2.0

- Add shortcuts for normalizing and converting domains into labels.
- Add a helper for comparing label lists.
- Add helpers to convert from and to codes into their string representation.

## 4.1.0

- Add support for RFC7873 EDNS cookies encoding and decoding

## 4.0.1

- Fix additional count when truncating a message

## 4.0.0

- Use `erlang:system_time/1` for timestamps.
- Use maps instead of proplists for options to be passed to
    encoding, decoding, TSIG, and DNSSEC functions.
- Encoding logic builds responses that contain the full question section,
    and optionally drop the answers if the response is to be truncated.
- Use consistent record names.
- Split names functions into a standalone `dns_names` module.
- Extends and reorganise documentation.

## 3.1.3

- Fix: now using the reserved space for the OPT RR records during the encoding of the message (#74)

## 3.1.2

- Add NXNAME type to terms types.

## 3.1.1

- Fix EDNS0 compliance for truncated records and unsupported versions

## 3.1.0

- Fix EDNS0 compliance for truncated records and unsupported versions

## 3.0.5

- Fix `max_size` in encode_message opts

## 3.0.4

- Upgrade dependencies
- Apply linter specs

## 3.0.3

- Performance improvements in string manipulations

## 3.0.2

- Fix type definitions

## 3.0.1

- Ensure ASN1 compilation before building package

## 3.0.0

- Added xref, dialyzer, and ex_doc
- Add strict typing and RFC references to all records
- Add support for TXT splitting of strings over the maximum permitted size

## 2.0.0

### Changed

- Bumps to OTP/27
- Replaced "jsx" with "json"

### Added

- Erlfmt
- CONTRIBUTING.md
- CHANGELOG.md
- Release process to hex.pm

## 1.1.0

N/A
