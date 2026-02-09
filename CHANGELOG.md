# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

## v5.0.5

- SVCB/HTTPS params: treat numeric keys key0–key6 as reserved and equivalent to named params (mandatory, alpn, no-default-alpn, port, ipv4hint, ech, ipv6hint). Validate them the same at ingestion in zone parsing, JSON parsing, and wire decoding; key0–key6 are no longer accepted as generic unknown keys ([#110](https://github.com/dnsimple/dns_erlang/issues/110), [#111](https://github.com/dnsimple/dns_erlang/issues/111))
- SVCB params JSON docs: document key0–key6 equivalence to named params, no-default-alpn as null, and keyNNNN format (value binary or null) in generated JSON documentation
- SVCB params wire: decode unknown keys with zero-length value as `none` (not `<<>>`) so round-trip and `to_json` stay consistent (null vs empty binary)
- SVCB params JSON: reject invalid param keys in `to_json/1` (e.g. key > 65535) with `{svcb_param_invalid_key, K}` instead of emitting a map with `undefined` as key

## v5.0.4

### Fixed

- Fix parsing SVCB json records when `svc_params` are missing

## v5.0.3

### Fixed

- Fix FQDNs an (C)DNSKEY payloads in zonefile encoding

## v5.0.2

### Changed

- Use nulls instead of none in SVCB params JSON payloads [#107](https://github.com/dnsimple/dns_erlang/pull/107)

## v5.0.1

### Fixed

- Fix an issue with the hex package not including all needed files

## v5.0.0

### Added

- Add new `dns_json` module for bidirectional Record <-> JSON/Map transcoding
- Add DNS zone file encoding functionality — convert DNS resource records to RFC 1035 zone file format
- `dns_domain:to_lower/1` and `dns_domain:to_upper/1` for case conversion
- `dns_domain:are_equal/2` and `dns_domain:are_equal_labels/2` for case-insensitive comparison
- `dns_domain:escape_label/1` and `dns_domain:unescape_label/1` for label escaping
- Improved performance with chunked binary pattern matching
- Better RFC1035 and RFC9267 compliance with accurate wire format size tracking

### Changed

- Require OTP 27 or later (`minimum_otp_vsn` set to "27")
- `dns:encode_message/2` changed how truncation is returned to a clearer type
- Migrate domain name operations to new `dns_domain` module

All domain name processing functions have been moved to a new optimized
`dns_domain` module. The old implementations in `dns` and related helper
modules have been removed and replaced with calls to the new module.

#### Migration guide

All domain name functions have been moved to `dns_domain`. Update your code as follows:

```erl
% Old → New
dns:dname_to_lower(Name)             -> dns_domain:to_lower(Name)
dns:dname_to_upper(Name)             -> dns_domain:to_upper(Name)
dns:dname_to_labels(Name)            -> dns_domain:split(Name)
dns:labels_to_dname(Labels)          -> dns_domain:join(Labels)
dns:dname_to_lower_labels(Name)      -> dns_domain:split(dns_domain:to_lower(Name))
dns:compare_dname(NameA, NameB)      -> dns_domain:are_equal(NameA, NameB)
dns:compare_labels(LabelsA, LabelsB) -> dns_domain:are_equal_labels(LabelsA, LabelsB)
dns:escape_label(Label)              -> dns_domain:escape_label(Label)
dns_encode:encode_dname(Name)        -> dns_domain:to_wire(Name)
dns_encode:encode_dname(CM, Pos, N)  -> dns_domain:to_wire(CM, Pos, N)
```

**Note:** The wrapper functions in `dns` module (`dname_to_labels/1`, `labels_to_dname/1`,
`dname_to_lower_labels/1`, `dname_to_upper/1`, `dname_to_lower/1`, `compare_dname/2`,
`compare_labels/2`, `escape_label/1`) have been removed. Use `dns_domain` functions directly now.

**Error Handling Changes:**

- decoding invalid wire packets previously used `throw/1` for errors (`decode_loop`, `bad_pointer`),
  it uses `error/1` now
- Update error handling: `try dns:decode_message(...) catch error:Reason -> ... end`

### Removed

- Removed old `dns_record` and `dns_record_info` modules

## 4.9.1

### Fixed

- Fix a bug that would incorrectly calculate pointers, introduced in 4.9.0

## 4.9.0

### Added

- Add extended support for SVCB and HTTPS Resource Records — [RFC9460](https://datatracker.ietf.org/doc/rfc9460/)
- Add support for OPENPGPKEY (Type 61) — [RFC 7929](https://datatracker.ietf.org/doc/rfc7929/)
- Add support for SMIMEA (Type 53) — [RFC 8162](https://datatracker.ietf.org/doc/rfc8162/)
- Add support for URI (Type 256) — [RFC 7553](https://datatracker.ietf.org/doc/rfc7553/)
- Add support for WALLET (Type 262) — IANA Registration
- Add support for EUI48 (Type 108) and EUI64 (Type 109) — [RFC 7043](https://datatracker.ietf.org/doc/rfc7043/)
- Add support for CSYNC (Type 62) — [RFC 7477](https://datatracker.ietf.org/doc/rfc7477/)
- Add support for DSYNC (Type 66) — [RFC 9859](https://datatracker.ietf.org/doc/rfc9859/)
- Add `dns:decode_query/1` function for strict query validation to prevent DoS attacks

### Changed

- Performance improvements in message encoding (~5-15% faster for encode/1, ~0-20% faster for encode/2)

## 4.8.1

### Fixed

- Fix bad size for reserved OptRR record during encoding

## 4.8.0

### Added

- Add support for [RFC8976](https://datatracker.ietf.org/doc/rfc8914/): Message Digest for DNS Zones

### Fixed

- Fix Base64 lexing of zone files

## 4.7.0

### Added

- Extend support for [RFC8914](https://datatracker.ietf.org/doc/rfc8914/): Extended DNS Errors.

## 4.6.0

### Added

- Add support for DNS zone file parsing

## 4.5.0

### Added

- Add support for [RFC8080](https://datatracker.ietf.org/doc/rfc8080/): Ed22519/Ed448 for DNSSEC.
- Add support for [RFC8914](https://datatracker.ietf.org/doc/rfc8914/): Extended DNS Errors.

## 4.4.0

### Added

- Add support for [RFC6605](https://datatracker.ietf.org/doc/rfc6605/): ECDSA for DNSSEC.
- Add support for [RFC9077](https://datatracker.ietf.org/doc/rfc9077/): NSEC/NSEC3 TTLs.

## 4.3.0

### Added

- Add support for TLSA records.

## 4.2.0

### Added

- Add shortcuts for normalizing and converting domains into labels.
- Add a helper for comparing label lists.
- Add helpers to convert from and to codes into their string representation.

## 4.1.0

### Added

- Add support for RFC7873 EDNS cookies encoding and decoding

## 4.0.1

### Fixed

- Fix additional count when truncating a message

## 4.0.0

### Changed

- Use `erlang:system_time/1` for timestamps.
- Use maps instead of proplists for options to be passed to
    encoding, decoding, TSIG, and DNSSEC functions.
- Encoding logic builds responses that contain the full question section,
    and optionally drop the answers if the response is to be truncated.
- Use consistent record names.
- Split names functions into a standalone `dns_names` module.
- Extends and reorganise documentation.

## 3.1.3

### Fixed

- Fix: now using the reserved space for the OPT RR records during the encoding of the message (#74)

## 3.1.2

### Added

- Add NXNAME type to terms types.

## 3.1.1

### Fixed

- Fix EDNS0 compliance for truncated records and unsupported versions

## 3.1.0

### Fixed

- Fix EDNS0 compliance for truncated records and unsupported versions

## 3.0.5

### Fixed

- Fix `max_size` in encode_message opts

## 3.0.4

### Changed

- Upgrade dependencies
- Apply linter specs

## 3.0.3

### Changed

- Performance improvements in string manipulations

## 3.0.2

### Fixed

- Fix type definitions

## 3.0.1

### Fixed

- Ensure ASN1 compilation before building package

## 3.0.0

### Added

- Add xref, dialyzer, and ex_doc
- Add strict typing and RFC references to all records
- Add support for TXT splitting of strings over the maximum permitted size

## 2.0.0

### Changed

- Bump to OTP/27
- Replace "jsx" with "json"

### Added

- Erlfmt
- CONTRIBUTING.md
- CHANGELOG.md
- Release process to hex.pm

## 1.1.0

N/A
