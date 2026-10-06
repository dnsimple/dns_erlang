# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

### Fixed

- DNSSEC canonical form no longer lowercases the names in the RDATA of NSEC, IPSECKEY, DSYNC, SVCB and HTTPS records. RFC 3597 §7 closes the list of RFC 4034 §6.2 to the types published before it, and RFC 6840 §5.1 takes NSEC off it, so these names keep their case, as in BIND. With an uppercase letter in such a name, a signature made here did not verify elsewhere, and one made elsewhere did not verify here.
- Zone files: the names in RDATA, and the origin they are resolved against, now keep the case they are written in (RFC 1035 §2.3.3); owner names are still lowercased. The parser lowercased every name, so a signature over a record whose RDATA names keep their case in DNSSEC canonical form, such as an HTTPS record pointing at `Svc.Example.Test.`, did not verify against the record read from the zone, and a signature made over the record read did not verify elsewhere.
- `dnssec:sign_rr/6` and `dnssec:verify_rrsig/4` now put the signer's name into the signed data lowercased, as RFC 4034 §3.1.8.1 and RFC 6840 §5.1 require, and `sign_rr/6` writes it lowercased in the RRSIG. It went in as given, so signing with a mixed-case zone name gave signatures other validators rejected, and an RRSIG received with a mixed-case signer did not verify.
- The names in the RDATA of DNAME, KX, NXT and RT records are no longer compressed on the wire. RFC 3597 §4 forbids compressing names in the RDATA of types not defined in RFC 1035, and RFC 6672 §2.5 says so of the DNAME target. A receiver that does not know such a type cannot follow the pointer and corrupts the name when it passes the record on.
- Zone files: RRSIG expiration and inception times written as `YYYYMMDDHHmmSS` (RFC 4034 §3.2), as signed zones usually spell them, are now read as UTC dates. They were kept as the 14-digit number, and encoding wrote its low 32 bits, so the signature times on the wire were wrong. Invalid dates and values that fit neither form are rejected.
- `dns_domain:split/1` and `dns_domain:to_wire/1` now raise `{label_too_long, Label}` for a last label over 63 bytes, as they did for the others. `to_wire/1` wrote its length as it was, a byte the wire reads as another label type, so the uncompressed names in RDATA (SRV targets, RRSIG signers, and others) could go out malformed. Compressed names already refused it.
- `dns_json:from_map/1` and the zone file parser now refuse, when they load it, a record the wire cannot carry as written, raising `{invalid_record, Record}` and returning a semantic error respectively. The encoder trusts its input and writes each field with bit syntax, which silently cuts an integer too wide for its field (MX preference 70000 went out as 4464, -1 as 65535) and writes a binary of the wrong size as it is. The checks cover every fixed-width RDATA field, addresses, LOC coordinates, 8-bit lengths (CAA tags, NSEC3 salts and hashes, HINFO strings), NSEC type numbers, SVCB params (a hint that is not an address was silently dropped), names, RDATA over 65535 bytes, the RR header (type and class are 16 bits, and the TTL 31 bits as RFC 2181 §8 has it), and, in JSON, message headers, queries, the OPT pseudo-RR and its options. The RDATA is checked in the record's class, so a record in a class the encoder does not write its type in, such as an A record in class CH, is refused. Such records, and EUI48 and EUI64 addresses of the wrong length in JSON, used to load and then fail every response carrying them.
- Zone files: a type without a mnemonic, written `TYPE###` (RFC 3597 §5), is now read in RDATA, such as an RRSIG's type covered or an NSEC or CSYNC type bitmap. The encoder writes such types that way, so a zone it wrote with them did not parse back, nor did a zone holding the TYPE65534 records BIND keeps its signing state in, which its NSEC lists and an RRSIG covers.
- Zone files: an owner spelled as a type mnemonic, such as a host named `LOC`, `MX` or `KX`, is now read as the owner when a class follows it, directly or after a TTL. The parser read it as a type, so the record failed to parse. Without a class, as in `LOC 3600 A 192.0.2.1`, the line still reads as a record of that type with a blank owner, since the parser does not keep the whitespace that marks one.

## v5.0.19

### Fixed

- The SVCB/HTTPS `ech` parameter is base64 in JSON, both ways. `from_json/1` took the string as the raw ECHConfigList, so a base64 value was served as its own characters, and `to_json/1` crashed on any real ECHConfigList because it is not valid UTF-8.

## v5.0.18

### Updated

- Name compression is 1.1x-8.9x faster across the benchmark corpus depending on how much a message repeats its names. Both the relative and fully-qualified spelling of a repeated name take the same fast path.
- `t:dns_domain:compmap/0` is now explicitly opaque. Build one with `dns_domain:new_compmap/0`.

## v5.0.17

### Fixed

- `gen_nsec/1,3,4` no longer crashes when a zone carries one name spelled both as an FQDN and relatively (`example.com` and `example.com.`).

## v5.0.16

### Fixed

- `decode_query/1` no longer rejects rfc1995 IXFR queries as `formerr` but as `notimp`.

## v5.0.15

### Fixed

- `decode_message/1` now decodes rfc2136 UPDATE messages, while `decode_query/1` does not anymore as it shouldn't have, returning `notimp`.

## v5.0.14

### Updated

- Optimized `dns_domain:to_wire/3` (compressed name encoding): 1.4–2.8x faster on typical names, up to 17–22x on many-label names such as IPv6 reverse PTRs, with 1.1–3x less allocation.
- Optimized `dns_domain:from_wire/1,2` (wire-format name decoding): ~1.1–1.2x faster on typical compressed names, up to 1.4–1.5x on pointer chains, with up to 18% less allocation on pointer-heavy names.
- Optimized message encoding: ~1.1–1.3x faster on typical bounded responses with 5–35% less allocation across message shapes.

### Fixed

- Correct name compression in the additional section of `encode_message/2` for non-EDNS responses
- NSEC/NSEC3/CSYNC/NXT type bitmap encoding shifted every type after the first by one bit position in any window whose first present type is a multiple of 256
- MINFO records failed to decode inside full messages (`formerr`) due to swapped `dns_domain:from_wire/2` arguments in the MINFO rdata decoder
- `encode_message/2` subtracted the question section twice when sizing the OPT RR and additional records, wrongly dropping them (including the EDNS OPT RR, contra RFC 6891) from responses within question-size bytes of `max_size`
- LOC latitude and longitude used `2^31 - 1` instead of `2^31` as the equator/prime-meridian reference point (RFC 1876 §2)
- LOC `size`/`horiz`/`vert` outside the representable 0–9e9 cm range now raise `badarg`, and in-range values round to nearest instead of truncating (RFC 1876 §2)
- `encode_message/2` with `tc_mode => llq_event` raised `badmatch` when the authority/additional tail or the question section exceeded `max_size`; it now truncates and sets TC
- Zero-length `<character-string>`s were dropped when encoding TXT, SPF, RESINFO and WALLET records (RFC 1035 §3.3)
- A NAPTR record whose REGEXP is not valid UTF-8 decoded into a record holding an error tuple instead of being rejected (RFC 3403 §4.1)
- An EDNS OPT RR advertising a UDP payload size below 512 is clamped to 512 instead of raising `badarg` (RFC 6891 §6.2.3)
- `encode_message/2` with an unsupported `tsig` algorithm raised `case_clause` instead of `badarg`
- An SVCB/HTTPS `alpn` id longer than 255 bytes silently truncated its length octet, producing undecodable wire data; it now raises `{svcb_invalid_alpn_id, _}`
- SVCB/HTTPS `mandatory`, `ipv4hint` and `ipv6hint` values that are not a whole number of elements are rejected instead of silently dropping the remainder (RFC 9460 §7.4, §8)
- An EDNS OPT RR with a non-root owner name, and a message carrying more than one OPT RR, now decode to `formerr` (RFC 6891 §6.1.1)
- `RDLENGTH = 0` for a type this library decodes now decodes to `formerr` instead of an opaque `<<>>` (RFC 1035 §3.2.1)
- An OPT RR anywhere but first in the additional section was ignored when sizing the response and dropped from truncated ones (RFC 6891 §6.1.1)
- URI targets were replaced by their normalized form when decoding, losing data and changing the canonical RDATA that RRSIGs cover (RFC 7553 §4.5)
- A DNSKEY or CDNSKEY with a DSA algorithm but rdata too short to parse as one crashed on re-encode (RFC 2536 §2)
- Re-encoding a DSA DNSKEY whose P began with a zero byte truncated G and Y, producing an undecodable record (RFC 2536 §2)
- `encode_rrdata/2` crashed with `badmap` on every KX record, and with it the DNSSEC canonical form (RFC 2230)
- A repeated or out-of-order NSEC/NSEC3/CSYNC type-bitmap window decoded to a types list containing duplicates (RFC 4034 §4.1.2)
- LOC precision octets with a base nibble above nine were accepted instead of being left opaque (RFC 1876 §2)
- `encode_message/1,2` would emit a message carrying two OPT RRs, which the decoder rejects (RFC 6891 §6.1.1)
- A non-canonically encoded RSA DNSKEY/CDNSKEY public key changed shape when re-encoded, altering the canonical RDATA an RRSIG covers (RFC 3110 §2)

## v5.0.13

### Fixed

- Correctly return `formerr` on invalid NOTIFY DNS messages (rfc1996 §3.7: a NOTIFY carries exactly one question (QDCOUNT=1) and at most one), (#130)

## v5.0.12

### Fixed

- A malformed EDNS COOKIE option (RFC 7873) in a received message now decodes to a `formerr` result instead of raising `bad_cookie`.

## v5.0.11

### Fixed

- WALLET (type 262) RDATA uses TXT-style character-strings on the wire and in zone files (`data` as a list of binaries), per [IANA WALLET](https://www.iana.org/assignments/dns-parameters/WALLET/wallet-completed-template).
- Zone file parsing and RDATA decoding: improved handling of BIND-style presentations and record types;
- Empty TXT/RESINFO RDATA are rejected during semantic validation;
- Empty A/AAAA RDATA is rejected (no longer skipped);

## v5.0.10

### Updated

- Minimal performance improvement for `dns_domain:to_lower/1`, `dns_domain:to_upper/1`, and `dns_domain:are_equal/2`

## v5.0.9

### Updated

- Minimal performance improvement for `dns_domain:are_equal_labels/2`

## v5.0.8

### Fixed

- Handle truncated RR headers in additional and body sections ([#121](https://github.com/dnsimple/dns_erlang/pull/121))

## v5.0.7

### Changed

- Minor internal cleanups in the dnssec module (better function naming)

## v5.0.6

### Added

- `dnssec` exports record types it works over as types.

### Fixed

- Fixed encoding and decoding of ECDSA signatures
- Refactored `dnssec` to use the newer `dns_domain` API internally in a more efficient way
- Incremented test coverage for DNSSEC

### Removed

- Internal ASN1 parser, as it is supported by OTP's `public_key` module.

## v5.0.5

### Fixed

- SVCB/HTTPS params: treat numeric keys key0–key6 as reserved and equivalent to named params (mandatory, alpn, no-default-alpn, port, ipv4hint, ech, ipv6hint). Validate them the same at ingestion in zone parsing, JSON parsing, and wire decoding; key0–key6 are no longer accepted as generic unknown keys ([#110](https://github.com/dnsimple/dns_erlang/issues/110), [#111](https://github.com/dnsimple/dns_erlang/issues/111))
- SVCB params JSON docs: document key0–key6 equivalence to named params, no-default-alpn as null, and keyNNNN format (value binary or null) in generated JSON documentation
- SVCB params wire: decode unknown keys with zero-length value as `none` (not `<<>>`) so round-trip and `to_json` stay consistent (null vs empty binary)
- SVCB params JSON: reject invalid param keys in `to_json/1` (e.g. key > 65535) with `{svcb_param_invalid_key, K}` instead of emitting a map with `undefined` as key
- Ensure strict parsing of IPv4 and IPv6 in zonefiles respectively ([#108](https://github.com/dnsimple/dns_erlang/issues/108))

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
