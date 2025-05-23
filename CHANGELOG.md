# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

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
