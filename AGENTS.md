# Agent Instructions

Instructions for AI coding agents working on this repository.

## Project Overview

dns_erlang is an Erlang DNS message library supporting most common record types, TSIG authentication, EDNS0, and DNSSEC. This is a low-level packet handling library, not a DNS server. For an example of this library in use, see [erldns](https://github.com/dnsimple/erldns).

## Key Documentation

- **[README.md](./README.md)** - Library overview, features, usage examples, and API reference
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines, commit format, testing approach
- **[Hex Documentation](https://hexdocs.pm/dns_erlang/)** - API reference

## Build Commands

- `make test` - Full test suite (lint, xref, dialyzer, ex_doc, ct, cover)
- `rebar3 compile` / `make build` - Build
- `rebar3 fmt` / `make format` - Format code
- `rebar3 lint` / `make lint` - Lint code
- `rebar3 ex_doc` / `make docs` - Build documentation
- `rebar3 clean` / `make clean` - Clean build artifacts
- `rebar3 shell` - Interactive Erlang shell
- `rebar3 ct` - Common Test (unit/integration/system tests)
- `rebar3 xref` - Cross-reference analysis
- `rebar3 dialyzer` - Static type analysis

## Architecture

**Core Modules:**

- `dns.erl` - Main public API: encode/decode messages, TSIG operations, domain name utilities
- `dns_encode.erl` - Wire format encoding (DNS records to binary)
- `dns_decode.erl` - Wire format decoding (binary to DNS records)
- `dns_names.erl` - DNS numeric code ↔ name conversions (type, class, rcode, opcode)
- `dns_record.erl` - Record serialization/deserialization
- `dns_tsig.erl` - TSIG authentication (RFC 2845)
- `dnssec.erl` - DNSSEC operations (signing, verification, keytag generation)
- `dns_zone.erl` - Zone file parsing (RFC 1035 format)

**Headers (include/):**

- `dns.hrl` - Main header (includes dns_terms.hrl and dns_records.hrl)
- `dns_terms.hrl` - DNS constants (types, classes, opcodes, rcodes, algorithms)
- `dns_records.hrl` - Erlang record definitions for DNS structures

**Generated Files (excluded from formatting/linting):**

- `src/DNS-ASN1.erl`, `include/DNS-ASN1.hrl` - ASN.1 generated code
- `src/dns_zone_lexer.erl` - Generated from dns_zone_lexer.xrl
- `src/dns_zone_parser.erl` - Generated from dns_zone_parser.yrl

## Key Data Structures

```erlang
#dns_message{}   % Complete DNS message (header + questions + RRs)
#dns_query{}     % Single DNS question (name, class, type)
#dns_rr{}        % Resource record (name, type, class, ttl, data)
#dns_optrr{}     % EDNS OPT pseudo-record
#dns_rrdata_*{}  % Type-specific record data (A, AAAA, MX, SOA, etc.)
```

## Coding Standards

Follow the coding standards defined in [CONTRIBUTING.md](./CONTRIBUTING.md#code-standards), which reference the [Inaka Erlang Guidelines](https://github.com/inaka/erlang_guidelines).

## Testing

Tests are in `test/` using Common Test framework. Test files follow `*_SUITE.erl` naming.

Coverage requirement: 75% minimum and should always increase. Excluded: dns_zone_lexer, dns_zone_parser.

## Code Review Checklist

When reviewing or writing code:

- [ ] Code compiles: `rebar3 compile`
- [ ] Formatting correct: `rebar3 fmt --check` – fix with `rebar3 fmt`
- [ ] Tests added/updated for behavior changes
- [ ] Types and specs updated for public API changes
- [ ] Commit messages follow conventional format (see [CONTRIBUTING.md](./CONTRIBUTING.md#commit-messages))
- [ ] Changelog updated for user-facing changes

## CI Requirements

Every PR must pass `rebar3 fmt --check`, and `make test` which runs: lint, xref, dialyzer, ct, coverage check.

When adding RFC support, regenerate the RFC list: `make rfc-list`

## Release Process

1. Finalize CHANGELOG.md with version number
2. `git commit -a -m "Release $VERSION"` and push
3. Wait for CI
4. `git tag -a v$VERSION -s -m "Release $VERSION"`
5. `git push origin --tags` (GitHub Actions publishes to Hex.pm)
