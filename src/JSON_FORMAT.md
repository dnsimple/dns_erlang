# JSON format

This document describes the JSON encoding format for all DNS record types.

## Format Structure

### Resource Records (RR)

Resource records (`dns_rr`) are encoded as follows:

```json
{
  "name": "example.com",
  "type": "A",
  "class": "in",
  "ttl": 3600,
  "data": {
    "ip": "192.168.1.1"
  }
}
```

The format includes:

- `name`: Domain name (binary)
- `type`: DNS type name as uppercase string (e.g., "A", "AAAA", "MX")
- `ttl`: Time to live (integer)
- `data`: Map containing the record-specific fields
- `class`: Optional, only included if not IN (default)

### Other Records

Non-RR records (message, query, OPT records) use a two-level nested map format:

- Outer key: Record type identifier (descriptive name)
- Inner map: Record fields with binary keys

## Field Encoding Rules

- **IP addresses**: String format (`"192.168.1.1"`, `"2001:db8::1"`)
- **Base64**: Certificates, keys, signatures, MACs
- **Base16 (hex)**: Digests, hashes, fingerprints, addresses
- **Base32**: NSEC3 hash
- **Domain names**: Binary (dname format)
- **Lists**: Arrays of converted values

## Record Types

### MESSAGE (dns_message) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**JSON Key:** `message`

**Fields:**

- `id` (`t:dns:message_id/0`): Direct value
- `qr` (`t:boolean/0`): Direct value
- `oc` (`t:dns:opcode/0`): Direct value
- `aa` (`t:boolean/0`): Direct value
- `tc` (`t:boolean/0`): Direct value
- `rd` (`t:boolean/0`): Direct value
- `ra` (`t:boolean/0`): Direct value
- `ad` (`t:boolean/0`): Direct value
- `cd` (`t:boolean/0`): Direct value
- `rc` (`t:dns:rcode/0`): Direct value
- `qc` (`t:dns:uint16/0`): Direct value
- `anc` (`t:dns:uint16/0`): Direct value
- `auc` (`t:dns:uint16/0`): Direct value
- `adc` (`t:dns:uint16/0`): Direct value
- `questions` (`t:dns:questions/0`): Direct value
- `answers` (`t:dns:answers/0`): Direct value
- `authority` (`t:dns:authority/0`): Direct value
- `additional` (`t:dns:additional/0`): Direct value

**Example:**

```json
{
  "message": {
    "id": 0,
    "qr": false,
    "oc": false,
    "aa": false,
    "tc": false,
    "rd": false,
    "ra": false,
    "ad": false,
    "cd": false,
    "rc": "value",
    "qc": 0,
    "anc": 0,
    "auc": 0,
    "adc": 0,
    "questions": [],
    "answers": [],
    "authority": [],
    "additional": []
  }
}
```

### QUERY (dns_query) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**JSON Key:** `query`

**Fields:**

- `name` (`t:dns:dname/0`): Binary data (dname format)
- `class` (`t:dns:class/0`): Direct value
- `type` (`t:dns:type/0`): Direct value

**Example:**

```json
{
  "query": {
    "name": "example.com",
    "class": 0,
    "type": 0
  }
}
```

### A (dns_rrdata_a) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `ip` (`t:inet:ip4_address/0`): IP address as string

**Example:**

```json
{
    "ip": "192.168.1.1"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### AAAA (dns_rrdata_aaaa) [RFC3596](https://datatracker.ietf.org/doc/html/rfc3596)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `ip` (`t:inet:ip6_address/0`): IP address as string

**Example:**

```json
{
    "ip": "192.168.1.1"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### AFSDB (dns_rrdata_afsdb) [RFC1183](https://datatracker.ietf.org/doc/html/rfc1183)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `subtype` (`t:dns:uint16/0`): Direct value
- `hostname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "subtype": 0,
    "hostname": "example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CAA (dns_rrdata_caa) [RFC6844](https://datatracker.ietf.org/doc/html/rfc6844)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `flags` (`t:dns:uint8/0`): Direct value
- `tag` (`t:binary/0`): Binary data (dname format)
- `value` (`t:binary/0`): Binary data (dname format)

**Example:**

```json
{
    "flags": 0,
    "tag": "base64-encoded-data",
    "value": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CDNSKEY (dns_rrdata_cdnskey) [RFC7344](https://datatracker.ietf.org/doc/html/rfc7344)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `flags` (`t:dns:uint16/0`): Direct value
- `protocol` (`t:dns:uint8/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `public_key` (`t:iodata/0`): Base64-encoded public key
- `keytag` (`t:integer/0`): Direct value

**Example:**

```json
{
    "flags": 0,
    "protocol": 0,
    "alg": 0,
    "public_key": "base64-encoded-data",
    "keytag": 0
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CDS (dns_rrdata_cds) [RFC7344](https://datatracker.ietf.org/doc/html/rfc7344)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `keytag` (`t:dns:uint16/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `digest_type` (`t:dns:uint8/0`): Direct value
- `digest` (`t:binary/0`): Base16 (hex)-encoded digest

**Example:**

```json
{
    "keytag": 0,
    "alg": 0,
    "digest_type": 0,
    "digest": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CERT (dns_rrdata_cert) [RFC4398](https://datatracker.ietf.org/doc/html/rfc4398)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `type` (`t:dns:uint16/0`): Direct value
- `keytag` (`t:dns:uint16/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `cert` (`t:binary/0`): Base64-encoded certificate

**Example:**

```json
{
    "type": 0,
    "keytag": 0,
    "alg": 0,
    "cert": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CNAME (dns_rrdata_cname) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `dname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "dname": "example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### CSYNC (dns_rrdata_csync) [RFC7477](https://datatracker.ietf.org/doc/html/rfc7477)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `soa_serial` (`t:dns:uint32/0`): Direct value
- `flags` (`t:dns:uint16/0`): Direct value
- `types` ([`t:non_neg_integer/0`]): Direct value

**Example:**

```json
{
    "soa_serial": "value",
    "flags": 0,
    "types": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DHCID (dns_rrdata_dhcid) [RFC4701](https://datatracker.ietf.org/doc/html/rfc4701)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `data` (`t:binary/0`): Base64-encoded data

**Example:**

```json
{
    "data": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DLV (dns_rrdata_dlv) [RFC4431](https://datatracker.ietf.org/doc/html/rfc4431)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `keytag` (`t:dns:uint16/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `digest_type` (`t:dns:uint8/0`): Direct value
- `digest` (`t:binary/0`): Base16 (hex)-encoded digest

**Example:**

```json
{
    "keytag": 0,
    "alg": 0,
    "digest_type": 0,
    "digest": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DNAME (dns_rrdata_dname) [RFC6672](https://datatracker.ietf.org/doc/html/rfc6672)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `dname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "dname": "example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DNSKEY (dns_rrdata_dnskey) [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `flags` (`t:dns:uint16/0`): Direct value
- `protocol` (`t:dns:uint8/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `public_key` (`t:iodata/0`): Base64-encoded public key
- `keytag` (`t:integer/0`): Direct value

**Example:**

```json
{
    "flags": 0,
    "protocol": 0,
    "alg": 0,
    "public_key": "base64-encoded-data",
    "keytag": 0
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DS (dns_rrdata_ds) [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `keytag` (`t:dns:uint16/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `digest_type` (`t:dns:uint8/0`): Direct value
- `digest` (`t:binary/0`): Base16 (hex)-encoded digest

**Example:**

```json
{
    "keytag": 0,
    "alg": 0,
    "digest_type": 0,
    "digest": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### DSYNC (dns_rrdata_dsync) [RFC9859](https://datatracker.ietf.org/doc/html/rfc9859)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `rrtype` (`t:dns:uint16/0`): Direct value
- `scheme` (`t:dns:uint8/0`): Direct value
- `port` (`t:dns:uint16/0`): Direct value
- `target` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "rrtype": "value",
    "scheme": 0,
    "port": 0,
    "target": "target.example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### EUI48 (dns_rrdata_eui48) [RFC7043](https://datatracker.ietf.org/doc/html/rfc7043)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `address` (`<<_:48>>`): Base16 (hex)-encoded address

**Example:**

```json
{
    "address": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### EUI64 (dns_rrdata_eui64) [RFC7043](https://datatracker.ietf.org/doc/html/rfc7043)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `address` (`<<_:64>>`): Base16 (hex)-encoded address

**Example:**

```json
{
    "address": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### HINFO (dns_rrdata_hinfo) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `cpu` (`t:binary/0`): Binary data (dname format)
- `os` (`t:binary/0`): Binary data (dname format)

**Example:**

```json
{
    "cpu": "value",
    "os": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### HTTPS (dns_rrdata_https)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `svc_priority` (`t:dns:uint16/0`): Direct value
- `target_name` (`t:dns:dname/0`): Binary data (dname format)
- `svc_params` (`t:dns:svcb_svc_params/0`): Map of SVCB service parameters (see [SVCB Service Parameters below](#svcb-service-parameters))

**Example:**

```json
{
    "svc_priority": 0,
    "target_name": "value",
    "svc_params": {"alpn": ["h2", "h3"], "port": 443}
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### IPSECKEY (dns_rrdata_ipseckey) [RFC4025](https://datatracker.ietf.org/doc/html/rfc4025)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `precedence` (`t:dns:uint8/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `gateway` (`t:dns:dname/0` | `t:inet:ip_address/0`): Binary data (dname format)
- `public_key` (`t:binary/0`): Base64-encoded public key

**Example:**

```json
{
    "precedence": 0,
    "alg": 0,
    "gateway": "value",
    "public_key": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### KEY (dns_rrdata_key) [RFC2535](https://datatracker.ietf.org/doc/html/rfc2535)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `type` (`t:dns:uint2/0`): Direct value
- `xt` (`0..1`): Direct value
- `name_type` (`t:dns:uint2/0`): Direct value
- `sig` (`t:dns:uint4/0`): Direct value
- `protocol` (`t:dns:uint8/0`): Direct value
- `alg` (`t:dns:uint8/0`): Direct value
- `public_key` (`t:binary/0`): Base64-encoded public key

**Example:**

```json
{
    "type": 0,
    "xt": 0,
    "name_type": 0,
    "sig": "value",
    "protocol": 0,
    "alg": 0,
    "public_key": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### KX (dns_rrdata_kx) [RFC2230](https://datatracker.ietf.org/doc/html/rfc2230)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `preference` (`t:dns:uint16/0`): Direct value
- `exchange` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "preference": 0,
    "exchange": "mail.example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### LOC (dns_rrdata_loc) [RFC1876](https://datatracker.ietf.org/doc/html/rfc1876)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `size` (`t:integer/0`): Direct value
- `horiz` (`t:integer/0`): Direct value
- `vert` (`t:integer/0`): Direct value
- `lat` (`t:dns:uint32/0`): Direct value
- `lon` (`t:dns:uint32/0`): Direct value
- `alt` (`t:dns:uint32/0`): Direct value

**Example:**

```json
{
    "size": "value",
    "horiz": "value",
    "vert": "value",
    "lat": "value",
    "lon": "value",
    "alt": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### MB (dns_rrdata_mb) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `madname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "madname": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### MG (dns_rrdata_mg) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `madname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "madname": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### MINFO (dns_rrdata_minfo) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `rmailbx` (`t:dns:dname/0`): Binary data (dname format)
- `emailbx` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "rmailbx": "value",
    "emailbx": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### MR (dns_rrdata_mr) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `newname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "newname": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### MX (dns_rrdata_mx) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `preference` (`t:dns:uint16/0`): Direct value
- `exchange` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "preference": 0,
    "exchange": "mail.example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NAPTR (dns_rrdata_naptr) [RFC3403](https://datatracker.ietf.org/doc/html/rfc3403)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `order` (`t:dns:uint16/0`): Direct value
- `preference` (`t:dns:uint16/0`): Direct value
- `flags` (`t:binary/0`): Binary data (dname format)
- `services` (`t:binary/0`): Binary data (dname format)
- `regexp` (`t:binary/0`): Binary data (dname format)
- `replacement` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "order": "value",
    "preference": 0,
    "flags": 0,
    "services": "value",
    "regexp": "value",
    "replacement": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NS (dns_rrdata_ns) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `dname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "dname": "example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NSEC (dns_rrdata_nsec) [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `next_dname` (`t:dns:dname/0`): Binary data (dname format)
- `types` ([`t:non_neg_integer/0`]): Direct value

**Example:**

```json
{
    "next_dname": "value",
    "types": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NSEC3 (dns_rrdata_nsec3) [RFC5155](https://datatracker.ietf.org/doc/html/rfc5155)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `hash_alg` (`t:dns:uint8/0`): Direct value
- `opt_out` (`t:boolean/0`): Direct value
- `iterations` (`t:dns:uint16/0`): Direct value
- `salt` (`t:binary/0`): Base16 (hex)-encoded salt (or "-" for empty)
- `hash` (`t:binary/0`): Base32-encoded binary (NSEC3 hash)
- `types` ([`t:non_neg_integer/0`]): Direct value

**Example:**

```json
{
    "hash_alg": 0,
    "opt_out": false,
    "iterations": 0,
    "salt": "base16-encoded-data",
    "hash": "base32-encoded-data",
    "types": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NSEC3PARAM (dns_rrdata_nsec3param) [RFC5155](https://datatracker.ietf.org/doc/html/rfc5155)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `hash_alg` (`t:dns:uint8/0`): Direct value
- `flags` (`t:dns:uint8/0`): Direct value
- `iterations` (`t:dns:uint16/0`): Direct value
- `salt` (`t:binary/0`): Base16 (hex)-encoded salt (or "-" for empty)

**Example:**

```json
{
    "hash_alg": 0,
    "flags": 0,
    "iterations": 0,
    "salt": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### NXT (dns_rrdata_nxt) [RFC2535](https://datatracker.ietf.org/doc/html/rfc2535)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `dname` (`t:dns:dname/0`): Binary data (dname format)
- `types` ([`t:non_neg_integer/0`]): Direct value

**Example:**

```json
{
    "dname": "example.com",
    "types": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### OPENPGPKEY (dns_rrdata_openpgpkey) [RFC7929](https://datatracker.ietf.org/doc/html/rfc7929)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `data` (`t:binary/0`): Base64-encoded data

**Example:**

```json
{
    "data": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### PTR (dns_rrdata_ptr) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `dname` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "dname": "example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### RESINFO (dns_rrdata_resinfo) [RFC9606](https://datatracker.ietf.org/doc/html/rfc9606)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `data` ([`t:binary/0`]): Binary data (dname format)

**Example:**

```json
{
    "data": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### RP (dns_rrdata_rp) [RFC1183](https://datatracker.ietf.org/doc/html/rfc1183)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `mbox` (`t:dns:dname/0`): Binary data (dname format)
- `txt` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "mbox": "value",
    "txt": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### RRSIG (dns_rrdata_rrsig) [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `type_covered` (`t:dns:uint16/0`): Direct value
- `alg` (`3` | `5` | `6` | `7` | `8` | `10` | `13` | `14` | `15` | `16`): Direct value
- `labels` (`t:dns:uint8/0`): Direct value
- `original_ttl` (`t:dns:uint32/0`): Direct value
- `expiration` (`t:dns:uint32/0`): Direct value
- `inception` (`t:dns:uint32/0`): Direct value
- `keytag` (`t:dns:uint16/0`): Direct value
- `signers_name` (`t:dns:dname/0`): Binary data (dname format)
- `signature` (`t:binary/0`): Base64-encoded signature

**Example:**

```json
{
    "type_covered": "value",
    "alg": 0,
    "labels": "value",
    "original_ttl": "value",
    "expiration": "value",
    "inception": "value",
    "keytag": 0,
    "signers_name": "value",
    "signature": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### RT (dns_rrdata_rt) [RFC1183](https://datatracker.ietf.org/doc/html/rfc1183)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `preference` (`t:dns:uint16/0`): Direct value
- `host` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "preference": 0,
    "host": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SMIMEA (dns_rrdata_smimea) [RFC8162](https://datatracker.ietf.org/doc/html/rfc8162)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `usage` (`t:dns:uint8/0`): Direct value
- `selector` (`t:dns:uint8/0`): Direct value
- `matching_type` (`t:dns:uint8/0`): Direct value
- `certificate` (`t:binary/0`): Base16 (hex)-encoded binary

**Example:**

```json
{
    "usage": "value",
    "selector": "value",
    "matching_type": "value",
    "certificate": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SOA (dns_rrdata_soa) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `mname` (`t:dns:dname/0`): Binary data (dname format)
- `rname` (`t:dns:dname/0`): Binary data (dname format)
- `serial` (`t:dns:uint32/0`): Direct value
- `refresh` (`t:dns:uint32/0`): Direct value
- `retry` (`t:dns:uint32/0`): Direct value
- `expire` (`t:dns:uint32/0`): Direct value
- `minimum` (`t:dns:uint32/0`): Direct value

**Example:**

```json
{
    "mname": "ns1.example.com",
    "rname": "admin.example.com",
    "serial": 0,
    "refresh": 0,
    "retry": 0,
    "expire": 0,
    "minimum": 0
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SPF (dns_rrdata_spf) [RFC4408](https://datatracker.ietf.org/doc/html/rfc4408)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `spf` ([`t:binary/0`]): Binary data (dname format)

**Example:**

```json
{
    "spf": "value"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SRV (dns_rrdata_srv) [RFC2782](https://datatracker.ietf.org/doc/html/rfc2782)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `priority` (`t:dns:uint16/0`): Direct value
- `weight` (`t:dns:uint16/0`): Direct value
- `port` (`t:dns:uint16/0`): Direct value
- `target` (`t:dns:dname/0`): Binary data (dname format)

**Example:**

```json
{
    "priority": 0,
    "weight": 0,
    "port": 0,
    "target": "target.example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SSHFP (dns_rrdata_sshfp) [RFC4255](https://datatracker.ietf.org/doc/html/rfc4255)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `alg` (`t:dns:uint8/0`): Direct value
- `fp_type` (`t:dns:uint8/0`): Direct value
- `fp` (`t:binary/0`): Base16 (hex)-encoded fingerprint

**Example:**

```json
{
    "alg": 0,
    "fptype": "value",
    "fp": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### SVCB (dns_rrdata_svcb) [RFC9460](https://datatracker.ietf.org/doc/html/rfc9460)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `svc_priority` (`t:dns:uint16/0`): Direct value
- `target_name` (`t:dns:dname/0`): Binary data (dname format)
- `svc_params` (`t:dns:svcb_svc_params/0`): Map of SVCB service parameters (see [SVCB Service Parameters below](#svcb-service-parameters))

**Example:**

```json
{
    "svc_priority": 0,
    "target_name": "value",
    "svc_params": {"alpn": ["h2", "h3"], "port": 443}
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### TLSA (dns_rrdata_tlsa) [RFC6698](https://datatracker.ietf.org/doc/html/rfc6698)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `usage` (`t:dns:uint8/0`): Direct value
- `selector` (`t:dns:uint8/0`): Direct value
- `matching_type` (`t:dns:uint8/0`): Direct value
- `certificate` (`t:binary/0`): Base16 (hex)-encoded binary

**Example:**

```json
{
    "usage": "value",
    "selector": "value",
    "matching_type": "value",
    "certificate": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### TSIG (dns_rrdata_tsig) [RFC2845](https://datatracker.ietf.org/doc/html/rfc2845)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `alg` (`t:dns:tsig_alg/0`): Direct value
- `time` (`t:dns:uint48/0`): Direct value
- `fudge` (`t:dns:uint16/0`): Direct value
- `mac` (`t:binary/0`): Base64-encoded MAC
- `msgid` (`t:dns:uint16/0`): Direct value
- `err` (`t:dns:uint16/0`): Direct value
- `other` (`t:binary/0`): Base16 (hex)-encoded data

**Example:**

```json
{
    "alg": 0,
    "time": "value",
    "fudge": "value",
    "mac": "base64-encoded-data",
    "msgid": "value",
    "err": "value",
    "other": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### TXT (dns_rrdata_txt) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `txt` ([`t:binary/0`]): Binary data (dname format)

**Example:**

```json
{
    "txts": []
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### URI (dns_rrdata_uri) [RFC7553](https://datatracker.ietf.org/doc/html/rfc7553)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `priority` (`t:dns:uint16/0`): Direct value
- `weight` (`t:dns:uint16/0`): Direct value
- `target` (`t:binary/0`): Binary data (dname format)

**Example:**

```json
{
    "priority": 0,
    "weight": 0,
    "target": "target.example.com"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### WALLET (dns_rrdata_wallet)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `data` (`t:binary/0`): Base64-encoded data

**Example:**

```json
{
    "data": "base64-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### ZONEMD (dns_rrdata_zonemd) [RFC8976](https://datatracker.ietf.org/doc/html/rfc8976)

**Format:** RRDATA fields (used within `dns_rr.data`)

**Fields:**

- `serial` (`t:dns:uint32/0`): Direct value
- `scheme` (`t:dns:uint8/0`): Direct value
- `algorithm` (`t:dns:uint8/0`): Direct value
- `hash` (`t:binary/0`): Base16 (hex)-encoded hash

**Example:**

```json
{
    "serial": 0,
    "scheme": 0,
    "algorithm": 0,
    "hash": "base16-encoded-data"
}
```


**Note:** This format is used within the `data` field of `dns_rr` records.

### OPTCOOKIE (dns_opt_cookie) [RFC7873](https://datatracker.ietf.org/doc/html/rfc7873)

**JSON Key:** `unknown`

**Fields:**

- `client` (`<<_:64>>`): Direct value
- `server` (`<<_:64, _:_*8>>`): Direct value

**Example:**

```json
{
  "unknown": {
    "client": "value",
    "server": "value"
  }
}
```

### OPTECS (dns_opt_ecs) [RFC7871](https://datatracker.ietf.org/doc/html/rfc7871)

**JSON Key:** `unknown`

**Fields:**

- `family` (`t:dns:uint16/0`): Base16 (hex)-encoded binary
- `source_prefix_length` (`t:dns:uint8/0`): Base16 (hex)-encoded binary
- `scope_prefix_length` (`t:dns:uint8/0`): Base16 (hex)-encoded binary
- `address` (`t:binary/0`): Base16 (hex)-encoded address

**Example:**

```json
{
  "unknown": {
    "family": "base16-encoded-data",
    "source_prefix_length": "base16-encoded-data",
    "scope_prefix_length": "base16-encoded-data",
    "address": "base16-encoded-data"
  }
}
```

### OPTEDE (dns_opt_ede) [RFC8914](https://datatracker.ietf.org/doc/html/rfc8914)

**JSON Key:** `unknown`

**Fields:**

- `info_code` (`t:dns:uint16/0`): Direct value
- `extra_text` (`t:binary/0`): Binary data (dname format)

**Example:**

```json
{
  "unknown": {
    "info_code": "value",
    "extra_text": "value"
  }
}
```

### OPTLLQ (dns_opt_llq) [RFC8764](https://datatracker.ietf.org/doc/html/rfc8764)

**JSON Key:** `unknown`

**Fields:**

- `opcode` (`t:dns:uint16/0`): Direct value
- `errorcode` (`t:dns:uint16/0`): Direct value
- `id` (`t:dns:uint64/0`): Direct value
- `leaselife` (`t:dns:uint32/0`): Direct value

**Example:**

```json
{
  "unknown": {
    "opcode": "value",
    "errorcode": "value",
    "id": 0,
    "leaselife": "value"
  }
}
```

### OPTNSID (dns_opt_nsid) [RFC5001](https://datatracker.ietf.org/doc/html/rfc5001)

**JSON Key:** `unknown`

**Fields:**

- `data` (`t:binary/0`): Base16 (hex)-encoded data

**Example:**

```json
{
  "unknown": {
    "data": "base16-encoded-data"
  }
}
```

### OPTOWNER (dns_opt_owner)

**JSON Key:** `unknown`

**Fields:**

- `seq` (`t:dns:uint8/0`): Base16 (hex)-encoded binary
- `primary_mac` (`<<_:48>>`): Base16 (hex)-encoded binary
- `wakeup_mac` (`<<>>` | `<<_:48>>`): Base16 (hex)-encoded binary
- `password` (`<<>>` | `<<_:48>>`): Base16 (hex)-encoded binary

**Example:**

```json
{
  "unknown": {
    "seq": "base16-encoded-data",
    "primary_mac": "base16-encoded-data",
    "wakeup_mac": "base16-encoded-data",
    "password": "base16-encoded-data"
  }
}
```

### OPTUL (dns_opt_ul)

**JSON Key:** `unknown`

**Fields:**

- `lease` (`t:dns:uint32/0`): Direct value

**Example:**

```json
{
  "unknown": {
    "lease": "value"
  }
}
```

### OPTUNKNOWN (dns_opt_unknown)

**JSON Key:** `OPT_UNKNOWN`

**Fields:**

- `id` (`t:integer/0`): Direct value
- `bin` (`t:binary/0`): Base16 (hex)-encoded binary

**Example:**

```json
{
  "OPT_UNKNOWN": {
    "id": 0,
    "bin": "base16-encoded-data"
  }
}
```

### OPTRR (dns_optrr) [RFC6891](https://datatracker.ietf.org/doc/html/rfc6891)

**JSON Key:** `OPT`

**Fields:**

- `udp_payload_size` (`t:dns:uint16/0`): Direct value
- `ext_rcode` (`t:dns:uint8/0`): Direct value
- `version` (`t:dns:uint8/0`): Direct value
- `dnssec` (`t:boolean/0`): Direct value
- `data` ([`t:dns:optrr_elem/0`]): Direct value

**Example:**

```json
{
  "OPT": {
    "udp_payload_size": "value",
    "ext_rcode": "value",
    "version": "value",
    "dnssec": "value",
    "data": []
  }
}
```

### RR (dns_rr) [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Fields:**

- `name` (`t:dns:dname/0`): Domain name (binary, dname format)
- `type` (`t:dns:type/0`): DNS type name as uppercase binary string (e.g., "A", "AAAA", "MX")
- `class` (`t:dns:class/0`): DNS class name as uppercase binary string (e.g., "IN", "CH", "HS") - optional, defaults to "IN" if omitted
- `ttl` (`t:dns:ttl/0`): Time to live (integer)
- `data` (`t:dns:rrdata/0`): Map containing the RRDATA-specific fields (see individual RRDATA record types below)

**Example:**

```json
{
  "name": "example.com",
  "type": "A",
  "class": "IN",
  "ttl": 3600,
  "data": {
    "ip": "192.168.1.1"
  }
}
```


**Note:** The `data` field contains the RRDATA-specific fields. The `class` field is optional and defaults to `"IN"` if omitted. See individual RRDATA record types below for complete field documentation.

### SVCB Service Parameters

The `svc_params` field in SVCB and HTTPS records is a map containing service binding parameters
as defined in [RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460).

> #### NOTE {: .note}
>
> The keys `keyN` when `N` ranges from `0` to `6` are equivalent to their named counterparts and will be validated accordingly.

**Parameters:**

- `mandatory` (`[string()]`): List of parameter names that must be present (e.g., `["alpn", "port"]`).
- `alpn` (`[binary()]`): List of ALPN protocol identifiers as decoded binaries (e.g., `["h2", "h3"]`)
- `no-default-alpn` (`null`): Indicates that no default ALPN should be used.
- `port` (`integer()`): Port number (0-65535)
- `ipv4hint` (`[string()]`): List of IPv4 addresses as strings (e.g., `["192.168.1.1", "192.168.1.2"]`)
- `ipv6hint` (`[string()]`): List of IPv6 addresses as strings (e.g., `["2001:db8::1"]`)
- `ech` (`binary()`): Encrypted ClientHello (ECH) configuration as decoded binary
- `keyNNNN` (`binary()` | `null`): Unknown parameters where `NNNN` is the parameter key number (0-65535). In JSON the key is the string `"key"` followed by the decimal number (e.g. `"key65001"`). The value is either a binary (as string) or `null` for no-value parameters.

**Example:**

```json
{
    "svc_priority": 1,
    "target_name": "target.example.com",
    "svc_params": {
        "mandatory": ["alpn", "port"],
        "alpn": ["h2", "h3"],
        "port": 443,
        "ipv4hint": ["192.168.1.1", "192.168.1.2"],
        "ipv6hint": ["2001:db8::1"],
        "ech": "ech-config-data",
        "key65001": "custom-param-value",
        "key65002": null
    }
}
```

**Note:** All parameter values are in their decoded/native format (not base64-encoded).
Binary values like ALPN identifiers and ECH config are provided as raw binaries, not base64 strings.
