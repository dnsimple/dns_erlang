#dns_erlang

dns_erlang is a DNS message library for Erlang. It supports most common record types, TSIG authenticated messages and EDNS0. Functionality for constructing or querying a nameserver beyond interpreting wire messages is not provided. Similarly, although DNSSEC header bits and record types are understood there is no provision for record signing or verification at present.

## Prerequisites
To use the SHA224, SHA384, SHA256 and SHA512 TSIG signatures, [sha2_erlang](https://github.com/andrewtj/sha2_erlang) is required which in turns requires R14 or later. If you're using pre-R14 and don't need this functionality you can comment out the dependancy in rebar.config.