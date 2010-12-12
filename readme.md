#dns_erlang

dns_erlang is a DNS message library for Erlang. It supports most common record types, MD5 TSIG authenticated messages and EDNS0. Functionality for constructing or querying a nameserver beyond interpreting wire messages is not provided. Similarly, although DNSSEC header bits and record types are understood there is no provision for record signing or verification at present.