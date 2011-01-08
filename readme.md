#dns_erlang

dns_erlang is a DNS message library for Erlang. It supports most common record types, TSIG authenticated messages, EDNS0 and DNSSEC. At present the best documentation is [edoc](http://andrewtj.github.com/dns_erlang/doc/) and the code itself. 

## Prerequisites
To use SHA224, SHA384, SHA256 and SHA512 DNSSEC or TSIG signatures [sha2_erlang](https://github.com/andrewtj/sha2_erlang) is required which in turns requires R14 or later. If you're using pre-R14 and don't need this functionality you can comment out the dependancy in rebar.config.