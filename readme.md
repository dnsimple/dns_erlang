#dns_erlang

dns_erlang is a DNS message library for Erlang. It supports most common record types, TSIG authenticated messages, EDNS0 and DNSSEC. At present the best documentation is [edoc](http://andrewtj.github.com/dns_erlang/doc/) and the code itself. 

## Prerequisites
To use SHA224, SHA384, SHA256 and SHA512 DNSSEC or TSIG signatures [sha2_erlang](https://github.com/andrewtj/sha2_erlang) is required (`make all` will pull this down automatically). sha2_erlang's performance is better on R14 due to the use of a NIF.

Neither sha2_erlang or dns_erlang have been tested on releases earlier than R13B04.