%% The DNSSEC algorithms whose DNSKEY key field RFC 2536 lays out for DSA and
%% RFC 3110 for RSA. Include after dns.hrl.
-define(IS_DSA_ALG(Alg), (Alg =:= ?DNS_ALG_DSA orelse Alg =:= ?DNS_ALG_NSEC3DSA)).
-define(IS_RSA_ALG(Alg),
    (Alg =:= ?DNS_ALG_RSASHA1 orelse Alg =:= ?DNS_ALG_NSEC3RSASHA1 orelse
        Alg =:= ?DNS_ALG_RSASHA256 orelse Alg =:= ?DNS_ALG_RSASHA512)
).
