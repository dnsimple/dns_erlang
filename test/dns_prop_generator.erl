-module(dns_prop_generator).
-compile([export_all, nowarn_export_all]).

-include_lib("proper/include/proper.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%% ============================================================================
%% Common Generators
%% ============================================================================

%% Generate a letter or digit
letter_or_digit_or_dash() ->
    oneof(lists:seq($a, $z) ++ lists:seq($A, $Z) ++ lists:seq($0, $9) ++ [$-, $_]).

%% Generate a letter or digit
letter_or_digit() ->
    oneof(lists:seq($a, $z) ++ lists:seq($A, $Z) ++ lists:seq($0, $9)).

%% Generate a single letter (a-z, A-Z)
letter() ->
    oneof(lists:seq($a, $z) ++ lists:seq($A, $Z)).

%% Generate a single digit (0-9)
digit() ->
    oneof(lists:seq($0, $9)).

%% Generate a DNS label without capping the maximum length
label() ->
    ?LET(
        {First, Rest},
        {letter_or_digit(), list(letter_or_digit_or_dash())},
        ?SUCHTHAT(
            Label,
            list_to_binary([First | Rest]),
            0 < byte_size(Label)
        )
    ).

%% Generate a DNS label with specific length constraints
label_with_length(MinLen, MaxLen) ->
    ?LET(
        LabelLen,
        range(MinLen, MaxLen),
        ?LET(
            {First, Rest},
            {letter_or_digit(), vector(LabelLen - 1, letter_or_digit_or_dash())},
            list_to_binary([First | Rest])
        )
    ).

%% Generate a simple domain name (2 labels, FQDN format with trailing dot)
%% Commonly used for testing
simple_dname() ->
    ?LET(
        {Label1, Label2},
        {valid_label(), valid_label()},
        <<Label1/binary, $., Label2/binary, $.>>
    ).

%% Generate a valid DNS label (1-63 bytes)
valid_label() ->
    label_with_length(1, 63).

%% Generate a list of valid labels (1-10 labels)
valid_labels() ->
    ?LET(
        NumLabels,
        range(1, 10),
        vector(NumLabels, valid_label())
    ).

%% Generate a valid domain name (1-10 labels, <= 255 bytes in wire format)
%% Wire format: [len1][label1][len2][label2]...[0]
%% Wire size = sum(label_sizes) + num_labels + 1 (for null terminator)
%% Text size = sum(label_sizes) + num_labels - 1 (dots between labels, no trailing dot)
%% So: wire_size = text_size + 2
%% To ensure wire_size <= 255, we need: text_size <= 253
valid_dname() ->
    ?LET(
        NumLabels,
        range(1, 10),
        ?LET(
            Labels,
            vector(NumLabels, valid_label()),
            begin
                DName = dname_from_labels(Labels),
                %% Calculate wire format size: sum of label sizes + num_labels + 1
                WireSize = lists:foldl(
                    fun(Label, Acc) -> Acc + byte_size(Label) + 1 end,
                    1,
                    Labels
                ),
                %% Ensure wire format size <= 255 bytes
                case WireSize =< 255 of
                    true -> DName;
                    false -> <<"example.com">>
                end
            end
        )
    ).

dns_type() ->
    oneof([
        ?DNS_TYPE_A,
        ?DNS_TYPE_AAAA,
        ?DNS_TYPE_NS,
        ?DNS_TYPE_CNAME,
        ?DNS_TYPE_PTR,
        ?DNS_TYPE_MX,
        ?DNS_TYPE_TXT,
        ?DNS_TYPE_SPF,
        ?DNS_TYPE_SOA,
        ?DNS_TYPE_SRV,
        ?DNS_TYPE_CAA,
        ?DNS_TYPE_NAPTR,
        ?DNS_TYPE_HINFO,
        ?DNS_TYPE_RP,
        ?DNS_TYPE_AFSDB,
        ?DNS_TYPE_RT,
        ?DNS_TYPE_KX,
        ?DNS_TYPE_DNAME,
        ?DNS_TYPE_MB,
        ?DNS_TYPE_MG,
        ?DNS_TYPE_MR,
        ?DNS_TYPE_MINFO,
        ?DNS_TYPE_DS,
        ?DNS_TYPE_CDS,
        ?DNS_TYPE_DLV,
        ?DNS_TYPE_DNSKEY,
        ?DNS_TYPE_CDNSKEY,
        ?DNS_TYPE_RRSIG,
        ?DNS_TYPE_NSEC,
        ?DNS_TYPE_NSEC3,
        ?DNS_TYPE_NSEC3PARAM,
        ?DNS_TYPE_SSHFP,
        ?DNS_TYPE_TLSA,
        ?DNS_TYPE_SMIMEA,
        ?DNS_TYPE_CERT,
        ?DNS_TYPE_DHCID,
        ?DNS_TYPE_OPENPGPKEY,
        ?DNS_TYPE_WALLET,
        ?DNS_TYPE_URI,
        ?DNS_TYPE_RESINFO,
        ?DNS_TYPE_EUI48,
        ?DNS_TYPE_EUI64,
        ?DNS_TYPE_ZONEMD,
        ?DNS_TYPE_CSYNC,
        ?DNS_TYPE_DSYNC,
        ?DNS_TYPE_SVCB,
        ?DNS_TYPE_HTTPS,
        ?DNS_TYPE_LOC,
        ?DNS_TYPE_IPSECKEY,
        ?DNS_TYPE_KEY,
        ?DNS_TYPE_NXT,
        ?DNS_TYPE_TSIG
    ]).

dns_class() ->
    oneof([
        ?DNS_CLASS_IN,
        ?DNS_CLASS_CH,
        ?DNS_CLASS_HS,
        ?DNS_CLASS_CS
    ]).

%% Generate a domain name from a list of labels (without trailing dot)
dname_from_labels(Labels) ->
    lists:foldl(
        fun(Label, Acc) ->
            case Acc of
                <<>> -> Label;
                _ -> <<Acc/binary, $., Label/binary>>
            end
        end,
        <<>>,
        Labels
    ).
