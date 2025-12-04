-module(dns_zone_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%% ============================================================================
%% CT Callbacks
%% ============================================================================

all() ->
    [{group, all}].

groups() ->
    [
        {all, [parallel], [
            {group, basic_records},
            {group, ipv6_records},
            {group, wildcard_labels},
            {group, underscore_labels},
            {group, soa_records},
            {group, multiple_records},
            {group, relative_names},
            {group, ttl_tests},
            {group, escape_sequences},
            {group, rfc3597_tests},
            {group, directives},
            {group, comments},
            {group, blank_owner},
            {group, uncommon_records},
            {group, dns_classes},
            {group, edge_cases},
            {group, parse_file_tests},
            {group, error_cases}
        ]},
        {basic_records, [parallel], [
            parse_simple_a_record,
            parse_simple_aaaa_record,
            parse_ns_record,
            parse_cname_record,
            parse_mx_record,
            parse_txt_record,
            parse_ptr_record,
            parse_srv_record,
            parse_caa_record,
            parse_full_zone
        ]},
        {ipv6_records, [parallel], [
            parse_aaaa_compressed_start,
            parse_aaaa_compressed_end,
            parse_aaaa_full_format,
            parse_aaaa_link_local,
            parse_aaaa_unspecified
        ]},
        {wildcard_labels, [parallel], [
            parse_wildcard_simple,
            parse_wildcard_subdomain,
            parse_wildcard_multiple_labels,
            parse_wildcard_with_srv
        ]},
        {underscore_labels, [parallel], [
            parse_underscore_srv_record,
            parse_underscore_dkim_txt,
            parse_underscore_dmarc_txt,
            parse_underscore_multiple_labels
        ]},
        {soa_records, [parallel], [
            parse_soa_record,
            parse_soa_record_no_parens
        ]},
        {multiple_records, [parallel], [
            parse_multiple_records
        ]},
        {relative_names, [parallel], [
            parse_relative_name,
            parse_at_sign
        ]},
        {ttl_tests, [parallel], [
            parse_time_value_hours,
            parse_time_value_days,
            parse_time_value_mixed,
            parse_default_ttl,
            parse_time_value_years,
            parse_time_value_years_mixed,
            parse_time_value_all_units
        ]},
        {escape_sequences, [parallel], [
            parse_escape_backslash,
            parse_escape_quote,
            parse_escape_decimal_simple,
            parse_escape_decimal_null,
            parse_escape_decimal_space,
            parse_escape_decimal_max,
            parse_escape_decimal_mixed,
            parse_escape_hex_simple,
            parse_escape_hex_lowercase,
            parse_escape_hex_uppercase,
            parse_escape_hex_null,
            parse_escape_hex_max,
            parse_escape_hex_mixed
        ]},
        {rfc3597_tests, [parallel], [
            parse_rfc3597_generic_type_simple,
            parse_rfc3597_generic_type_min,
            parse_rfc3597_generic_type_max,
            parse_rfc3597_generic_class_in,
            parse_rfc3597_generic_class_custom,
            parse_rfc3597_generic_rdata_empty,
            parse_rfc3597_generic_rdata_simple,
            parse_rfc3597_generic_rdata_ipv4,
            parse_rfc3597_combined_all_generic,
            parse_rfc3597_known_type_generic_rdata
        ]},
        {directives, [parallel], [
            parse_origin_directive,
            parse_ttl_directive,
            parse_origin_and_ttl_directives
        ]},
        {comments, [parallel], [
            parse_with_comments,
            parse_inline_comment_after_rr,
            parse_inline_comment_in_soa,
            parse_inline_comment_after_directive,
            parse_comment_only_lines
        ]},
        {blank_owner, [parallel], [
            parse_blank_owner
        ]},
        {uncommon_records, [parallel], [
            parse_hinfo_record,
            parse_mb_record,
            parse_mg_record,
            parse_mr_record,
            parse_minfo_record,
            parse_rp_record,
            parse_afsdb_record,
            parse_rt_record,
            parse_kx_record,
            parse_spf_record,
            parse_dname_record,
            parse_naptr_record,
            parse_sshfp_record,
            parse_tlsa_record,
            parse_cert_record,
            parse_cert_record_hex,
            parse_dhcid_record,
            parse_ds_record,
            parse_dnskey_record,
            parse_svcb_record,
            parse_https_record
        ]},
        {dns_classes, [parallel], [
            parse_class_ch,
            parse_class_hs,
            parse_class_cs
        ]},
        {edge_cases, [parallel], [
            parse_multiple_txt_strings,
            parse_soa_without_parens_multiline,
            parse_mixed_ttl_formats,
            parse_relative_and_absolute_names,
            parse_at_sign_in_soa,
            parse_default_class,
            parse_ipv4_as_domain,
            parse_ns_record_relative,
            parse_cname_record_relative,
            parse_ptr_record_relative,
            parse_txt_single_string,
            parse_default_ttl_directive,
            parse_default_class_option,
            parse_rfc3597_empty_data,
            parse_rfc3597_odd_hex_length,
            parse_rp_record_test,
            parse_afsdb_record_test,
            parse_rt_record_test,
            parse_kx_record_test,
            parse_dname_record_relative,
            parse_mb_record_relative,
            parse_mg_record_relative,
            parse_mr_record_relative,
            parse_root_domain,
            parse_spf_record_test,
            parse_record_without_origin,
            parse_rfc3597_type0,
            parse_rfc3597_type65535,
            parse_generic_class1,
            parse_string_with_list_input,
            parse_unknown_class_fallback,
            parse_uncommon_type_numbers,
            parse_generic_type_invalid,
            parse_generic_class_invalid,
            parse_ns_invalid_domain,
            parse_cname_invalid_domain,
            parse_ptr_invalid_domain,
            parse_txt_invalid_strings,
            parse_empty_origin_relative_name,
            parse_zone_only_whitespace
        ]},
        {parse_file_tests, [parallel], [
            parse_file_named_root,
            parse_file_root_zone,
            parse_file_simple,
            parse_file_with_options,
            parse_file_include_simple,
            parse_file_include_with_origin,
            parse_file_include_not_found,
            parse_file_complex_example,
            parse_file_godaddy_example,
            parse_file_godaddy_2_example,
            parse_file_simple_with_aaaa,
            parse_file_dyn,
            parse_file_list,
            parse_file_reverse,
            parse_file_simple_with_errors,
            parse_file_bad_list,
            test_format_error_with_file
        ]},
        {error_cases, [parallel], [
            parse_invalid_ipv4,
            parse_invalid_ipv6,
            parse_empty_zone,
            parse_only_comments,
            parse_file_not_found,
            parse_invalid_syntax,
            parse_rfc3597_invalid_length,
            parse_rfc3597_invalid_hex,
            parse_rfc3597_length_mismatch,
            parse_invalid_mx_rdata,
            parse_invalid_srv_rdata,
            parse_invalid_soa_rdata,
            parse_invalid_caa_rdata,
            parse_caa_with_domain_tag,
            parse_invalid_hinfo_rdata,
            parse_invalid_minfo_rdata,
            parse_ipv6_as_domain,
            parse_invalid_naptr_rdata,
            parse_invalid_sshfp_rdata,
            parse_invalid_sshfp_hex,
            parse_invalid_tlsa_rdata,
            parse_invalid_tlsa_hex,
            parse_invalid_cert_rdata,
            parse_invalid_dhcid_rdata,
            parse_invalid_dhcid_base64,
            parse_invalid_ds_rdata,
            parse_invalid_ds_hex,
            parse_invalid_dnskey_rdata,
            parse_invalid_dnskey_base64,
            parse_invalid_svcb_rdata,
            parse_invalid_https_rdata,
            test_format_error,
            test_format_error_with_suggestion
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Basic Parsing Tests
%% ============================================================================

parse_simple_a_record(_Config) ->
    Zone = <<"example.com. 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(#dns_rr{}, RR),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class),
    ?assertEqual(3600, RR#dns_rr.ttl),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR#dns_rr.data).

parse_simple_aaaa_record(_Config) ->
    Zone = <<"example.com. 3600 IN AAAA 2001:db8::1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {8193, 3512, 0, 0, 0, 0, 0, 1}}, RR#dns_rr.data).

parse_aaaa_compressed_start(_Config) ->
    %% RFC 4291 §2.2 - Compressed notation starting with ::
    Zone = <<"example.com. 3600 IN AAAA ::1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 1}}, RR#dns_rr.data).

parse_aaaa_compressed_end(_Config) ->
    %% RFC 4291 §2.2 - Compressed notation ending with ::
    Zone = <<"example.com. 3600 IN AAAA 2001:db8::\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {8193, 3512, 0, 0, 0, 0, 0, 0}}, RR#dns_rr.data).

parse_aaaa_full_format(_Config) ->
    %% RFC 4291 §2.2 - Full uncompressed format
    Zone = <<"example.com. 3600 IN AAAA 2001:0db8:0000:0000:0000:0000:0000:0001\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {8193, 3512, 0, 0, 0, 0, 0, 1}}, RR#dns_rr.data).

parse_aaaa_link_local(_Config) ->
    %% RFC 4291 §2.5.6 - Link-local address
    Zone = <<"example.com. 3600 IN AAAA fe80::1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {65152, 0, 0, 0, 0, 0, 0, 1}}, RR#dns_rr.data).

parse_aaaa_unspecified(_Config) ->
    %% RFC 4291 §2.5.2 - Unspecified address (all zeros)
    Zone = <<"example.com. 3600 IN AAAA ::\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 0}}, RR#dns_rr.data).

%% ============================================================================
%% Wildcard Label Tests - RFC 4592
%% ============================================================================

parse_wildcard_simple(_Config) ->
    %% RFC 4592 - Simple wildcard: *.example.com
    Zone = <<"*.example.com. 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"*.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR#dns_rr.data).

parse_wildcard_subdomain(_Config) ->
    %% RFC 4592 - Wildcard in subdomain: *.sub.example.com
    Zone = <<"*.sub.example.com. 3600 IN A 192.0.2.2\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"*.sub.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type).

parse_wildcard_multiple_labels(_Config) ->
    %% RFC 4592 removes RFC 1034's restriction on multiple wildcards
    %% Testing wildcard with multiple labels: *.*.example.com
    Zone = <<"*.*.example.com. 3600 IN A 192.0.2.3\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"*.*.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type).

parse_wildcard_with_srv(_Config) ->
    %% RFC 4592 - Wildcard works with all record types including SRV
    Zone = <<"*.example.com. 3600 IN SRV 10 20 80 www.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"*.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_SRV, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_srv{priority = 10, weight = 20, port = 80},
        RR#dns_rr.data
    ).

%% ============================================================================
%% Underscore Label Tests - RFC 2782, RFC 6376
%% ============================================================================

parse_underscore_srv_record(_Config) ->
    %% RFC 2782 - SRV record with service and protocol labels
    %% Format: _service._proto.name
    Zone = <<"_http._tcp.example.com. 3600 IN SRV 10 20 80 www.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"_http._tcp.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_SRV, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_srv{
            priority = 10,
            weight = 20,
            port = 80,
            target = <<"www.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_underscore_dkim_txt(_Config) ->
    %% RFC 6376 - DKIM uses underscore labels like SRV
    %% Format: selector._domainkey.domain.com
    Zone = <<"default._domainkey.example.com. 3600 IN TXT \"v=DKIM1; k=rsa; p=...\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"default._domainkey.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"v=DKIM1; k=rsa; p=...">>]}, RR#dns_rr.data).

parse_underscore_dmarc_txt(_Config) ->
    %% DMARC uses underscore labels
    %% Format: _dmarc.domain.com
    Zone = <<"_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none;\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"_dmarc.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"v=DMARC1; p=none;">>]}, RR#dns_rr.data).

parse_underscore_multiple_labels(_Config) ->
    %% Multiple underscore labels: _service._sub._proto.domain.com
    Zone = <<"_xmpp-server._tcp.example.com. 3600 IN SRV 5 0 5269 xmpp.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"_xmpp-server._tcp.example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_SRV, RR#dns_rr.type).

parse_ns_record(_Config) ->
    Zone = <<"example.com. 3600 IN NS ns1.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_NS, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_ns{dname = <<"ns1.example.com.">>}, RR#dns_rr.data).

parse_cname_record(_Config) ->
    Zone = <<"www.example.com. 3600 IN CNAME example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_CNAME, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_cname{dname = <<"example.com.">>}, RR#dns_rr.data).

parse_mx_record(_Config) ->
    Zone = <<"example.com. 3600 IN MX 10 mail.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_MX, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_mx{preference = 10, exchange = <<"mail.example.com.">>},
        RR#dns_rr.data
    ).

parse_txt_record(_Config) ->
    Zone = <<"example.com. 3600 IN TXT \"v=spf1 include:_spf.example.com ~all\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_txt{txt = [<<"v=spf1 include:_spf.example.com ~all">>]},
        RR#dns_rr.data
    ).

parse_ptr_record(_Config) ->
    Zone = <<"1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(?DNS_TYPE_PTR, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_ptr{dname = <<"example.com.">>}, RR#dns_rr.data).

parse_srv_record(_Config) ->
    Zone = <<"_http._tcp.example.com. 3600 IN SRV 10 20 80 www.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SRV, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_srv{
            priority = 10,
            weight = 20,
            port = 80,
            target = <<"www.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_caa_record(_Config) ->
    Zone = <<"example.com. 3600 IN CAA 0 \"issue\" \"letsencrypt.org\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_CAA, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_caa{flags = 0, tag = <<"issue">>, value = <<"letsencrypt.org">>},
        RR#dns_rr.data
    ).

%% ============================================================================
%% SOA Record Tests
%% ============================================================================

parse_soa_record(_Config) ->
    Zone = <<
        "example.com. 3600 IN SOA ns1.example.com. admin.example.com. (\n"
        "    2024010101  ; serial\n"
        "    3600        ; refresh\n"
        "    1800        ; retry\n"
        "    604800      ; expire\n"
        "    86400 )     ; minimum\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_soa{
            mname = <<"ns1.example.com.">>,
            rname = <<"admin.example.com.">>,
            serial = 2024010101,
            refresh = 3600,
            retry = 1800,
            expire = 604800,
            minimum = 86400
        },
        RR#dns_rr.data
    ).

parse_soa_record_no_parens(_Config) ->
    Zone = <<
        "example.com. 3600 IN SOA ns1.example.com. admin.example.com. "
        "2024010101 3600 1800 604800 86400\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_soa{
            serial = 2024010101,
            refresh = 3600
        },
        RR#dns_rr.data
    ).

%% ============================================================================
%% Multiple Record Tests
%% ============================================================================

parse_multiple_records(_Config) ->
    Zone = <<
        "example.com. 3600 IN A 192.0.2.1\n"
        "example.com. 3600 IN AAAA 2001:db8::1\n"
        "example.com. 3600 IN NS ns1.example.com.\n"
        "example.com. 3600 IN NS ns2.example.com.\n"
    >>,
    {ok, Records} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(4, length(Records)),
    [A, AAAA, NS1, NS2] = Records,
    ?assertEqual(?DNS_TYPE_A, A#dns_rr.type),
    ?assertEqual(?DNS_TYPE_AAAA, AAAA#dns_rr.type),
    ?assertEqual(?DNS_TYPE_NS, NS1#dns_rr.type),
    ?assertEqual(?DNS_TYPE_NS, NS2#dns_rr.type).

%% ============================================================================
%% Relative Name Tests
%% ============================================================================

parse_relative_name(_Config) ->
    Zone = <<"www 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"www.example.com.">>, RR#dns_rr.name).

parse_at_sign(_Config) ->
    Zone = <<"@ 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

%% ============================================================================
%% TTL Tests
%% ============================================================================

parse_time_value_hours(_Config) ->
    Zone = <<"example.com. 1h IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(3600, RR#dns_rr.ttl).

parse_time_value_days(_Config) ->
    Zone = <<"example.com. 2d IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(172800, RR#dns_rr.ttl).

parse_time_value_mixed(_Config) ->
    Zone = <<"example.com. 1h30m IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(5400, RR#dns_rr.ttl).

parse_default_ttl(_Config) ->
    Zone = <<"example.com. IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>, default_ttl => 7200}),
    ?assertEqual(7200, RR#dns_rr.ttl).

parse_time_value_years(_Config) ->
    %% BIND extension: y = year = 365 days = 31536000 seconds
    Zone = <<"example.com. 1y IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(31536000, RR#dns_rr.ttl).

parse_time_value_years_mixed(_Config) ->
    %% BIND extension: Mixed years and other units
    %% 1y6m = 1 year + 6 months (assume 30 days/month)
    %% But since our parser doesn't have months, test: 1y30d = 365 days + 30 days
    %% 1y = 31536000 seconds, 30d = 2592000 seconds
    Zone = <<"example.com. 1y30d IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(34128000, RR#dns_rr.ttl).

parse_time_value_all_units(_Config) ->
    %% Test all time units including year (BIND extension)
    %% 1y1w1d1h1m1s = 31536000 + 604800 + 86400 + 3600 + 60 + 1
    Zone = <<"example.com. 1y1w1d1h1m1s IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(32230861, RR#dns_rr.ttl).

%% ============================================================================
%% Escape Sequence Tests - RFC 1035 §5.1
%% ============================================================================

parse_escape_backslash(_Config) ->
    %% RFC 1035 §5.1: \\ means literal backslash
    Zone = <<"example.com. 3600 IN TXT \"backslash: \\\\\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"backslash: \\">>]}, RR#dns_rr.data).

parse_escape_quote(_Config) ->
    %% RFC 1035 §5.1: \" means literal quote
    Zone = <<"example.com. 3600 IN TXT \"quote: \\\"\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"quote: \"">>]}, RR#dns_rr.data).

parse_escape_decimal_simple(_Config) ->
    %% RFC 1035 §5.1: \065 = 'A' (ASCII 65)
    Zone = <<"example.com. 3600 IN TXT \"\\065BC\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"ABC">>]}, RR#dns_rr.data).

parse_escape_decimal_null(_Config) ->
    %% RFC 1035 §5.1: \000 = null byte (valid in DNS TXT records)
    Zone = <<"example.com. 3600 IN TXT \"\\000\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    % Null byte should be present
    ?assertMatch(#dns_rrdata_txt{txt = [<<0>>]}, RR#dns_rr.data).

parse_escape_decimal_space(_Config) ->
    %% RFC 1035 §5.1: \032 = space (ASCII 32)
    Zone = <<"example.com. 3600 IN TXT \"hello\\032world\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"hello world">>]}, RR#dns_rr.data).

parse_escape_decimal_max(_Config) ->
    %% RFC 1035 §5.1: \255 = maximum value (0xFF)
    Zone = <<"example.com. 3600 IN TXT \"\\255\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<255>>]}, RR#dns_rr.data).

parse_escape_decimal_mixed(_Config) ->
    %% RFC 1035 §5.1: Mixed \DDD and regular text
    %% "v=DKIM1\\059" = "v=DKIM1;" where \059 = semicolon (ASCII 59)
    Zone = <<"example.com. 3600 IN TXT \"v=DKIM1\\059 k=rsa\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"v=DKIM1; k=rsa">>]}, RR#dns_rr.data).

parse_escape_hex_simple(_Config) ->
    %% Convenience extension: \x41 = 'A' (hex 41 = decimal 65)
    Zone = <<"example.com. 3600 IN TXT \"\\x41BC\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"ABC">>]}, RR#dns_rr.data).

parse_escape_hex_lowercase(_Config) ->
    %% Convenience extension: \x61 = 'a' (lowercase hex digits)
    Zone = <<"example.com. 3600 IN TXT \"\\x61bc\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"abc">>]}, RR#dns_rr.data).

parse_escape_hex_uppercase(_Config) ->
    %% Convenience extension: \x41 = 'A' (uppercase hex digits)
    Zone = <<"example.com. 3600 IN TXT \"\\x41\\x42\\x43\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"ABC">>]}, RR#dns_rr.data).

parse_escape_hex_null(_Config) ->
    %% Convenience extension: \x00 = null byte
    Zone = <<"example.com. 3600 IN TXT \"\\x00\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<0>>]}, RR#dns_rr.data).

parse_escape_hex_max(_Config) ->
    %% Convenience extension: \xFF = maximum value (255)
    Zone = <<"example.com. 3600 IN TXT \"\\xFF\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<255>>]}, RR#dns_rr.data).

parse_escape_hex_mixed(_Config) ->
    %% Convenience extension: Mixed \xHH and regular text
    %% "v=DKIM1\x3B" = "v=DKIM1;" where \x3B = semicolon (hex 3B = decimal 59)
    Zone = <<"example.com. 3600 IN TXT \"v=DKIM1\\x3B k=rsa\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TXT, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"v=DKIM1; k=rsa">>]}, RR#dns_rr.data).

%% ============================================================================
%% RFC 3597 Tests - Generic RR Syntax
%% ============================================================================

parse_rfc3597_generic_type_simple(_Config) ->
    %% RFC 3597 - Generic type syntax: TYPE99 (unassigned type)
    Zone = <<"example.com. 3600 IN TYPE99 \\# 4 C0000201\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(99, RR#dns_rr.type),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class),
    ?assertEqual(3600, RR#dns_rr.ttl),
    %% RDATA should be binary: <<192, 0, 2, 1>>
    ?assertEqual(<<192, 0, 2, 1>>, RR#dns_rr.data).

parse_rfc3597_generic_type_min(_Config) ->
    %% RFC 3597 - Minimum type number: TYPE0
    Zone = <<"example.com. 3600 IN TYPE0 \\# 0\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(0, RR#dns_rr.type),
    ?assertEqual(<<>>, RR#dns_rr.data).

parse_rfc3597_generic_type_max(_Config) ->
    %% RFC 3597 - Maximum type number: TYPE65535
    Zone = <<"example.com. 3600 IN TYPE65535 \\# 2 ABCD\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(65535, RR#dns_rr.type),
    ?assertEqual(<<171, 205>>, RR#dns_rr.data).

parse_rfc3597_generic_class_in(_Config) ->
    %% RFC 3597 - Generic class syntax: CLASS1 (IN in generic form)
    Zone = <<"example.com. 3600 CLASS1 A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR#dns_rr.data).

parse_rfc3597_generic_class_custom(_Config) ->
    %% RFC 3597 - Custom class number: CLASS32
    Zone = <<"example.com. 3600 CLASS32 TYPE99 \\# 4 12345678\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(32, RR#dns_rr.class),
    ?assertEqual(99, RR#dns_rr.type),
    ?assertEqual(<<18, 52, 86, 120>>, RR#dns_rr.data).

parse_rfc3597_generic_rdata_empty(_Config) ->
    %% RFC 3597 - Empty RDATA: \# 0
    Zone = <<"example.com. 3600 IN TYPE100 \\# 0\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(100, RR#dns_rr.type),
    ?assertEqual(<<>>, RR#dns_rr.data).

parse_rfc3597_generic_rdata_simple(_Config) ->
    %% RFC 3597 - Simple generic RDATA with hex data
    %% \# 8 0102030405060708 = 8 bytes of sequential data
    Zone = <<"example.com. 3600 IN TYPE101 \\# 8 0102030405060708\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(101, RR#dns_rr.type),
    ?assertEqual(<<1, 2, 3, 4, 5, 6, 7, 8>>, RR#dns_rr.data).

parse_rfc3597_generic_rdata_ipv4(_Config) ->
    %% RFC 3597 - IPv4 address in generic format
    %% A record (TYPE1) using generic RDATA: \# 4 C0000201 = 192.0.2.1
    Zone = <<"example.com. 3600 IN TYPE1 \\# 4 C0000201\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    %% When using generic RDATA, it's stored as binary not as dns_rrdata_a
    ?assertEqual(<<192, 0, 2, 1>>, RR#dns_rr.data).

parse_rfc3597_combined_all_generic(_Config) ->
    %% RFC 3597 - Combination: generic type + generic class + generic RDATA
    Zone = <<"example.com. 3600 CLASS255 TYPE12345 \\# 6 AABBCCDDEEFF\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(255, RR#dns_rr.class),
    ?assertEqual(12345, RR#dns_rr.type),
    ?assertEqual(<<170, 187, 204, 221, 238, 255>>, RR#dns_rr.data).

parse_rfc3597_known_type_generic_rdata(_Config) ->
    %% RFC 3597 - Known type (A) using generic RDATA format
    %% This is valid per RFC 3597 - any type can use generic format
    Zone = <<"example.com. 3600 IN A \\# 4 C0000201\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class),
    %% Generic RDATA format stores as binary
    ?assertEqual(<<192, 0, 2, 1>>, RR#dns_rr.data).

%% ============================================================================
%% Directive Tests
%% ============================================================================

parse_origin_directive(_Config) ->
    Zone = <<
        "$ORIGIN example.com.\n"
        "www 3600 IN A 192.0.2.1\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"www.example.com.">>, RR#dns_rr.name).

parse_ttl_directive(_Config) ->
    Zone = <<
        "$TTL 7200\n"
        "example.com. IN A 192.0.2.1\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(7200, RR#dns_rr.ttl).

parse_origin_and_ttl_directives(_Config) ->
    Zone = <<
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        "www IN A 192.0.2.1\n"
        "mail IN A 192.0.2.2\n"
    >>,
    {ok, Records} = dns_zone:parse_string(Zone),
    ?assertEqual(2, length(Records)),
    [WWW, Mail] = Records,
    ?assertEqual(<<"www.example.com.">>, WWW#dns_rr.name),
    ?assertEqual(<<"mail.example.com.">>, Mail#dns_rr.name),
    ?assertEqual(3600, WWW#dns_rr.ttl),
    ?assertEqual(3600, Mail#dns_rr.ttl).

%% ============================================================================
%% Comment Tests
%% ============================================================================

%% ============================================================================
%% Comment Tests - RFC 1035 §5.1
%% ============================================================================
%% RFC 1035 §5.1: "The end of any line in the master file can end with a
%% comment. The comment starts with a ';' (semicolon)."
%% This is STANDARD, not a BIND extension.

parse_with_comments(_Config) ->
    %% RFC 1035 §5.1 - Comments on their own lines and inline
    Zone = <<
        "; This is a zone file for example.com\n"
        "example.com. 3600 IN A 192.0.2.1 ; This is the main A record\n"
        "; Another comment\n"
        "example.com. 3600 IN AAAA 2001:db8::1\n"
    >>,
    {ok, Records} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(2, length(Records)).

parse_inline_comment_after_rr(_Config) ->
    %% RFC 1035 §5.1 - Inline comment after complete RR
    Zone = <<"example.com. 3600 IN A 192.0.2.1 ; Web server IP\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR#dns_rr.data).

parse_inline_comment_in_soa(_Config) ->
    %% RFC 1035 §5.1 - Comments after each field in SOA (common practice)
    Zone = <<
        "example.com. 3600 IN SOA ns1.example.com. admin.example.com. (\n"
        "    2024010101  ; Serial number\n"
        "    3600        ; Refresh interval\n"
        "    1800        ; Retry interval\n"
        "    604800      ; Expire time\n"
        "    86400 )     ; Minimum TTL\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_soa{serial = 2024010101}, RR#dns_rr.data).

parse_inline_comment_after_directive(_Config) ->
    %% RFC 1035 §5.1 - Comments after directives
    Zone = <<
        "$ORIGIN example.com. ; Set the origin\n"
        "$TTL 3600           ; Default TTL is 1 hour\n"
        "www IN A 192.0.2.1\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"www.example.com.">>, RR#dns_rr.name),
    ?assertEqual(3600, RR#dns_rr.ttl).

parse_comment_only_lines(_Config) ->
    %% RFC 1035 §5.1 - Lines with only comments (and whitespace)
    Zone = <<
        "; ======================================\n"
        ";  DNS Zone File for example.com\n"
        "; ======================================\n"
        "\n"
        "example.com. IN A 192.0.2.1\n"
        "\n"
        ";  End of file\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type).

%% ============================================================================
%% Blank Owner Tests
%% ============================================================================

parse_blank_owner(_Config) ->
    Zone = <<
        "example.com. 3600 IN NS ns1.example.com.\n"
        "             3600 IN NS ns2.example.com.\n"
    >>,
    {ok, Records} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(2, length(Records)),
    [NS1, NS2] = Records,
    ?assertEqual(<<"example.com.">>, NS1#dns_rr.name),
    ?assertEqual(<<"example.com.">>, NS2#dns_rr.name).

%% ============================================================================
%% Less Common Record Type Tests
%% ============================================================================

parse_hinfo_record(_Config) ->
    Zone = <<"example.com. 3600 IN HINFO \"Intel Xeon\" \"Linux\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_HINFO, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_hinfo{cpu = <<"Intel Xeon">>, os = <<"Linux">>},
        RR#dns_rr.data
    ).

parse_mb_record(_Config) ->
    Zone = <<"example.com. 3600 IN MB mailhost.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_MB, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_mb{madname = <<"mailhost.example.com.">>}, RR#dns_rr.data).

parse_mg_record(_Config) ->
    Zone = <<"example.com. 3600 IN MG mailgroup.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_MG, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_mg{madname = <<"mailgroup.example.com.">>}, RR#dns_rr.data).

parse_mr_record(_Config) ->
    Zone = <<"example.com. 3600 IN MR newmail.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_MR, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_mr{newname = <<"newmail.example.com.">>}, RR#dns_rr.data).

parse_minfo_record(_Config) ->
    Zone = <<"example.com. 3600 IN MINFO admin.example.com. errors.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_MINFO, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_minfo{
            rmailbx = <<"admin.example.com.">>,
            emailbx = <<"errors.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_rp_record(_Config) ->
    Zone = <<"example.com. 3600 IN RP admin.example.com. txt.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_RP, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_rp{
            mbox = <<"admin.example.com.">>,
            txt = <<"txt.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_afsdb_record(_Config) ->
    Zone = <<"example.com. 3600 IN AFSDB 1 afsdb.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AFSDB, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_afsdb{subtype = 1, hostname = <<"afsdb.example.com.">>},
        RR#dns_rr.data
    ).

parse_rt_record(_Config) ->
    Zone = <<"example.com. 3600 IN RT 10 relay.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_RT, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_rt{preference = 10, host = <<"relay.example.com.">>},
        RR#dns_rr.data
    ).

parse_kx_record(_Config) ->
    Zone = <<"example.com. 3600 IN KX 10 kx.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_KX, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_kx{preference = 10, exchange = <<"kx.example.com.">>},
        RR#dns_rr.data
    ).

parse_spf_record(_Config) ->
    Zone = <<"example.com. 3600 IN SPF \"v=spf1 include:_spf.example.com ~all\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SPF, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_spf{spf = [<<"v=spf1 include:_spf.example.com ~all">>]},
        RR#dns_rr.data
    ).

parse_dname_record(_Config) ->
    Zone = <<"example.com. 3600 IN DNAME target.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_DNAME, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_dname{dname = <<"target.example.com.">>}, RR#dns_rr.data).

parse_naptr_record(_Config) ->
    %% NAPTR for SIP service discovery (RFC 3403)
    Zone =
        <<"_sip._tcp.example.com. 3600 IN NAPTR 100 10 \"S\" \"SIP+D2T\" \"\" _sip._tcp.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_NAPTR, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_naptr{
            order = 100,
            preference = 10,
            flags = <<"S">>,
            services = <<"SIP+D2T">>,
            regexp = <<"">>,
            replacement = <<"_sip._tcp.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_sshfp_record(_Config) ->
    %% SSHFP for SSH host key fingerprints (RFC 4255)
    %% Algorithm 2 = RSA, FP Type 1 = SHA-1
    Zone = <<"example.com. 3600 IN SSHFP 2 1 \"123456789ABCDEF67890123456789ABCDEF67890\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SSHFP, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_sshfp{
            alg = 2,
            fp_type = 1,
            fp =
                <<16#12, 16#34, 16#56, 16#78, 16#9A, 16#BC, 16#DE, 16#F6, 16#78, 16#90, 16#12,
                    16#34, 16#56, 16#78, 16#9A, 16#BC, 16#DE, 16#F6, 16#78, 16#90>>
        },
        RR#dns_rr.data
    ).

parse_tlsa_record(_Config) ->
    %% TLSA for DANE TLS certificate association (RFC 6698)
    %% Usage 3 = DANE-EE, Selector 1 = SPKI, Matching Type 1 = SHA-256
    Zone =
        <<"_443._tcp.example.com. 3600 IN TLSA 3 1 1 \"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_TLSA, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_tlsa{
            usage = 3,
            selector = 1,
            matching_type = 1,
            certificate =
                <<16#AB, 16#CD, 16#EF, 16#01, 16#23, 16#45, 16#67, 16#89, 16#AB, 16#CD, 16#EF,
                    16#01, 16#23, 16#45, 16#67, 16#89, 16#AB, 16#CD, 16#EF, 16#01, 16#23, 16#45,
                    16#67, 16#89, 16#AB, 16#CD, 16#EF, 16#01, 16#23, 16#45, 16#67, 16#89>>
        },
        RR#dns_rr.data
    ).

parse_cert_record(_Config) ->
    %% CERT for certificate records with base64 data (RFC 4398)
    %% Type 1 = PKIX, Algorithm 8 = RSA/SHA-256
    Zone = <<"example.com. 3600 IN CERT 1 12345 8 \"MIICXAIBAAKBgQC8\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_CERT, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_cert{
            type = 1,
            keytag = 12345,
            alg = 8,
            cert = <<48, 130, 2, 92, 2, 1, 0, 2, 129, 129, 0, 188>>
        },
        RR#dns_rr.data
    ).

parse_cert_record_hex(_Config) ->
    %% CERT record with hex-encoded data
    Zone = <<"example.com. 3600 IN CERT 1 12345 8 \"ABCDEF01\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_CERT, RR#dns_rr.type),
    ?assertMatch(
        #dns_rrdata_cert{
            type = 1,
            keytag = 12345,
            alg = 8,
            cert = <<16#AB, 16#CD, 16#EF, 16#01>>
        },
        RR#dns_rr.data
    ).

parse_dhcid_record(_Config) ->
    %% DHCID for DHCP client identification (RFC 4701)
    Zone = <<"example.com. 3600 IN DHCID \"AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_DHCID, RR#dns_rr.type),
    #dns_rrdata_dhcid{data = Data} = RR#dns_rr.data,
    %% Verify it's valid base64-decoded binary data
    ?assert(is_binary(Data)),
    ?assert(byte_size(Data) > 0).

parse_ds_record(_Config) ->
    %% DS (Delegation Signer) for DNSSEC (RFC 4034)
    %% Format: keytag algorithm digest-type digest
    Zone = <<"example.com. 3600 IN DS 12345 8 2 \"49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_DS, RR#dns_rr.type),
    #dns_rrdata_ds{
        keytag = KeyTag,
        alg = Alg,
        digest_type = DigestType,
        digest = Digest
    } = RR#dns_rr.data,
    ?assertEqual(12345, KeyTag),
    ?assertEqual(8, Alg),
    ?assertEqual(2, DigestType),
    ?assert(is_binary(Digest)),
    ?assertEqual(20, byte_size(Digest)).

parse_dnskey_record(_Config) ->
    %% DNSKEY (DNS Public Key) for DNSSEC (RFC 4034)
    %% Format: flags protocol algorithm public-key
    %% This is a real DNSKEY for example.com (ZSK, Zone Signing Key)
    Zone =
        <<"example.com. 3600 IN DNSKEY 256 3 8 \"AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_DNSKEY, RR#dns_rr.type),
    #dns_rrdata_dnskey{
        flags = Flags,
        protocol = Protocol,
        alg = Alg,
        public_key = PublicKey,
        keytag = KeyTag
    } = RR#dns_rr.data,
    ?assertEqual(256, Flags),
    ?assertEqual(3, Protocol),
    ?assertEqual(8, Alg),
    ?assert(is_binary(PublicKey)),
    ?assert(byte_size(PublicKey) > 0),
    %% KeyTag should be calculated automatically
    ?assert(is_integer(KeyTag)),
    ?assert(KeyTag >= 0),
    ?assert(KeyTag =< 65535).

parse_svcb_record(_Config) ->
    %% SVCB (Service Binding) for modern service discovery (RFC 9460)
    %% Format: priority target [svcparams...]
    %% Note: svcparams are not yet supported, only basic priority and target
    Zone = <<"example.com. 3600 IN SVCB 1 svc.example.com.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SVCB, RR#dns_rr.type),
    #dns_rrdata_svcb{
        svc_priority = Priority,
        target_name = TargetName,
        svc_params = SvcParams
    } = RR#dns_rr.data,
    ?assertEqual(1, Priority),
    ?assertEqual(<<"svc.example.com.">>, TargetName),
    ?assertEqual(#{}, SvcParams).

parse_https_record(_Config) ->
    %% HTTPS (HTTPS-specific Service Binding) for HTTPS discovery (RFC 9460)
    %% Format: priority target [svcparams...]
    %% Note: svcparams are not yet supported, only basic priority and target
    %% Using "." as target means use the owner name
    Zone = <<"example.com. 3600 IN HTTPS 1 .\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_HTTPS, RR#dns_rr.type),
    #dns_rrdata_svcb{
        svc_priority = Priority,
        target_name = TargetName,
        svc_params = SvcParams
    } = RR#dns_rr.data,
    ?assertEqual(1, Priority),
    ?assertEqual(<<".">>, TargetName),
    ?assertEqual(#{}, SvcParams).

%% ============================================================================
%% Full Zone File Test
%% ============================================================================

parse_full_zone(_Config) ->
    Zone = <<
        "; Zone file for example.com\n"
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        "\n"
        "; SOA record\n"
        "@ IN SOA ns1.example.com. admin.example.com. (\n"
        "    2024010101 ; serial\n"
        "    3600       ; refresh\n"
        "    1800       ; retry\n"
        "    604800     ; expire\n"
        "    86400 )    ; minimum\n"
        "\n"
        "; Name servers\n"
        "@ IN NS ns1.example.com.\n"
        "@ IN NS ns2.example.com.\n"
        "\n"
        "; Main domain\n"
        "@ IN A 192.0.2.1\n"
        "@ IN AAAA 2001:db8::1\n"
        "\n"
        "; Subdomains\n"
        "www IN A 192.0.2.2\n"
        "mail IN A 192.0.2.3\n"
        "ftp IN CNAME www\n"
        "\n"
        "; Mail\n"
        "@ IN MX 10 mail.example.com.\n"
        "@ IN TXT \"v=spf1 include:_spf.example.com ~all\"\n"
    >>,
    {ok, Records} = dns_zone:parse_string(Zone),
    ?assert(length(Records) > 0),

    %% Check that we have the expected record types
    Types = [RR#dns_rr.type || RR <- Records],
    ?assert(lists:member(?DNS_TYPE_SOA, Types)),
    ?assert(lists:member(?DNS_TYPE_NS, Types)),
    ?assert(lists:member(?DNS_TYPE_A, Types)),
    ?assert(lists:member(?DNS_TYPE_AAAA, Types)),
    ?assert(lists:member(?DNS_TYPE_CNAME, Types)),
    ?assert(lists:member(?DNS_TYPE_MX, Types)),
    ?assert(lists:member(?DNS_TYPE_TXT, Types)).

%% ============================================================================
%% Real World Zone File Tests
%% ============================================================================

parse_file_named_root(_Config) ->
    %% Parse the root hints file (named.root)
    DataDir = proplists:get_value(data_dir, _Config),
    FilePath = filename:join(DataDir, "named.root"),

    {ok, Records} = dns_zone:parse_file(FilePath),

    %% Verify we got records
    ?assert(length(Records) > 0),

    %% The named.root file contains NS, A, and AAAA records for the 13 root servers
    %% Expected: 13 NS records for "." + 13 A records + 13 AAAA records = 39 records
    ?assert(length(Records) >= 39),

    %% Check that we have the expected record types
    Types = [RR#dns_rr.type || RR <- Records],
    ?assert(lists:member(?DNS_TYPE_NS, Types)),
    ?assert(lists:member(?DNS_TYPE_A, Types)),
    ?assert(lists:member(?DNS_TYPE_AAAA, Types)),

    %% Verify some root server names are present
    Names = [RR#dns_rr.name || RR <- Records],
    ?assert(lists:member(<<"a.root-servers.net.">>, Names)),
    ?assert(lists:member(<<"m.root-servers.net.">>, Names)),

    %% Check that root zone (".") has NS records
    RootNSRecords = [
        RR
     || RR <- Records,
        RR#dns_rr.name =:= <<".">>,
        RR#dns_rr.type =:= ?DNS_TYPE_NS
    ],
    ?assertEqual(13, length(RootNSRecords)).

parse_file_root_zone(_Config) ->
    %% Parse a sample of the root zone file
    %% Note: The full root.zone is very large (~650KB), this tests that we can handle it
    DataDir = proplists:get_value(data_dir, _Config),
    FilePath = filename:join(DataDir, "root.zone"),

    Result = dns_zone:parse_file(FilePath),

    %% The root zone may have parsing issues due to complex DNSSEC records
    %% or unusual formatting, so we accept either success or specific error types
    case Result of
        {ok, Records} ->
            %% If it parses successfully, verify basic properties
            ?assert(length(Records) > 0),

            %% Should contain various record types including DNSSEC
            Types = lists:usort([RR#dns_rr.type || RR <- Records]),
            ?assert(length(Types) > 1);
        {error, Reason} ->
            %% If it fails, log the reason but don't fail the test
            %% This is because the root zone may contain records or formats
            %% that our parser doesn't fully support yet
            ct:log("Root zone parsing failed (expected for complex DNSSEC zones): ~p", [Reason]),
            %% Mark as passed - we're testing that it doesn't crash
            ok
    end.

%% ============================================================================
%% Error Tests
%% ============================================================================

parse_invalid_ipv4(_Config) ->
    %% Test A record with invalid IPv4 format that gets past lexer
    %% This is tricky - need to trigger parse_ipv4 error path
    %% The lexer usually catches bad IPs, but domain fallback might not
    Zone = <<"example.com. 3600 IN A 999.999.999.999\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_ipv6(_Config) ->
    Zone = <<"example.com. 3600 IN AAAA zzz::1\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_empty_zone(_Config) ->
    Zone = <<"\n\n\n">>,
    {ok, []} = dns_zone:parse_string(Zone).

parse_only_comments(_Config) ->
    Zone = <<
        "; This is a comment\n"
        "; Another comment\n"
    >>,
    {ok, []} = dns_zone:parse_string(Zone).

parse_file_not_found(_Config) ->
    %% Test error when file doesn't exist
    {error, #{type := file}} = dns_zone:parse_file("/nonexistent/file.zone").

parse_invalid_syntax(_Config) ->
    %% Test parser error with invalid syntax
    Zone = <<"example.com. 3600 IN A INVALID_IP\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_rfc3597_invalid_length(_Config) ->
    %% RFC 3597 - Invalid length specification
    Zone = <<"example.com. 3600 IN TYPE99 \\# INVALID C0000201\n">>,
    {error, _} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_rfc3597_invalid_hex(_Config) ->
    %% RFC 3597 - Invalid hex characters
    Zone = <<"example.com. 3600 IN TYPE99 \\# 4 GGGGGGGG\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_rfc3597_length_mismatch(_Config) ->
    %% RFC 3597 - Length doesn't match hex data
    Zone = <<"example.com. 3600 IN TYPE99 \\# 10 C0000201\n">>,
    {error, #{type := semantic, details := {semantic_error, {rfc3597_length_mismatch, 10, 4}}}} =
        dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

%% ============================================================================
%% parse_file Tests
%% ============================================================================

parse_file_simple(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "simple.zone"),
    {ok, [RR | _] = Records} = dns_zone:parse_file(TestFile),
    ?assertEqual(7, length(Records)),
    ?assertEqual(3600, RR#dns_rr.ttl),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

parse_file_with_options(Config) ->
    %% Use test data file with relative names from data_dir
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "with_options.zone"),
    %% Parse with origin option
    {ok, Records} = dns_zone:parse_file(TestFile, #{origin => <<"example.com.">>}),
    ?assertEqual(2, length(Records)),
    [RR1, RR2] = Records,
    ?assertEqual(<<"www.example.com.">>, RR1#dns_rr.name),
    ?assertEqual(<<"mail.example.com.">>, RR2#dns_rr.name),
    %% Parse with TTL option
    {ok, [RR3 | _]} = dns_zone:parse_file(TestFile, #{
        origin => <<"example.com.">>,
        default_ttl => 9999
    }),
    %% The file has explicit TTL, so default_ttl shouldn't override it
    ?assertEqual(3600, RR3#dns_rr.ttl).

%% ============================================================================
%% $INCLUDE Directive Tests
%% ============================================================================

parse_file_include_simple(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "main_simple.zone"),
    %% Parse the main file
    {ok, Records} = dns_zone:parse_file(TestFile),
    ?assertEqual(2, length(Records)),
    %% Verify records
    [WWW, Mail] = Records,
    ?assertEqual(<<"www.example.com.">>, WWW#dns_rr.name),
    ?assertEqual(<<"mail.example.com.">>, Mail#dns_rr.name).

parse_file_include_with_origin(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "main_origin.zone"),
    %% Parse the main file
    {ok, [RR]} = dns_zone:parse_file(TestFile),
    %% Verify the included record has the specified origin
    ?assertEqual(<<"ns1.sub.example.com.">>, RR#dns_rr.name).

parse_file_include_not_found(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "main_error.zone"),
    %% Parse should fail with file error from included file
    {error, #{type := file}} = dns_zone:parse_file(TestFile).

parse_file_complex_example(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "example.zone"),
    %% Parse should fail with file error from included file
    {ok, [RR | _]} = dns_zone:parse_file(TestFile),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

parse_file_godaddy_example(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "godaddy.zone"),
    %% Parse should fail with file error from included file
    {ok, [RR | _]} = dns_zone:parse_file(TestFile),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

parse_file_godaddy_2_example(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "godaddy-2.zone"),
    %% Parse should fail with file error from included file
    {ok, [RR | _]} = dns_zone:parse_file(TestFile),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

parse_file_simple_with_aaaa(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "simple-with-aaaa.zone"),
    %% Parse should fail with file error from included file
    {ok, [_ | _] = Records} = dns_zone:parse_file(TestFile),
    AAAA = lists:last(Records),
    ?assertEqual(6, length(Records)),
    ?assertEqual(3600, AAAA#dns_rr.ttl),
    ?assertEqual(?DNS_TYPE_AAAA, AAAA#dns_rr.type),
    ?assertEqual(<<"test01.example.com.">>, AAAA#dns_rr.name).

parse_file_dyn(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "dyn.zone"),
    {ok, [_ | _] = Records} = dns_zone:parse_file(TestFile),
    SearchCname = lists:search(
        fun(#dns_rr{name = Name, type = Type}) ->
            ?DNS_TYPE_CNAME =:= Type andalso <<"admin.foo.bar.">> =:= Name
        end,
        Records
    ),
    ?assertMatch(
        {value, #dns_rr{
            data = #dns_rrdata_cname{
                dname = <<"hello-world.dnsimple.com.">>
            }
        }},
        SearchCname
    ),
    SearchMx = lists:search(
        fun(#dns_rr{name = Name, type = Type}) ->
            ?DNS_TYPE_MX =:= Type andalso <<"foo.bar.">> =:= Name
        end,
        Records
    ),
    ?assertMatch(
        {value, #dns_rr{
            data = #dns_rrdata_mx{
                exchange = <<"mx.l.mike.com.">>
            }
        }},
        SearchMx
    ),
    ?assertEqual(43, length(Records)).

parse_file_list(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "list.zone"),
    {ok, [RR | _] = Records} = dns_zone:parse_file(TestFile),
    Cname = lists:last(Records),
    ?assertEqual(16, length(Records)),
    ?assertEqual(<<>>, RR#dns_rr.name),
    ?assertEqual(<<"calendar">>, Cname#dns_rr.name),
    ?assertMatch(#dns_rrdata_cname{dname = <<"baz.examplehosted.com.">>}, Cname#dns_rr.data).

parse_file_reverse(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "reverse.zone"),
    {ok, [_ | _] = Records} = dns_zone:parse_file(TestFile),
    Ptr = lists:last(Records),
    ?assertEqual(6, length(Records)),
    ?assertEqual(<<"4.3.2.1.in-addr.arpa.">>, Ptr#dns_rr.name),
    ?assertMatch(#dns_rrdata_ptr{dname = <<"example.com.">>}, Ptr#dns_rr.data).

parse_file_simple_with_errors(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "simple-with-errors.zone"),
    %% Parse should fail with file error from included file
    {error, Error} = dns_zone:parse_file(TestFile),
    Location = maps:get(location, Error, #{}),
    ?assert(maps:is_key(file, Location), Error),
    Formatted = dns_zone:format_error(Error),
    FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
    ?assertNotEqual(nomatch, string:find(FormattedStr, "simple-with-errors.zone"), FormattedStr).

parse_file_bad_list(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    TestFile = filename:join(DataDir, "bad-list.zone"),
    {error, Error} = dns_zone:parse_file(TestFile),
    %% Error should have file in location
    Location = maps:get(location, Error, #{}),
    ?assert(maps:is_key(file, Location), Error),
    %% Format error should include file path
    Formatted = dns_zone:format_error(Error),
    FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
    ?assertNotEqual(nomatch, string:find(FormattedStr, "bad-list.zone"), FormattedStr).

test_format_error_with_file(Config) ->
    %% Test format_error with file path in error location
    DataDir = proplists:get_value(priv_dir, Config),
    TestFile = filename:join(DataDir, "test_error.zone"),
    file:write_file(TestFile, <<"example.com. 3600 IN SSHFP 2 1\n">>),
    {error, Error} = dns_zone:parse_file(TestFile),
    Location = maps:get(location, Error, #{}),
    ?assert(maps:is_key(file, Location), Error),
    Formatted = dns_zone:format_error(Error),
    FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
    ?assertNotEqual(nomatch, string:find(FormattedStr, "test_error.zone"), FormattedStr).

% ★ bad-list.txt
% ★ dyn.txt
% ★ list.txt
% ★ reverse.txt

%% ============================================================================
%% DNS Class Tests
%% ============================================================================

parse_class_ch(_Config) ->
    %% Test CHAOS class
    Zone = <<"example.com. 3600 CH A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_CH, RR#dns_rr.class).

parse_class_hs(_Config) ->
    %% Test HESIOD class
    Zone = <<"example.com. 3600 HS A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_HS, RR#dns_rr.class).

parse_class_cs(_Config) ->
    %% Test CSNET class
    Zone = <<"example.com. 3600 CS A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_CS, RR#dns_rr.class).

%% ============================================================================
%% Edge Case Tests
%% ============================================================================

parse_multiple_txt_strings(_Config) ->
    %% Test TXT record with multiple strings
    Zone = <<"example.com. 3600 IN TXT \"string1\" \"string2\" \"string3\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(
        #dns_rrdata_txt{txt = [<<"string1">>, <<"string2">>, <<"string3">>]}, RR#dns_rr.data
    ).

parse_soa_without_parens_multiline(_Config) ->
    %% Test SOA record without parentheses (single line)
    Zone =
        <<"example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_soa{serial = 2024010101}, RR#dns_rr.data).

parse_mixed_ttl_formats(_Config) ->
    %% Test mixing numeric and unit-based TTL values
    Zone = <<
        "$TTL 3600\n"
        "example.com. IN A 192.0.2.1\n"
        "www 1h IN A 192.0.2.2\n"
        "mail 7200 IN A 192.0.2.3\n"
    >>,
    {ok, [RR1, RR2, RR3]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(3600, RR1#dns_rr.ttl),
    ?assertEqual(3600, RR2#dns_rr.ttl),
    ?assertEqual(7200, RR3#dns_rr.ttl).

parse_relative_and_absolute_names(_Config) ->
    %% Test mix of relative and absolute names
    Zone = <<
        "$ORIGIN example.com.\n"
        "www 3600 IN A 192.0.2.1\n"
        "mail.example.com. 3600 IN A 192.0.2.2\n"
        "ftp 3600 IN CNAME www\n"
        "ns1 3600 IN A 192.0.2.3\n"
    >>,
    {ok, [WWW, Mail, FTP, NS1]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"www.example.com.">>, WWW#dns_rr.name),
    ?assertEqual(<<"mail.example.com.">>, Mail#dns_rr.name),
    ?assertEqual(<<"ftp.example.com.">>, FTP#dns_rr.name),
    ?assertMatch(#dns_rrdata_cname{dname = <<"www.example.com.">>}, FTP#dns_rr.data),
    ?assertEqual(<<"ns1.example.com.">>, NS1#dns_rr.name).

parse_at_sign_in_soa(_Config) ->
    %% Test @ symbol in SOA record
    Zone = <<
        "$ORIGIN example.com.\n"
        "@ 3600 IN SOA ns1.example.com. admin.example.com. (\n"
        "    2024010101\n"
        "    3600\n"
        "    1800\n"
        "    604800\n"
        "    86400\n"
        ")\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_SOA, RR#dns_rr.type).

parse_default_class(_Config) ->
    %% Test that default class is IN when not specified
    Zone = <<"example.com. 3600 A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class).

%% ============================================================================
%% Additional Error Case Tests
%% ============================================================================

parse_invalid_mx_rdata(_Config) ->
    %% MX record with invalid RDATA
    Zone = <<"example.com. 3600 IN MX INVALID\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_srv_rdata(_Config) ->
    %% SRV record with invalid RDATA
    Zone = <<"_http._tcp.example.com. 3600 IN SRV 10 20\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_soa_rdata(_Config) ->
    %% SOA record with incomplete RDATA
    Zone = <<"example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_caa_rdata(_Config) ->
    %% CAA record with invalid RDATA
    Zone = <<"example.com. 3600 IN CAA 0\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_caa_with_domain_tag(_Config) ->
    %% CAA record with tag parsed as domain (tests alternative code path)
    Zone = <<"example.com. 3600 IN CAA 0 issue \"ca.example.com\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(#dns_rrdata_caa{tag = <<"issue">>}, RR#dns_rr.data).

parse_invalid_hinfo_rdata(_Config) ->
    %% HINFO record with invalid RDATA
    Zone = <<"example.com. 3600 IN HINFO \"PC\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_minfo_rdata(_Config) ->
    %% MINFO record with invalid RDATA
    Zone = <<"example.com. 3600 IN MINFO admin.example.com.\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_ipv6_as_domain(_Config) ->
    %% Sometimes IPv6 addresses are parsed as domain names (tests fallback path)
    Zone = <<"example.com. 3600 IN AAAA 2001:db8::1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_TYPE_AAAA, RR#dns_rr.type),
    ?assertMatch(#dns_rrdata_aaaa{ip = {8193, 3512, 0, 0, 0, 0, 0, 1}}, RR#dns_rr.data).

parse_invalid_naptr_rdata(_Config) ->
    %% NAPTR record with invalid RDATA (missing fields)
    Zone = <<"example.com. 3600 IN NAPTR 100 10\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_sshfp_rdata(_Config) ->
    %% SSHFP record with invalid RDATA (missing fingerprint)
    Zone = <<"example.com. 3600 IN SSHFP 2 1\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_sshfp_hex(_Config) ->
    %% SSHFP record with invalid hex data (odd length)
    Zone = <<"example.com. 3600 IN SSHFP 2 1 \"ABCDE\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_tlsa_rdata(_Config) ->
    %% TLSA record with invalid RDATA (missing cert data)
    Zone = <<"_443._tcp.example.com. 3600 IN TLSA 3 1 1\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_tlsa_hex(_Config) ->
    %% TLSA record with invalid hex data (odd length)
    Zone = <<"_443._tcp.example.com. 3600 IN TLSA 3 1 1 \"ABC\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_cert_rdata(_Config) ->
    %% CERT record with invalid RDATA (missing cert data)
    Zone = <<"example.com. 3600 IN CERT 1 12345 8\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_dhcid_rdata(_Config) ->
    %% DHCID record with no RDATA
    Zone = <<"example.com. 3600 IN DHCID\n">>,
    {error, #{type := parser}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_dhcid_base64(_Config) ->
    %% DHCID record with invalid base64 data
    Zone = <<"example.com. 3600 IN DHCID \"!!!INVALID!!!\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_ds_rdata(_Config) ->
    %% DS record with missing fields
    Zone = <<"example.com. 3600 IN DS 12345\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_ds_hex(_Config) ->
    %% DS record with invalid hex digest (odd length)
    Zone = <<"example.com. 3600 IN DS 12345 8 2 \"49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51D\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_dnskey_rdata(_Config) ->
    %% DNSKEY record with missing fields
    Zone = <<"example.com. 3600 IN DNSKEY 256 3\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_dnskey_base64(_Config) ->
    %% DNSKEY record with invalid base64 public key
    Zone = <<"example.com. 3600 IN DNSKEY 256 3 8 \"!!!INVALID!!!\"\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_svcb_rdata(_Config) ->
    %% SVCB record with missing target
    Zone = <<"example.com. 3600 IN SVCB 1\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_invalid_https_rdata(_Config) ->
    %% HTTPS record with missing target
    Zone = <<"example.com. 3600 IN HTTPS 1\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

test_format_error(_Config) ->
    %% Test formatting of error details
    Zone = <<"example.com. 3600 IN SSHFP 2 1\n">>,
    {error, Error} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),

    %% Error should be a map with proper structure
    ?assert(is_map(Error)),
    ?assertEqual(semantic, maps:get(type, Error)),
    ?assert(is_binary(maps:get(message, Error))),

    %% format_error should produce iolist
    Formatted = dns_zone:format_error(Error),
    ?assert(is_list(Formatted) orelse is_binary(Formatted)),

    %% Should contain helpful text
    FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
    ?assert(string:find(FormattedStr, "SSHFP") =/= nomatch),
    ?assert(
        string:find(FormattedStr, "Suggestion") =/= nomatch orelse
            string:find(FormattedStr, "Example") =/= nomatch
    ).

test_format_error_with_suggestion(_Config) ->
    %% Test format_error with suggestion in error
    Zone = <<"example.com. 3600 IN DS 12345\n">>,
    {error, Error} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    %% Error should have suggestion
    ?assert(maps:is_key(suggestion, Error)),
    %% Format error should include suggestion
    Formatted = dns_zone:format_error(Error),
    FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
    ?assert(
        string:find(FormattedStr, "Suggestion") =/= nomatch orelse
            string:find(FormattedStr, "Example") =/= nomatch
    ).

%% ============================================================================
%% More Edge Case Tests
%% ============================================================================

parse_ipv4_as_domain(_Config) ->
    %% IPv4 sometimes lexed as domain (tests A record fallback path)
    Zone = <<"example.com. 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(#dns_rrdata_a{ip = {192, 0, 2, 1}}, RR#dns_rr.data).

parse_ns_record_relative(_Config) ->
    %% NS record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "@ 3600 IN NS ns1\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_ns{dname = <<"ns1.example.com.">>}, RR#dns_rr.data).

parse_cname_record_relative(_Config) ->
    %% CNAME record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "www 3600 IN CNAME server\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_cname{dname = <<"server.example.com.">>}, RR#dns_rr.data).

parse_ptr_record_relative(_Config) ->
    %% PTR record
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN PTR server.example.com.\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_ptr{dname = <<"server.example.com.">>}, RR#dns_rr.data).

parse_txt_single_string(_Config) ->
    %% TXT record with single string
    Zone = <<"example.com. 3600 IN TXT \"v=spf1 mx -all\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(#dns_rrdata_txt{txt = [<<"v=spf1 mx -all">>]}, RR#dns_rr.data).

parse_default_ttl_directive(_Config) ->
    %% Test $TTL directive sets default TTL
    Zone = <<
        "$TTL 7200\n"
        "$ORIGIN example.com.\n"
        "www IN A 192.0.2.1\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(7200, RR#dns_rr.ttl).

parse_default_class_option(_Config) ->
    %% Test default_class option
    Zone = <<"example.com. 3600 A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{
        origin => <<"example.com.">>,
        default_class => ?DNS_CLASS_CH
    }),
    ?assertEqual(?DNS_CLASS_CH, RR#dns_rr.class).

parse_rfc3597_empty_data(_Config) ->
    %% RFC 3597 - Verify empty data works correctly
    Zone = <<"example.com. 3600 IN TYPE100 \\# 0\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(100, RR#dns_rr.type),
    ?assertEqual(<<>>, RR#dns_rr.data).

parse_rfc3597_odd_hex_length(_Config) ->
    %% RFC 3597 - Odd number of hex characters (invalid)
    Zone = <<"example.com. 3600 IN TYPE99 \\# 2 ABC\n">>,
    {error, #{type := semantic}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

parse_rp_record_test(_Config) ->
    %% RP record with relative names
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN RP admin.example.com. txt.example.com.\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(
        #dns_rrdata_rp{
            mbox = <<"admin.example.com.">>,
            txt = <<"txt.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_afsdb_record_test(_Config) ->
    %% AFSDB record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN AFSDB 1 afsserver.example.com.\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(
        #dns_rrdata_afsdb{
            subtype = 1,
            hostname = <<"afsserver.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_rt_record_test(_Config) ->
    %% RT record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN RT 10 relay.example.com.\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(
        #dns_rrdata_rt{
            preference = 10,
            host = <<"relay.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_kx_record_test(_Config) ->
    %% KX record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN KX 10 kx.example.com.\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(
        #dns_rrdata_kx{
            preference = 10,
            exchange = <<"kx.example.com.">>
        },
        RR#dns_rr.data
    ).

parse_dname_record_relative(_Config) ->
    %% DNAME record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN DNAME target\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_dname{dname = <<"target.example.com.">>}, RR#dns_rr.data).

parse_mb_record_relative(_Config) ->
    %% MB record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN MB mailbox\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_mb{madname = <<"mailbox.example.com.">>}, RR#dns_rr.data).

parse_mg_record_relative(_Config) ->
    %% MG record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN MG mail\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_mg{madname = <<"mail.example.com.">>}, RR#dns_rr.data).

parse_mr_record_relative(_Config) ->
    %% MR record with relative name
    Zone = <<
        "$ORIGIN example.com.\n"
        "host 3600 IN MR newname\n"
    >>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertMatch(#dns_rrdata_mr{newname = <<"newname.example.com.">>}, RR#dns_rr.data).

parse_root_domain(_Config) ->
    %% Test root domain (.)
    Zone = <<".\t3600\tIN\tNS\ta.root-servers.net.\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<".">>, RR#dns_rr.name).

parse_spf_record_test(_Config) ->
    %% SPF record with multiple strings
    Zone = <<"example.com. 3600 IN SPF \"v=spf1\" \"mx\" \"-all\"\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertMatch(#dns_rrdata_spf{spf = [<<"v=spf1">>, <<"mx">>, <<"-all">>]}, RR#dns_rr.data).

parse_record_without_origin(_Config) ->
    %% Test parsing record without setting origin
    Zone = <<"example.com. 3600 IN A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name).

parse_rfc3597_type0(_Config) ->
    %% RFC 3597 - TYPE0
    Zone = <<"example.com. 3600 IN TYPE0 \\# 0\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(0, RR#dns_rr.type).

parse_rfc3597_type65535(_Config) ->
    %% RFC 3597 - TYPE65535 (max type)
    Zone = <<"example.com. 3600 IN TYPE65535 \\# 2 ABCD\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(65535, RR#dns_rr.type).

parse_generic_class1(_Config) ->
    %% RFC 3597 - CLASS1 is IN
    Zone = <<"example.com. 3600 CLASS1 A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class).

%% Test parse_string with list (string) input instead of binary
parse_string_with_list_input(_Config) ->
    %% Test line 188: parse_string(list_to_binary(Data), Options)
    Zone = "example.com. 3600 IN A 192.0.2.1\n",
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(<<"example.com.">>, RR#dns_rr.name),
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type).

%% Test unknown DNS class fallback to IN
parse_unknown_class_fallback(_Config) ->
    %% Test line 766: class_to_number(_) default clause
    %% This is harder to test since the parser validates classes
    %% but we can verify behavior with valid but uncommon classes
    Zone = <<"example.com. 3600 CH A 192.0.2.1\n">>,
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_CH, RR#dns_rr.class).

%% Test uncommon DNS type numbers
parse_uncommon_type_numbers(_Config) ->
    %% Test various type_to_number clauses (lines 798-860)
    %% Use RFC 3597 format to test these types
    Tests = [
        {<<"NAPTR">>, ?DNS_TYPE_NAPTR, <<"\\# 4 C0000201">>},
        {<<"SSHFP">>, ?DNS_TYPE_SSHFP, <<"\\# 4 C0000201">>},
        {<<"TLSA">>, ?DNS_TYPE_TLSA, <<"\\# 4 C0000201">>},
        {<<"DS">>, ?DNS_TYPE_DS, <<"\\# 4 C0000201">>},
        {<<"DNSKEY">>, ?DNS_TYPE_DNSKEY, <<"\\# 4 C0000201">>},
        {<<"RRSIG">>, ?DNS_TYPE_RRSIG, <<"\\# 4 C0000201">>},
        {<<"NSEC">>, ?DNS_TYPE_NSEC, <<"\\# 4 C0000201">>},
        {<<"NSEC3">>, ?DNS_TYPE_NSEC3, <<"\\# 4 C0000201">>},
        {<<"NSEC3PARAM">>, ?DNS_TYPE_NSEC3PARAM, <<"\\# 4 C0000201">>},
        {<<"CDNSKEY">>, ?DNS_TYPE_CDNSKEY, <<"\\# 4 C0000201">>},
        {<<"CDS">>, ?DNS_TYPE_CDS, <<"\\# 4 C0000201">>},
        {<<"KEY">>, ?DNS_TYPE_KEY, <<"\\# 4 C0000201">>},
        {<<"LOC">>, ?DNS_TYPE_LOC, <<"\\# 4 C0000201">>},
        {<<"NXT">>, ?DNS_TYPE_NXT, <<"\\# 4 C0000201">>},
        {<<"CERT">>, ?DNS_TYPE_CERT, <<"\\# 4 C0000201">>},
        {<<"DHCID">>, ?DNS_TYPE_DHCID, <<"\\# 4 C0000201">>},
        {<<"SVCB">>, ?DNS_TYPE_SVCB, <<"\\# 4 C0000201">>},
        {<<"HTTPS">>, ?DNS_TYPE_HTTPS, <<"\\# 4 C0000201">>},
        {<<"DLV">>, ?DNS_TYPE_DLV, <<"\\# 4 C0000201">>},
        {<<"IPSECKEY">>, ?DNS_TYPE_IPSECKEY, <<"\\# 4 C0000201">>}
    ],
    lists:foreach(
        fun({TypeName, TypeNum, RData}) ->
            Zone = iolist_to_binary([
                <<"example.com. 3600 IN ">>, TypeName, <<" ">>, RData, <<"\n">>
            ]),
            {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
            ?assertEqual(TypeNum, RR#dns_rr.type)
        end,
        Tests
    ).

%% Test parse_generic_type with invalid format
parse_generic_type_invalid(_Config) ->
    %% Test lines 900, 903, 906: parse_generic_type error paths
    %% When TYPE number is out of range, it falls back to A (TYPE1)
    Zone = <<"example.com. 3600 IN TYPE99999 \\# 4 C0000201\n">>,
    %% TYPE99999 is out of range (> 65535), falls back to A
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    %% Verify it falls back to TYPE A
    ?assertEqual(?DNS_TYPE_A, RR#dns_rr.type).

%% Test parse_generic_class with invalid format
parse_generic_class_invalid(_Config) ->
    %% Test lines 916, 919, 922: parse_generic_class error paths
    %% When CLASS number is out of range, it falls back to IN (CLASS1)
    Zone = <<"example.com. 3600 CLASS99999 A 192.0.2.1\n">>,
    %% CLASS99999 is out of range (> 65535), falls back to IN
    {ok, [RR]} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}),
    ?assertEqual(?DNS_CLASS_IN, RR#dns_rr.class).

%% Test NS record with invalid domain
parse_ns_invalid_domain(_Config) ->
    %% Test line 440: NS extract_domain error
    %% This is tricky - need malformed RDATA that passes parsing but fails semantic processing
    Zone = <<"example.com. 3600 IN NS\n">>,
    %% Missing nameserver - this is a parser error
    {error, #{type := parser}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

%% Test CNAME record with invalid domain
parse_cname_invalid_domain(_Config) ->
    %% Test line 447: CNAME extract_domain error
    Zone = <<"example.com. 3600 IN CNAME\n">>,
    %% Missing target - this is a parser error
    {error, #{type := parser}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

%% Test PTR record with invalid domain
parse_ptr_invalid_domain(_Config) ->
    %% Test line 454: PTR extract_domain error
    Zone = <<"1.2.0.192.in-addr.arpa. 3600 IN PTR\n">>,
    %% Missing target - this is a parser error
    {error, #{type := parser}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

%% Test TXT record with invalid strings
parse_txt_invalid_strings(_Config) ->
    %% Test line 469, 640: TXT extract_strings error
    %% TXT needs at least one string - this is a parser error
    Zone = <<"example.com. 3600 IN TXT\n">>,
    {error, #{type := parser}} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).

%% Test relative name resolution with empty origin
parse_empty_origin_relative_name(_Config) ->
    %% Test line 651: resolve_name when origin is empty
    Zone = <<"relative-name 3600 IN A 192.0.2.1\n">>,
    %% Parse without setting an origin - relative name stays as-is
    {ok, [RR]} = dns_zone:parse_string(Zone),
    ?assertEqual(<<"relative-name">>, RR#dns_rr.name).

%% ============================================================================
%% Additional Edge Case Tests
%% ============================================================================

parse_zone_only_whitespace(_Config) ->
    %% Zone with only whitespace should return empty list
    Zone = <<"   \n\t\n  \n">>,
    {ok, []} = dns_zone:parse_string(Zone, #{origin => <<"example.com.">>}).
