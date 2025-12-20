-module(dns_record_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            type_rec,
            recinfo,
            recinfo_new_types,
            recinfo_missing_coverage,
            serialise_dnssec,
            serialise_optrr,
            serialise_rrdata,
            serialise_tsig
        ]}
    ].

type_rec(_) ->
    Cases = data_samples:rrdata_wire(),
    Types = sets:to_list(sets:from_list([T || {_, T, _} <- Cases, T =/= 999])),
    [
        ?assertEqual(Type, dns_record_info:type_for_atom(dns_record_info:atom_for_type(Type)))
     || Type <- Types
    ].

recinfo(_) ->
    Cases = data_samples:rrdata_wire(),
    Types = sets:to_list(sets:from_list([T || {_, T, _} <- Cases, T =/= 999])),
    Tags = [dns_rr | [dns_record_info:atom_for_type(Type) || Type <- Types]],
    [
        {
            atom_to_list(Tag),
            ?assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            )
        }
     || Tag <- Tags
    ].

recinfo_new_types(_) ->
    %% Test new record types that may not be in wire samples
    NewTypes = [
        ?DNS_TYPE_OPENPGPKEY,
        ?DNS_TYPE_SMIMEA,
        ?DNS_TYPE_WALLET,
        ?DNS_TYPE_EUI48,
        ?DNS_TYPE_EUI64,
        ?DNS_TYPE_SVCB,
        ?DNS_TYPE_HTTPS
    ],
    [
        begin
            Tag = dns_record_info:atom_for_type(Type),
            ?assertNotEqual(undefined, Tag),
            ?assertNotEqual(undefined, dns_record_info:type_for_atom(Tag)),
            ?assertEqual(Type, dns_record_info:type_for_atom(Tag)),
            ?assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            ),
            ?assert(is_list(dns_record_info:fields(Tag))),
            ?assert(length(dns_record_info:fields(Tag)) > 0)
        end
     || Type <- NewTypes
    ].

recinfo_missing_coverage(_) ->
    %% Test types that are not covered by existing tests
    %% Based on code coverage report
    %% Test DNS record types not in wire samples
    %% Note: MD and MF are obsolete types without record definitions,
    %% so we only test atom_for_type/type_for_atom for them
    MissingTypesWithRecords = [
        ?DNS_TYPE_CAA,
        ?DNS_TYPE_MB,
        ?DNS_TYPE_MG,
        ?DNS_TYPE_MINFO,
        ?DNS_TYPE_MR,
        ?DNS_TYPE_ZONEMD,
        ?DNS_TYPE_TSIG
    ],
    [
        begin
            Tag = dns_record_info:atom_for_type(Type),
            ?assertNotEqual(undefined, Tag),
            ?assertNotEqual(undefined, dns_record_info:type_for_atom(Tag)),
            ?assertEqual(Type, dns_record_info:type_for_atom(Tag)),
            ?assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            ),
            ?assert(is_list(dns_record_info:fields(Tag))),
            ?assert(length(dns_record_info:fields(Tag)) > 0)
        end
     || Type <- MissingTypesWithRecords
    ],
    %% Test obsolete types MD and MF (no record definitions, only type mappings)
    ObsoleteTypes = [?DNS_TYPE_MD, ?DNS_TYPE_MF],
    [
        begin
            Tag = dns_record_info:atom_for_type(Type),
            ?assertNotEqual(undefined, Tag),
            ?assertNotEqual(undefined, dns_record_info:type_for_atom(Tag)),
            ?assertEqual(Type, dns_record_info:type_for_atom(Tag))
        end
     || Type <- ObsoleteTypes
    ],
    %% Test dns_message and dns_query
    [
        begin
            ?assert(is_list(dns_record_info:fields(Tag))),
            ?assert(length(dns_record_info:fields(Tag)) > 0),
            ?assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            )
        end
     || Tag <- [dns_message, dns_query]
    ],
    %% Test OPT record types
    OptTags = [
        dns_optrr,
        dns_opt_llq,
        dns_opt_nsid,
        dns_opt_owner,
        dns_opt_ul,
        dns_opt_ecs,
        dns_opt_unknown
    ],
    [
        begin
            ?assert(is_list(dns_record_info:fields(Tag))),
            ?assert(length(dns_record_info:fields(Tag)) > 0),
            ?assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            )
        end
     || Tag <- OptTags
    ],
    %% Test atom_for_type with undefined case
    ?assertEqual(undefined, dns_record_info:atom_for_type(99999)),
    %% Test type_for_atom with undefined case
    ?assertEqual(undefined, dns_record_info:type_for_atom(nonexistent_atom)).

serialise_dnssec(_) -> erl_tests(dnssec_cases()).

serialise_optrr(_) -> erl_tests(optrr_cases()).

serialise_rrdata(_) -> erl_tests(rrdata_cases()).

serialise_tsig(_) -> erl_tests(tsig_cases()).

dnssec_cases() ->
    Cases = data_samples:dnssec(),
    [
        {ZoneName, dns:decode_message(Bin)}
     || {ZoneName, _RawKeys, Bin} <- Cases
    ].

optrr_cases() ->
    [
        {atom_to_list(element(1, Opt)), #dns_message{additional = [#dns_optrr{data = [Opt]}]}}
     || Opt <- [
            #dns_opt_llq{
                opcode = ?DNS_LLQOPCODE_SETUP,
                errorcode = ?DNS_LLQERRCODE_NOERROR,
                id = dns:random_id(),
                leaselife = 42
            },
            #dns_opt_nsid{data = <<222, 175>>},
            #dns_opt_owner{
                seq = 0,
                primary_mac = <<17, 28, 15, 254, 225, 17>>,
                _ = <<>>
            },
            #dns_opt_ul{lease = 42},
            #dns_opt_unknown{id = 1, bin = <<222, 173, 192, 222>>}
        ]
    ].

rrdata_cases() ->
    Cases = data_samples:rrdata_wire(),
    WireCases = [
        {
            lists:flatten(io_lib:format("~p/~p", [Class, Type])),
            dns_decode:decode_rrdata(Bin, Class, Type)
        }
     || {Class, Type, Bin} <- Cases
    ],
    [
        {"OPENPGPKEY", #dns_rrdata_openpgpkey{
            data = base64:decode(
                <<"mQINBFit2jsBEADrbl5vjVxYeAE0g0IDYCBpHirv1Sjlqxx5gjtPhb2YhvyDMXjq">>
            )
        }},
        {"SMIMEA", #dns_rrdata_smimea{
            usage = 3,
            selector = 1,
            matching_type = 1,
            certificate = base64:decode(<<"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA">>)
        }},
        {"WALLET", #dns_rrdata_wallet{
            data = base64:decode(<<"dGVzdC13YWxsZXQtZGF0YQ==">>)
        }},
        {"EUI48", #dns_rrdata_eui48{
            address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E>>
        }},
        {"EUI64", #dns_rrdata_eui64{
            address = <<16#00, 16#1A, 16#2B, 16#3C, 16#4D, 16#5E, 16#6F, 16#70>>
        }},
        {"SVCB", #dns_rrdata_svcb{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{}
        }},
        {"SVCB with params", #dns_rrdata_svcb{
            svc_priority = 16,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_PORT => 8080}
        }},
        {"HTTPS", #dns_rrdata_https{
            svc_priority = 0,
            target_name = <<"target.example.com">>,
            svc_params = #{}
        }},
        {"HTTPS with params", #dns_rrdata_https{
            svc_priority = 1,
            target_name = <<"target.example.com">>,
            svc_params = #{?DNS_SVCB_PARAM_ALPN => [<<"h2">>, <<"h3">>]}
        }}
        | WireCases
    ].

tsig_cases() ->
    Cases = data_samples:tsig(),
    [{Name, dns:decode_message(Msg)} || {Name, Msg} <- Cases].

tests(Cases, Serialise, Deserialise) ->
    [
        {TestName, ?assertEqual(Term, Deserialise(Serialise(Term)))}
     || {TestName, Term} <- Cases
    ].

erl_tests(Cases) -> tests(Cases, fun dns_record:serialise/1, fun dns_record:deserialise/1).

ejson_serialise(Term) ->
    Fun = fun
        ({K, V}) -> {[{<<"_tag">>, K} | V]};
        (Bin) when is_binary(Bin) -> Bin
    end,
    ejson:encode(dns_record:serialise(Term, #{wrap_fun => Fun})).

ejson_deserialise(Term) ->
    Fun = fun
        ({V}) when is_list(V) ->
            {proplists:get_value(<<"_tag">>, V), V};
        (Term0) ->
            Term0
    end,
    dns_record:deserialise(ejson:decode(Term), #{wrap_fun => Fun}).

json_tests(Cases) ->
    Serialise = fun ejson_serialise/1,
    Deserialise = fun ejson_deserialise/1,
    case code:ensure_loaded(ejson) of
        {module, ejson} -> tests(Cases, Serialise, Deserialise);
        {error, nofile} -> []
    end.

json_dnssec_test_() -> json_tests(dnssec_cases()).

json_optrr_test_() -> json_tests(optrr_cases()).

json_rrdata_test_() -> json_tests(rrdata_cases()).

json_tsig_test_() -> json_tests(tsig_cases()).
