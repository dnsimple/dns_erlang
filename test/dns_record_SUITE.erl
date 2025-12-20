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
