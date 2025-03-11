-module(dns_record_test).

-include("dns.hrl").
-include_lib("eunit/include/eunit.hrl").

dnssec_cases() ->
    {ok, Cases} = file:consult(filename:join("priv", "dnssec_samples.txt")),
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
    {ok, Cases} = file:consult(filename:join("priv", "rrdata_wire_samples.txt")),
    [
        {lists:flatten(io_lib:format("~p/~p", [Class, Type])), dns:decode_rrdata(Class, Type, Bin)}
     || {Class, Type, Bin} <- Cases
    ].

tsig_cases() ->
    {ok, Cases} = file:consult(filename:join("priv", "tsig_wire_samples.txt")),
    [{Name, dns:decode_message(Msg)} || {Name, Msg} <- Cases].

tests(Cases, Serialise, Deserialise) ->
    [
        {TestName, ?_assertEqual(Term, Deserialise(Serialise(Term)))}
     || {TestName, Term} <- Cases
    ].

erl_tests(Cases) -> tests(Cases, fun dns_record:serialise/1, fun dns_record:deserialise/1).

serialise_dnssec_test_() -> erl_tests(dnssec_cases()).

serialise_optrr_test_() -> erl_tests(optrr_cases()).

serialise_rrdata_test_() -> erl_tests(rrdata_cases()).

serialise_tsig_test_() -> erl_tests(tsig_cases()).

ejson_serialise(Term) ->
    Fun = fun
        ({K, V}) -> {[{<<"_tag">>, K} | V]};
        (Bin) when is_binary(Bin) -> Bin
    end,
    ejson:encode(dns_record:serialise(Term, [{wrap_fun, Fun}])).

ejson_deserialise(Term) ->
    Fun = fun
        ({V}) when is_list(V) ->
            {proplists:get_value(<<"_tag">>, V), V};
        (Term0) ->
            Term0
    end,
    dns_record:deserialise(ejson:decode(Term), [{wrap_fun, Fun}]).

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
