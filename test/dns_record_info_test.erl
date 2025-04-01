-module(dns_record_info_test).

-include_lib("eunit/include/eunit.hrl").

type_rec_test_() ->
    {ok, Cases} = file:consult(filename:join("test", "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([T || {_, T, _} <- Cases, T =/= 999])),
    [
        ?_assertEqual(Type, dns_record_info:type_for_atom(dns_record_info:atom_for_type(Type)))
     || Type <- Types
    ].

recinfo_test_() ->
    {ok, Cases} = file:consult(filename:join("test", "rrdata_wire_samples.txt")),
    Types = sets:to_list(sets:from_list([T || {_, T, _} <- Cases, T =/= 999])),
    Tags = [dns_rr | [dns_record_info:atom_for_type(Type) || Type <- Types]],
    [
        {
            atom_to_list(Tag),
            ?_assertEqual(
                length(dns_record_info:fields(Tag)),
                dns_record_info:size(Tag) - 1
            )
        }
     || Tag <- Tags
    ].
