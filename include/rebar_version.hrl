-ifndef('REBAR_VERSION').
-define(REBAR_VERSION, "3").
-endif.

rebar_version() ->
    case string:sub_string(?REBAR_VERSION, 1, 1) of
        "3" ->
            3;
        "2" ->
            2
    end.


prefix() ->
    case rebar_version() of
        2 ->
            "../priv/";
        3 ->
            "priv"
    end.
