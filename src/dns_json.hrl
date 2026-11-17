%% A JSON null as decoding gives it: the atom null from json:decode/1, or nil from Elixir's
%% JSON.decode/1. No other JSON value decodes to either atom.
-define(IS_JSON_NULL(Value), (Value =:= null orelse Value =:= nil)).
