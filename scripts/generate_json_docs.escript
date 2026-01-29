#!/usr/bin/env escript
%% -*- erlang -*-
%% Generate JSON format documentation from record definitions and encoding rules.
%%
%% This script parses:
%% - include/dns_records.hrl: Record definitions with field types
%% - src/dns_json.erl: Encoding rules from to_map_value/3 clauses
%%
%% Usage:
%%     escript scripts/generate_json_docs.escript
%%     escript scripts/generate_json_docs.escript --output docs/JSON_FORMAT.md

% -mode(compile).

%% ============================================================================
%% Type definitions
%% ============================================================================

-type record_name() :: atom().
-type field_name() :: atom().
-type rfc_number() :: pos_integer().
% ExDoc-formatted type string
-type ex_doc_type_string() :: binary().
-type encoding() :: base64 | base16 | base32 | ip_string | binary | direct.

-type field() :: {field_name(), ex_doc_type_string()}.
-type record_info() :: {record_name(), [field()], rfc_number() | undefined}.
-type encoding_rule_key() :: {record_name(), field_name() | any}.
-type encoding_rules() :: #{encoding_rule_key() => encoding()}.
-type key_mappings() :: #{record_name() => binary()}.
-type rfc_map() :: #{record_name() => rfc_number()}.

%% ============================================================================
%% Main entry point
%% ============================================================================

-spec main([string()]) -> ok.
main(Args) ->
    RootDir = get_root_dir(),
    Opts = parse_args(Args, []),
    RecordsIncludeFile = filename:join([RootDir, "include", "dns_records.hrl"]),
    DnsJsonSourceCode = filename:join([RootDir, "src", "dns_json.erl"]),
    Records = parse_records(RecordsIncludeFile, RootDir),
    EncodingRules = parse_encoding_rules(DnsJsonSourceCode, RootDir),
    KeyMappings = extract_key_mappings(DnsJsonSourceCode, RootDir),
    Markdown = generate_documentation(Records, EncodingRules, KeyMappings),
    case proplists:get_value(output, Opts, undefined) of
        undefined ->
            io:format("~s", [Markdown]);
        File ->
            ok = file:write_file(File, Markdown, [raw]),
            io:format(standard_io, "Generated JSON documentation: ~s~n", [File])
    end.

-spec parse_args([string()], [{atom(), string()}]) -> [{atom(), string()}].
parse_args([], Acc) ->
    lists:reverse(Acc);
parse_args(["--output", File | Rest], Acc) ->
    parse_args(Rest, [{output, File} | Acc]);
parse_args([Unknown | Rest], Acc) ->
    io:format(standard_error, "Warning: Unknown option ~s~n", [Unknown]),
    parse_args(Rest, Acc).

-spec get_root_dir() -> file:filename().
get_root_dir() ->
    ScriptPath = escript:script_name(),
    ScriptDir = filename:dirname(filename:absname(ScriptPath)),
    filename:dirname(ScriptDir).

%% ============================================================================
%% Parse record definitions from .hrl file using proper Erlang parsing
%% ============================================================================

-spec parse_records(file:filename(), file:filename()) -> [record_info()].
parse_records(File, RootDir) ->
    IncludePath = filename:join([RootDir, "include"]),
    {ok, FileContent} = file:read_file(File),
    RFCMap = extract_rfc_map_from_file(FileContent),
    {ok, Forms} = epp:parse_file(File, [RootDir, IncludePath], []),
    extract_records_from_forms(Forms, [], RFCMap).

-spec extract_rfc_map_from_file(binary()) -> rfc_map().
extract_rfc_map_from_file(Content) ->
    %% Match comment lines with RFC numbers before record definitions
    %% Pattern: %% ... See RFC NNNN ... \n -record(record_name, ...
    Pattern = ~B"%%[^\n]*RFC\s+(\d+)[^\n]*\n-record\(([a-z_0-9]+),",
    case re:run(Content, Pattern, [global, {capture, [1, 2], list}, multiline]) of
        {match, Matches} ->
            #{
                list_to_atom(RecordName) => list_to_integer(RFCNum)
             || [RFCNum, RecordName] <- Matches
            };
        nomatch ->
            #{}
    end.

-spec extract_records_from_forms([erl_parse:abstract_form()], [record_info()], rfc_map()) ->
    [record_info()].
extract_records_from_forms(
    [{attribute, _, record, {RecordName, FieldsTuples}} | Rest], Acc, RFCMap
) ->
    Fields = extract_record_fields_abstract(FieldsTuples, []),
    RFC = maps:get(RecordName, RFCMap, undefined),
    extract_records_from_forms(Rest, [{RecordName, Fields, RFC} | Acc], RFCMap);
extract_records_from_forms([_Form | Rest], Acc, RFCMap) ->
    extract_records_from_forms(Rest, Acc, RFCMap);
extract_records_from_forms([], Acc, _RFCMap) ->
    Acc.

-spec extract_record_fields_abstract([erl_parse:abstract_form()], [field()]) -> [field()].
extract_record_fields_abstract([{typed_record_field, FieldData, TypeData} | Rest], Acc) ->
    FieldName = extract_record_field_name(FieldData),
    %% TypeData is the type abstract form - could be union, remote_type, type, etc.
    TypeStr = extract_record_field_type_string(TypeData),
    extract_record_fields_abstract(Rest, [{FieldName, TypeStr} | Acc]);
extract_record_fields_abstract([], Acc) ->
    lists:reverse(Acc).

-spec extract_record_field_name(tuple()) -> field_name().
extract_record_field_name({record_field, _, {atom, _, Field}, _}) ->
    Field;
extract_record_field_name({record_field, _, {atom, _, Field}}) ->
    Field;
extract_record_field_name({atom, _, Field}) ->
    Field.

-spec extract_record_field_type_string(erl_parse:abstract_form()) -> ex_doc_type_string().
extract_record_field_type_string(TypeData) ->
    %% Convert type abstract form to ExDoc-formatted string representation
    %% For union types, preserve all non-undefined types since they're relevant for:
    %% 1. Type display in documentation - shows all possible types
    %% 2. Encoding inference - searches for keywords like "binary", "dname", "ip_address" in the
    %%    full type string
    %% 3. Understanding optional fields - undefined | binary() means optional binary
    %%
    %% Handle union types directly from the abstract form for better accuracy
    RawTypeStr =
        case TypeData of
            {type, _Line, union, UnionTypes} ->
                %% Extract string representation for each union member
                TypeStrs = [
                    erl_prettypr:format(erl_syntax:revert(UT))
                 || UT <- UnionTypes
                ],
                %% Filter out undefined and atom, normalize whitespace
                NonUndefinedStrs = lists:filtermap(
                    fun filter_undefined_type/1,
                    TypeStrs
                ),
                case NonUndefinedStrs of
                    [] ->
                        %% All parts were undefined/atom, use first
                        [First | _] = TypeStrs,
                        normalize_type_string(First);
                    [Single] ->
                        Single;
                    Multiple ->
                        %% Multiple non-undefined types - join them with |
                        lists:join(~" | ", Multiple)
                end;
            _ ->
                %% Single type (not a union) - format normally
                TypeStr = erl_prettypr:format(erl_syntax:revert(TypeData)),
                normalize_type_string(TypeStr)
        end,
    %% Format with ExDoc links - this formatted string is used for all purposes:
    %% - Display (already formatted)
    %% - Encoding inference (keywords still searchable in formatted string)
    %% - Encoding description (keywords still searchable in formatted string)
    type_description(RawTypeStr).

-spec filter_undefined_type(string()) -> {true, string()} | false.
filter_undefined_type(TypeStr0) ->
    TypeStr1 = re:replace(TypeStr0, ~B"\s+", ~" ", [global, {return, list}]),
    Trimmed = string:trim(TypeStr1),
    case Trimmed of
        "undefined" -> false;
        "atom" -> false;
        _ -> {true, Trimmed}
    end.

-spec normalize_type_string(string()) -> string().
normalize_type_string(TypeStr) ->
    TypeStr1 = re:replace(TypeStr, ~B"\s+", ~" ", [global, {return, list}]),
    string:trim(TypeStr1).

-spec type_description(string() | binary()) -> ex_doc_type_string().
type_description(TypeStr) ->
    %% Convert type string to ExDoc format with type links
    %% Examples:
    %%   "inet:ip4_address()" -> "`t:inet:ip4_address/0`"
    %%   "dns:dname() | inet:ip_address()" -> "`t:dns:dname/0` | `t:inet:ip_address/0`"
    %%   "binary()" -> "`t:binary/0`"
    %%   "undefined | binary()" -> "undefined | `t:binary/0`"
    %% Always split by | - for single types this returns a list with one element
    TypeStr1 = string:trim(TypeStr),
    Parts = string:split(TypeStr1, ~"|", all),
    FormattedParts = [format_type_with_exdoc_link(string:trim(Part)) || Part <- Parts],
    iolist_to_binary(lists:join(~" | ", FormattedParts)).

-spec format_type_with_exdoc_link(string() | binary()) -> ex_doc_type_string().
format_type_with_exdoc_link(TypeStr) ->
    %% Match patterns like:
    %%   "module:type()" -> "`t:module:type/0`"
    %%   "type()" -> "`t:type/0`"
    %%   "[module:type()]" -> "[`t:module:type/0`]"
    %%   "[type()]" -> "[`t:type/0`]"
    %%   "undefined" -> "undefined" (no link)
    %%   "<<_:64>>" -> "<<_:64>>" (binary pattern, no link)
    case re:run(TypeStr, ~B"^\[([^\]]+)\]$", [{capture, [1], list}]) of
        {match, [InnerType]} ->
            %% List type: [type()] - recursively format inner type
            InnerFormatted = format_type_with_exdoc_link(InnerType),
            <<"[", InnerFormatted/binary, "]">>;
        nomatch ->
            format_single_type(TypeStr)
    end.

-spec format_single_type(string() | binary()) -> ex_doc_type_string().
format_single_type(TypeStr) ->
    %% Try remote type first: module:type()
    Regex = ~B"^([a-z_][a-z_0-9]*):([a-z_][a-z_0-9]*)\(\)$",
    case re:run(TypeStr, Regex, [{capture, [1, 2], binary}]) of
        {match, [Module, Type]} ->
            <<"`t:", Module/binary, ":", Type/binary, "/0`">>;
        nomatch ->
            %% Try local type: type()
            case re:run(TypeStr, ~B"^([a-z_][a-z_0-9]*)\(\)$", [{capture, [1], binary}]) of
                {match, [Type]} ->
                    <<"`t:", Type/binary, "/0`">>;
                nomatch ->
                    %% Not a type reference (undefined, binary pattern, etc.)
                    TypeStrBin = iolist_to_binary(TypeStr),
                    <<"`", TypeStrBin/binary, "`">>
            end
    end.

%% ============================================================================
%% Parse encoding rules from dns_json.erl using proper Erlang parsing
%% ============================================================================

-spec parse_encoding_rules(file:filename(), file:filename()) -> encoding_rules().
parse_encoding_rules(File, RootDir) ->
    IncludePath = filename:join([RootDir, "include"]),
    {ok, Forms} = epp:parse_file(File, [RootDir, IncludePath], []),
    Clauses = lists:flatten(lists:filtermap(fun find_encoding_rules/1, Forms)),
    lists:foldl(fun extract_encoding_from_clause_abstract/2, #{}, Clauses).

-spec find_encoding_rules(erl_parse:abstract_form()) -> {true, [erl_parse:abstract_form()]} | false.
find_encoding_rules({function, _Line, to_map_value, 3, Clauses}) ->
    {true, Clauses};
find_encoding_rules(_) ->
    false.

-spec extract_encoding_from_clause_abstract(erl_parse:abstract_clause(), encoding_rules()) ->
    encoding_rules().
extract_encoding_from_clause_abstract(
    {clause, _Line, [RecordPattern, FieldPattern, _ValuePattern], Guards, Body}, Acc
) ->
    RecordNames = extract_atom_from_pattern_abstract(RecordPattern, Guards),
    FieldName = extract_field_from_pattern_abstract(FieldPattern),
    Encoding = extract_encoding_from_body_abstract(Body),
    FieldKey =
        case FieldName of
            '_Field' -> any;
            '_Tag' -> any;
            _ -> FieldName
        end,
    %% If RecordNames is a list (from guards), add entries for each record
    %% Otherwise it's a single atom
    case RecordNames of
        [H | _] when is_atom(H) ->
            %% Multiple records from guards
            lists:foldl(
                fun(RecordName, AccAcc) ->
                    maps:put({RecordName, FieldKey}, Encoding, AccAcc)
                end,
                Acc,
                RecordNames
            );
        Atom when is_atom(Atom) ->
            %% Single record
            maps:put({Atom, FieldKey}, Encoding, Acc);
        _ ->
            Acc
    end.

-spec extract_atom_from_pattern_abstract(tuple(), [erl_parse:abstract_form()]) -> atom() | [atom()].
extract_atom_from_pattern_abstract({atom, _Line, Atom}, _Guards) ->
    Atom;
extract_atom_from_pattern_abstract({var, _Line, _VarName}, Guards) ->
    %% Variable pattern - extract record names from guards
    RecordNames = extract_record_names_from_guards(Guards),
    case RecordNames of
        [] -> undefined;
        _ -> RecordNames
    end.

-spec extract_record_names_from_guards([erl_parse:abstract_form()]) -> [atom()].
extract_record_names_from_guards(Guards) ->
    %% Guards is a list of guard expressions (each guard is a list of test expressions)
    %% Extract all atoms from equality comparisons in guards
    %% Example: (Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa)
    %% Returns a list of record names found in guards
    lists:flatten([
        extract_atoms_from_guard_expr(GuardExpr)
     || GuardList <- Guards, GuardExpr <- GuardList
    ]).

-spec extract_atoms_from_guard_expr(erl_parse:abstract_form()) -> [atom()].
extract_atoms_from_guard_expr({op, _Line, 'orelse', Left, Right}) ->
    %% Handle: Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa
    extract_atoms_from_guard_expr(Left) ++ extract_atoms_from_guard_expr(Right);
extract_atoms_from_guard_expr({op, _Line, 'andalso', Left, Right}) ->
    %% Handle: (Tag =:= dns_rrdata_a orelse ...) andalso is_tuple(Value)
    extract_atoms_from_guard_expr(Left) ++ extract_atoms_from_guard_expr(Right);
extract_atoms_from_guard_expr({op, _Line, '=:=', {var, _Line2, _VarName}, {atom, _Line3, Atom}}) ->
    %% Handle: Tag =:= dns_rrdata_a
    [Atom];
extract_atoms_from_guard_expr({op, _Line, '=:=', {atom, _Line2, Atom}, {var, _Line3, _VarName}}) ->
    %% Handle: dns_rrdata_a =:= Tag (reversed order)
    [Atom];
extract_atoms_from_guard_expr(_) ->
    [].

-spec extract_field_from_pattern_abstract(tuple()) -> field_name().
extract_field_from_pattern_abstract({atom, _Line, Atom}) ->
    Atom;
extract_field_from_pattern_abstract({var, _Line, VarName}) ->
    VarName.

-spec extract_encoding_from_body_abstract([erl_parse:abstract_form()]) -> encoding().
extract_encoding_from_body_abstract([Expr | _]) ->
    ExprStr = erl_prettypr:format(erl_syntax:revert(Expr)),
    normalize_encoding(ExprStr);
extract_encoding_from_body_abstract([]) ->
    direct.

-spec normalize_encoding(string()) -> encoding().
normalize_encoding(Expr) ->
    Expr1 = string:trim(Expr),
    HasBase64 = nomatch =/= re:run(Expr1, ~"base64:encode", [{capture, first}]),
    HasBase32 = nomatch =/= re:run(Expr1, ~"base32:encode", [{capture, first}]),
    HasHex = nomatch =/= re:run(Expr1, ~"binary:encode_hex", [{capture, first}]),
    HasNtoa = nomatch =/= re:run(Expr1, ~"inet:ntoa", [{capture, first}]),
    HasListToBin = nomatch =/= re:run(Expr1, ~"list_to_binary", [{capture, first}]),
    if
        HasBase64 -> base64;
        HasBase32 -> base32;
        HasHex -> base16;
        HasNtoa -> ip_string;
        HasListToBin -> binary;
        true -> direct
    end.

%% ============================================================================
%% Extract JSON key mappings from record_key_name/1 function
%% ============================================================================

extract_key_mappings(File, _RootDir) ->
    %% Read file and extract using regex since epp parsing seems to stop before record_key_name
    {ok, Content} = file:read_file(File),
    extract_key_mappings_regex(Content, #{}).

-spec extract_key_mappings_regex(binary(), key_mappings()) -> key_mappings().
extract_key_mappings_regex(Content, Acc) ->
    %% Match: record_key_name(dns_xxx) -> ~"key"; or record_key_name(dns_xxx) -> ?DNS_TYPE_XXX_BSTR;
    %% Pattern matches both binary literals and macros
    %% Note: record names can contain digits (e.g., dns_rrdata_eui48)
    Pattern = ~B"record_key_name\s*\(\s*([a-z_0-9]+)\s*\)\s*->\s*([^;]+);",
    case re:run(Content, Pattern, [global, {capture, [1, 2], list}, multiline]) of
        {match, Matches} ->
            lists:foldl(
                fun([RecordName, KeyExpr], AccAcc) ->
                    Key = extract_binary_key_regex(KeyExpr),
                    maps:put(list_to_atom(RecordName), Key, AccAcc)
                end,
                Acc,
                Matches
            );
        nomatch ->
            Acc
    end.

-spec extract_binary_key_regex(string()) -> binary().
extract_binary_key_regex(Expr) ->
    %% Expr is a list (from regex capture), normalize whitespace
    Expr1 = string:trim(Expr),
    %% Try binary literal first: ~"key"
    case re:run(Expr1, ~"\"([^\"]+)\"", [{capture, [1], list}]) of
        {match, [Key]} ->
            list_to_binary(Key);
        nomatch ->
            %% Try macro: ?DNS_TYPE_XXX_BSTR (XXX can contain letters, underscores, and digits)
            %% Use character class [?] to match literal ? character
            case re:run(Expr1, "[?]DNS_TYPE_([A-Z_0-9]+)_BSTR", [{capture, [1], list}]) of
                {match, [TypeName]} ->
                    list_to_binary(TypeName);
                nomatch ->
                    ~"unknown"
            end
    end.

%% ============================================================================
%% Generate markdown documentation
%% ============================================================================

-spec generate_documentation([record_info()], encoding_rules(), key_mappings()) -> binary().
generate_documentation(Records, EncodingRules, KeyMappings) ->
    InitAcc =
        ~"""
        This document describes the JSON encoding format for all DNS record types.

        ## Format Structure

        ### Resource Records (RR)

        Resource records (`dns_rr`) are encoded as follows:
        ```json
        {
          "name": "example.com",
          "type": "A",
          "class": "in",
          "ttl": 3600,
          "data": {
            "ip": "192.168.1.1"
          }
        }
        ```

        The format includes:
        - `name`: Domain name (binary)
        - `type`: DNS type name as uppercase string (e.g., "A", "AAAA", "MX")
        - `ttl`: Time to live (integer)
        - `data`: Map containing the record-specific fields
        - `class`: Optional, only included if not IN (default)

        ### Other Records

        Non-RR records (message, query, OPT records) use a two-level nested map format:
        - Outer key: Record type identifier (descriptive name)
        - Inner map: Record fields with binary keys

        ## Field Encoding Rules

        - **IP addresses**: String format (`"192.168.1.1"`, `"2001:db8::1"`)
        - **Base64**: Certificates, keys, signatures, MACs
        - **Base16 (hex)**: Digests, hashes, fingerprints, addresses
        - **Base32**: NSEC3 hash
        - **Domain names**: Binary (dname format)
        - **Lists**: Arrays of converted values

        ## Record Types


        """,

    OrderedRecords = lists:sort(fun record_order/2, Records),
    RecordsAcc = lists:foldl(
        fun(Record, Acc) ->
            generate_record_doc(Record, Acc, EncodingRules, KeyMappings)
        end,
        InitAcc,
        OrderedRecords
    ),
    <<RecordsAcc/binary, (generate_svcb_params_section())/binary>>.

%% Sort records with custom order: message, query, RRs (alphabetically), OPTs (alphabetically)
-spec record_order(record_info(), record_info()) -> boolean().
record_order({dns_message, _, _}, _) ->
    true;
record_order(_, {dns_message, _, _}) ->
    false;
record_order({dns_query, _, _}, _) ->
    true;
record_order(_, {dns_query, _, _}) ->
    false;
record_order({NameA, _, _}, {NameB, _, _}) ->
    AIsRrData = is_rrdata_record(NameA),
    BIsRrData = is_rrdata_record(NameB),
    case {AIsRrData, BIsRrData} of
        {Same, Same} -> NameA < NameB;
        {true, false} -> true;
        {false, true} -> false
    end.

-spec is_rrdata_record(record_name()) -> boolean().
is_rrdata_record(RecordName) when is_atom(RecordName) ->
    string:prefix(atom_to_list(RecordName), "dns_rrdata_") =/= nomatch.

-spec generate_record_doc(record_info(), binary(), encoding_rules(), key_mappings()) -> binary().
generate_record_doc({dns_rr, Fields, RFC}, Acc0, EncodingRules, _KeyMappings) ->
    RecordNameBin = atom_to_binary(dns_rr),
    DisplayName = display_name(RecordNameBin),
    RFCLink = maybe_rfc_link(RFC),
    Acc1 = <<
        Acc0/binary,
        "### ",
        (string:uppercase(DisplayName))/binary,
        " (",
        RecordNameBin/binary,
        ")",
        RFCLink/binary,
        "\n\n"
    >>,
    Acc2 = generate_fields_doc(dns_rr, Fields, EncodingRules, Acc1),
    generate_example_rr_format(Fields, Acc2);
generate_record_doc({RecordName, Fields, RFC}, Acc0, EncodingRules, KeyMappings) ->
    RecordNameBin = atom_to_binary(RecordName),
    DisplayName = display_name(RecordNameBin),
    RFCLink = maybe_rfc_link(RFC),
    case is_rrdata_record(RecordName) of
        true ->
            %% RRDATA records: show fields directly (no type key wrapper)
            Acc1 = <<
                Acc0/binary,
                "### ",
                (string:uppercase(DisplayName))/binary,
                " (",
                RecordNameBin/binary,
                ")",
                RFCLink/binary,
                "\n\n",
                "**Format:** RRDATA fields (used within `dns_rr.data`)\n\n"
            >>,
            Acc2 = generate_fields_doc(RecordName, Fields, EncodingRules, Acc1),
            generate_example_rrdata_format(RecordName, Fields, Acc2, EncodingRules);
        false ->
            %% Non-RRDATA records: use old nested format
            Key = maps:get(RecordName, KeyMappings, ~"UNKNOWN"),
            Acc1 = <<
                Acc0/binary,
                "### ",
                (string:uppercase(DisplayName))/binary,
                " (",
                RecordNameBin/binary,
                ")",
                RFCLink/binary,
                "\n\n",
                "**JSON Key:** `",
                Key/binary,
                "`\n\n"
            >>,
            Acc2 = generate_fields_doc(RecordName, Fields, EncodingRules, Acc1),
            generate_example(RecordName, Fields, Key, Acc2, EncodingRules)
    end.

-spec display_name(binary()) -> binary().
display_name(RecordNameBin) ->
    case string:prefix(RecordNameBin, ~"dns_opt_") of
        nomatch ->
            case string:prefix(RecordNameBin, ~"dns_rrdata_") of
                nomatch ->
                    case string:prefix(RecordNameBin, ~"dns_") of
                        nomatch -> RecordNameBin;
                        Match -> Match
                    end;
                Match ->
                    Match
            end;
        Match ->
            <<"OPT", Match/binary>>
    end.

-spec maybe_rfc_link(undefined | rfc_number()) -> binary().
maybe_rfc_link(undefined) ->
    <<>>;
maybe_rfc_link(RFCNum) when is_integer(RFCNum) ->
    RFCBin = integer_to_binary(RFCNum),
    <<" [RFC", RFCBin/binary, "](https://datatracker.ietf.org/doc/html/rfc", RFCBin/binary, ")">>.

-spec generate_fields_doc(record_name(), [field()], encoding_rules(), binary()) -> binary().
generate_fields_doc(dns_rr, Fields, EncodingRules, Acc) ->
    FieldsList = lists:foldl(
        fun({FieldName, TypeStr}, InnerAcc) ->
            FieldBin =
                case FieldName of
                    data -> <<"data">>;
                    _ -> atom_to_binary(FieldName, utf8)
                end,
            %% TypeStr is already formatted with ExDoc links from extract_record_field_type_string
            FieldDesc =
                case FieldName of
                    type ->
                        ~"DNS type name as uppercase binary string (e.g., \"A\", \"AAAA\", \"MX\")";
                    class ->
                        ~"DNS class name as uppercase binary string (e.g., \"IN\", \"CH\", \"HS\") - optional, defaults to \"IN\" if omitted";
                    name ->
                        ~"Domain name (binary, dname format)";
                    ttl ->
                        ~"Time to live (integer)";
                    data ->
                        ~"Map containing the RRDATA-specific fields (see individual RRDATA record types below)";
                    _ ->
                        Encoding = determine_encoding(dns_rr, FieldName, TypeStr, EncodingRules),
                        encoding_description(Encoding, FieldName, TypeStr)
                end,
            <<InnerAcc/binary, "- `", FieldBin/binary, "` (", TypeStr/binary, "): ",
                FieldDesc/binary, "\n">>
        end,
        <<Acc/binary, "**Fields:**\n\n">>,
        Fields
    ),
    FieldsList;
generate_fields_doc(RecordName, Fields, EncodingRules, Acc) ->
    FieldsList = lists:foldl(
        fun({FieldName, TypeStr}, InnerAcc) ->
            Encoding = determine_encoding(RecordName, FieldName, TypeStr, EncodingRules),
            EncodingDesc = encoding_description(Encoding, FieldName, TypeStr),
            FieldBin = atom_to_binary(FieldName),
            %% TypeStr is already formatted with ExDoc links from extract_record_field_type_string
            <<InnerAcc/binary, "- `", FieldBin/binary, "` (", TypeStr/binary, "): ",
                EncodingDesc/binary, "\n">>
        end,
        <<Acc/binary, "**Fields:**\n\n">>,
        Fields
    ),
    FieldsList.

-spec determine_encoding(record_name(), field_name(), ex_doc_type_string(), encoding_rules()) ->
    encoding().
determine_encoding(RecordName, FieldName, TypeStr, EncodingRules) ->
    case maps:get({RecordName, FieldName}, EncodingRules, undefined) of
        undefined ->
            case maps:get({RecordName, any}, EncodingRules, undefined) of
                undefined -> infer_encoding(TypeStr);
                Encoding -> Encoding
            end;
        Encoding ->
            Encoding
    end.

-spec infer_encoding(ex_doc_type_string()) -> encoding().
infer_encoding(TypeStr) ->
    TypeStrLower = string:lowercase(TypeStr),
    HasIp4 = nomatch =/= string:find(TypeStrLower, ~"ip4_address"),
    HasIp6 = nomatch =/= string:find(TypeStrLower, ~"ip6_address"),
    HasIp = nomatch =/= string:find(TypeStrLower, ~"ip_address"),
    if
        HasIp4 orelse HasIp6 orelse HasIp -> ip_string;
        true -> direct
    end.

-spec encoding_description(encoding(), field_name(), ex_doc_type_string()) -> binary().
encoding_description(base64, FieldName, _TypeStr) ->
    Suffix = encoding_suffix(base64, FieldName),
    <<"Base64-encoded", Suffix/binary>>;
encoding_description(base16, FieldName, _TypeStr) ->
    Suffix = encoding_suffix(base16, FieldName),
    <<"Base16 (hex)-encoded", Suffix/binary>>;
encoding_description(base32, _FieldName, _TypeStr) ->
    ~"Base32-encoded binary (NSEC3 hash)";
encoding_description(ip_string, _FieldName, _TypeStr) ->
    ~"IP address as string";
encoding_description(binary, _FieldName, _TypeStr) ->
    ~"Binary data";
encoding_description(direct, FieldName, TypeStr) ->
    TypeStrLower = string:lowercase(TypeStr),
    HasDname = nomatch =/= string:find(TypeStrLower, "dname"),
    HasBinary = nomatch =/= string:find(TypeStrLower, "binary"),
    HasSvcbParams = nomatch =/= string:find(TypeStrLower, "svcb_svc_params"),
    case FieldName of
        ip ->
            ~"IP address as string";
        svc_params when HasSvcbParams ->
            ~"Map of SVCB service parameters (see [SVCB Service Parameters below](#module-svcb-service-parameters))";
        _ when HasDname orelse HasBinary -> ~"Binary data (dname format)";
        _ ->
            ~"Direct value"
    end;
encoding_description(Other, _FieldName, _TypeStr) ->
    <<"Encoding: ", (atom_to_binary(Other))/binary>>.

-spec encoding_suffix(encoding(), field_name()) -> binary().
encoding_suffix(base64, cert) -> ~" certificate";
encoding_suffix(base64, public_key) -> ~" public key";
encoding_suffix(base64, signature) -> ~" signature";
encoding_suffix(base64, mac) -> ~" MAC";
encoding_suffix(base64, data) -> ~" data";
encoding_suffix(base64, certificate) -> ~" certificate";
encoding_suffix(base64, _) -> ~" binary";
encoding_suffix(base16, digest) -> ~" digest";
encoding_suffix(base16, hash) -> ~" hash";
encoding_suffix(base16, fp) -> ~" fingerprint";
encoding_suffix(base16, address) -> ~" address";
encoding_suffix(base16, salt) -> ~" salt (or \"-\" for empty)";
encoding_suffix(base16, other) -> ~" data";
encoding_suffix(base16, data) -> ~" data";
encoding_suffix(base16, _) -> ~" binary".

-spec generate_example(record_name(), [field()], binary(), binary(), encoding_rules()) -> binary().
generate_example(RecordName, Fields, KeyBin, Acc, EncodingRules) ->
    ExampleFieldsStr = format_example_fields(
        Fields, fun atom_to_binary/1, RecordName, EncodingRules
    ),
    <<
        Acc/binary,
        "**Example:**\n\n",
        "```json\n",
        "{\n",
        "  \"",
        KeyBin/binary,
        "\": {\n",
        ExampleFieldsStr/binary,
        "\n",
        "  }\n",
        "}\n",
        "```\n\n"
    >>.

-spec generate_example_rr_format([field()], binary()) -> binary().
generate_example_rr_format(_Fields, Acc) ->
    %% Generate example in RR format: {name, type, class, ttl, data}
    %% For dns_rr, the data field contains an RRDATA record
    %% We'll show a simple example with an A record
    %% The data field will contain the RRDATA fields
    %% Since we don't know which RRDATA type, we'll use a generic example
    %% showing the structure with common fields
    <<
        Acc/binary,
        "**Example:**\n\n",
        "```json\n",
        "{\n",
        "  \"name\": \"example.com\",\n",
        "  \"type\": \"A\",\n",
        "  \"class\": \"IN\",\n",
        "  \"ttl\": 3600,\n",
        "  \"data\": {\n",
        "    \"ip\": \"192.168.1.1\"\n",
        "  }\n",
        "}\n",
        "```\n\n",
        "**Note:** The `data` field contains the RRDATA-specific fields. ",
        "The `class` field is optional and defaults to `\"IN\"` if omitted. ",
        "See individual RRDATA record types below for complete field documentation.\n\n"
    >>.

-spec generate_example_rrdata_format(record_name(), [field()], binary(), encoding_rules()) ->
    binary().
generate_example_rrdata_format(RecordName, Fields, Acc, EncodingRules) ->
    %% Generate example for RRDATA records: just the fields directly (no type key wrapper)
    %% This matches the format used in dns_rr.data
    FieldNameFun = fun(FieldName) -> field_name_for_doc(RecordName, FieldName) end,
    ExampleFieldsStr = format_example_fields(Fields, FieldNameFun, RecordName, EncodingRules),
    <<
        Acc/binary,
        "**Example:**\n\n",
        "```json\n",
        "{\n",
        ExampleFieldsStr/binary,
        "\n",
        "}\n",
        "```\n\n",
        "**Note:** This format is used within the `data` field of `dns_rr` records.\n\n"
    >>.

-spec format_example_fields(
    [field()], fun((field_name()) -> binary()), record_name(), encoding_rules()
) -> binary().
format_example_fields(Fields, FieldNameFun, RecordName, EncodingRules) ->
    ExampleFields = [
        begin
            FieldBin = FieldNameFun(FieldName),
            Encoding = determine_encoding(RecordName, FieldName, TypeStr, EncodingRules),
            ExampleValue = example_value(FieldName, Encoding),
            [~"    \"", FieldBin, ~"\": ", ExampleValue]
        end
     || {FieldName, TypeStr} <- Fields
    ],
    iolist_to_binary(lists:join(~",\n", ExampleFields)).

-spec field_name_for_doc(record_name(), field_name()) -> binary().
field_name_for_doc(dns_rrdata_txt, txt) -> <<"txts">>;
field_name_for_doc(dns_rrdata_sshfp, fp_type) -> <<"fptype">>;
field_name_for_doc(_RecordName, Field) -> atom_to_binary(Field, utf8).

-spec example_value(field_name(), encoding()) -> unicode:unicode_binary().
example_value(Field, Encoding) ->
    case example_value_map() of
        #{Field := Value} -> Value;
        _ -> example_value_by_encoding(Field, Encoding)
    end.

-spec example_value_by_encoding(field_name(), encoding()) -> unicode:unicode_binary().
example_value_by_encoding(_Field, base16) ->
    ~"\"base16-encoded-data\"";
example_value_by_encoding(_Field, base32) ->
    ~"\"base32-encoded-data\"";
example_value_by_encoding(_Field, base64) ->
    ~"\"base64-encoded-data\"";
example_value_by_encoding(Field, _Encoding) ->
    example_value_by_category(Field).

-spec example_value_by_category(field_name()) -> unicode:unicode_binary().
example_value_by_category(Field) ->
    CategoryMap = example_category_map(),
    case maps:get(Field, CategoryMap, none) of
        boolean -> ~"false";
        numeric -> ~"0";
        list -> ~"[]";
        encoded -> ~"\"base64-encoded-data\"";
        none -> ~"\"value\""
    end.

-spec example_category_map() -> #{field_name() => boolean | numeric | list | encoded}.
example_category_map() ->
    %% Build map once - this is called multiple times but the overhead is acceptable for a doc script
    BooleanMap = maps:from_list([{F, boolean} || F <- boolean_fields()]),
    NumericMap = maps:from_list([{F, numeric} || F <- numeric_fields()]),
    ListMap = maps:from_list([{F, list} || F <- list_fields()]),
    EncodedMap = maps:from_list([{F, encoded} || F <- encoded_fields()]),
    maps:merge(maps:merge(BooleanMap, NumericMap), maps:merge(ListMap, EncodedMap)).

-spec example_value_map() -> #{field_name() => unicode:unicode_binary()}.
example_value_map() ->
    #{
        ip => ~"\"192.168.1.1\"",
        name => ~"\"example.com\"",
        dname => ~"\"example.com\"",
        hostname => ~"\"example.com\"",
        exchange => ~"\"mail.example.com\"",
        target => ~"\"target.example.com\"",
        mname => ~"\"ns1.example.com\"",
        rname => ~"\"admin.example.com\"",
        ttl => ~"3600",
        svc_params => ~"{\"alpn\": [\"h2\", \"h3\"], \"port\": 443}"
    }.

-spec boolean_fields() -> [field_name()].
boolean_fields() ->
    [qr, aa, tc, rd, ra, ad, cd, opt_out, oc].

-spec list_fields() -> [field_name()].
list_fields() ->
    [txt, questions, answers, authority, additional, data, types, protocols].

-spec numeric_fields() -> [field_name()].
numeric_fields() ->
    [
        flags,
        type,
        class,
        alg,
        protocol,
        preference,
        priority,
        weight,
        port,
        keytag,
        digest_type,
        hash_alg,
        iterations,
        serial,
        refresh,
        retry,
        expire,
        minimum,
        id,
        qc,
        anc,
        auc,
        adc,
        subtype,
        scheme,
        algorithm,
        precedence,
        xt,
        name_type,
        svc_priority
    ].

-spec encoded_fields() -> [field_name()].
encoded_fields() ->
    [
        cert,
        public_key,
        signature,
        mac,
        digest,
        hash,
        fp,
        address,
        salt,
        other,
        value,
        tag,
        certificate
    ].

-spec generate_svcb_params_section() -> binary().
generate_svcb_params_section() ->
    ~"""
    ### SVCB Service Parameters

    The `svc_params` field in SVCB and HTTPS records is a map containing service binding parameters
    as defined in [RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460).

    **Parameters:**

    - `mandatory` (`[string()]`): List of parameter names that must be present (e.g., `["alpn", "port"]`)
    - `alpn` (`[binary()]`): List of ALPN protocol identifiers as decoded binaries (e.g., `["h2", "h3"]`)
    - `no-default-alpn` (`"none"` | `none`): Indicates that no default ALPN should be used
    - `port` (`integer()`): Port number (0-65535)
    - `ipv4hint` (`[string()]`): List of IPv4 addresses as strings (e.g., `["192.168.1.1", "192.168.1.2"]`)
    - `ipv6hint` (`[string()]`): List of IPv6 addresses as strings (e.g., `["2001:db8::1"]`)
    - `ech` (`binary()`): Encrypted ClientHello (ECH) configuration as decoded binary
    - `keyNNNNN` (`binary()` | `integer()` | `"none"`): Unknown parameters where `NNNNN` is the parameter key number (0-65535)

    **Example:**

    ```json
    {
        "svc_priority": 1,
        "target_name": "target.example.com",
        "svc_params": {
            "mandatory": ["alpn", "port"],
            "alpn": ["h2", "h3"],
            "port": 443,
            "ipv4hint": ["192.168.1.1", "192.168.1.2"],
            "ipv6hint": ["2001:db8::1"],
            "ech": "ech-config-data"
        }
    }
    ```

    **Note:** All parameter values are in their decoded/native format (not base64-encoded).
    Binary values like ALPN identifiers and ECH config are provided as raw binaries, not base64 strings.

    """.
