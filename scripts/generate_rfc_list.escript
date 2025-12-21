#!/usr/bin/env escript
%% -*- erlang -*-
%% Extract RFC references from the codebase and generate a markdown list.
%%
%% Usage:
%%     # Generate RFC list to stdout
%%     escript scripts/generate_rfc_list.escript
%%
%%     # Generate RFC list and save to file
%%     escript scripts/generate_rfc_list.escript --output RFC_LIST.md
%%
%% To update the README.md:
%%     1. Run: escript scripts/generate_rfc_list.escript > /tmp/rfc_list.md
%%     2. Copy the output and replace the "## Supported RFCs" section in README.md
%%     3. Or use: escript scripts/generate_rfc_list.escript --output /tmp/rfc_list.md

-mode(compile).

-define(RFC_TITLES, #{
    <<"1034">> => <<"Domain Names - Concepts and Facilites">>,
    <<"1035">> => <<"Domain Names - Implementation and Specification">>,
    <<"3596">> => <<"DNS Extensions to Support IP Version 6">>,
    <<"1183">> => <<"New DNS RR Definitions">>,
    <<"1876">> => <<"A Means for Expressing Location Information in the Domain Name System">>,
    <<"2230">> => <<"Key Exchange Delegation Record for the DNS">>,
    <<"2782">> => <<"A DNS RR for specifying the location of services (DNS SRV)">>,
    <<"3403">> =>
        <<"Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database">>,
    <<"2308">> => <<"Negative Caching of DNS Queries (DNS NCACHE)">>,
    <<"3597">> => <<"Handling of Unknown DNS Resource Record (RR) Types">>,
    <<"4025">> => <<"A Method for Storing IPsec Keying Material in DNS">>,
    <<"4255">> => <<"Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints">>,
    <<"4398">> => <<"Storing Certificates in the Domain Name System (DNS)">>,
    <<"4408">> =>
        <<"Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1">>,
    <<"4701">> =>
        <<"A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)">>,
    <<"6672">> => <<"DNAME Redirection in the DNS">>,
    <<"6698">> =>
        <<"The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA">>,
    <<"6844">> => <<"DNS Certification Authority Authorization (CAA) Resource Record">>,
    <<"9460">> =>
        <<"Service Binding and Parameter Specification via the DNS (DNS SVCB and HTTPS Resource Records)">>,
    <<"2535">> => <<"Domain Name System Security Extensions">>,
    <<"4034">> => <<"Resource Records for the DNS Security Extensions">>,
    <<"4431">> => <<"The DNSSEC Lookaside Validation (DLV) DNS Resource Record">>,
    <<"5155">> => <<"DNS Security (DNSSEC) Hashed Authenticated Denial of Existence">>,
    <<"6605">> => <<"Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC">>,
    <<"7344">> => <<"Automating DNSSEC Delegation Trust Maintenance">>,
    <<"8080">> => <<"Ed25519 and Ed448 for DNSSEC">>,
    <<"9077">> => <<"NSEC and NSEC3 TTL Values">>,
    <<"7553">> => <<"The Uniform Resource Identifier (URI) DNS Resource Record">>,
    <<"7043">> => <<"Resource Records for EUI-48 and EUI-64 Addresses in the DNS">>,
    <<"8162">> => <<"Using Secure DNS to Associate Certificates with Domain Names for S/MIME">>,
    <<"9606">> => <<"DNS Resolver Information">>,
    <<"7929">> => <<"DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP">>,
    <<"2845">> => <<"Secret Key Transaction Authentication for DNS (TSIG)">>,
    <<"6891">> => <<"Extension Mechanisms for DNS (EDNS(0))">>,
    <<"8976">> => <<"Message Digest for DNS Zones">>,
    <<"5001">> => <<"DNS Name Server Identifier (NSID) Option">>,
    <<"7871">> => <<"Client Subnet in DNS Queries">>,
    <<"7873">> => <<"Domain Name System (DNS) Cookies">>,
    <<"8764">> => <<"DNS Long-Lived Queries (LLQ)">>,
    <<"8914">> => <<"Extended DNS Errors">>
}).

main(Args) ->
    RootDir = get_root_dir(),
    Opts = parse_args(Args, []),
    {ok, RfcPattern} = re:compile(<<"(?i)RFC[\\s-]?(\\d+)">>, [unicode]),
    io:format(standard_error, "Searching for RFC references in ~s...~n", [RootDir]),
    RfcRefs = find_rfc_references(RootDir, RfcPattern),
    RfcCount = maps:size(RfcRefs),
    io:format(standard_error, "Found ~p unique RFCs:~n", [RfcCount]),
    Markdown = generate_markdown(RfcRefs),
    case proplists:get_value(output, Opts, undefined) of
        undefined ->
            io:format("~s", [Markdown]);
        File ->
            file:write_file(File, Markdown),
            io:format(standard_error, "Generated RFC list: ~s~n", [File])
    end.

parse_args([], Acc) ->
    lists:reverse(Acc);
parse_args(["--output", File | Rest], Acc) ->
    parse_args(Rest, [{output, File} | Acc]);
parse_args([Unknown | Rest], Acc) ->
    io:format(standard_error, "Warning: Unknown option ~s~n", [Unknown]),
    parse_args(Rest, Acc).

get_root_dir() ->
    ScriptPath = escript:script_name(),
    ScriptDir = filename:dirname(filename:absname(ScriptPath)),
    filename:dirname(ScriptDir).

find_rfc_references(RootDir, RfcPattern) ->
    Dirs = [<<"src">>, <<"include">>],
    Extensions = ["*.erl", "*.hrl"],
    Files = [
        File
     || Ext <- Extensions,
        Dir <- Dirs,
        File <- filelib:wildcard(binary_to_list(filename:join([RootDir, Dir, "**", Ext])))
    ],
    lists:foldl(fun(File, Acc) -> scan_file(File, Acc, RfcPattern) end, #{}, Files).

scan_file(File, Acc, RfcPattern) ->
    case file:read_file(File) of
        {ok, Content} ->
            extract_rfc_numbers(Content, RfcPattern, File, Acc);
        {error, Reason} ->
            io:format(standard_error, "Warning: Could not read ~s: ~p~n", [File, Reason]),
            Acc
    end.

extract_rfc_numbers(Content, RfcPattern, File, Acc) ->
    case re:run(Content, RfcPattern, [global, {capture, all, binary}]) of
        {match, Matches} ->
            RfcNums = [RfcNum || [_, RfcNum] <- Matches],
            lists:foldl(
                fun(RfcNum, AccAcc) ->
                    maps:update_with(
                        RfcNum,
                        fun(Refs) -> [File | Refs] end,
                        [File],
                        AccAcc
                    )
                end,
                Acc,
                RfcNums
            );
        nomatch ->
            Acc
    end.

generate_markdown(RfcRefs) ->
    Header =
        <<"# Supported RFCs\n\n",
            "This library implements encoding and decoding of DNS packets according to the following RFCs. ",
            "Note that this library focuses on packet encoding/decoding only and does not implement DNS server ",
            "functionality such as socket handling or query resolution.\n\n">>,
    SortedRfcs = lists:sort(
        fun(A, B) -> binary_to_integer(A) < binary_to_integer(B) end, maps:keys(RfcRefs)
    ),
    RfcItems = lists:map(
        fun(RfcNum) ->
            Title = maps:get(RfcNum, ?RFC_TITLES, <<"Unknown">>),
            RfcUrl = iolist_to_binary([<<"https://tools.ietf.org/html/rfc">>, RfcNum]),
            iolist_to_binary([
                <<"- **[RFC ">>, RfcNum, <<"](">>, RfcUrl, <<")**: ">>, Title, <<"\n">>
            ])
        end,
        SortedRfcs
    ),
    iolist_to_binary([Header | RfcItems]).
