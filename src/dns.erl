%% -------------------------------------------------------------------
%%
%% Copyright (c) 2010 Andrew Tunnell-Jones. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(dns).
-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.
?MODULEDOC("""
The `dns` module is the primary entry point for the functionality in this library.
The module exports various types used in type specs, such as `t:message/0`, which indicates
a `#dns_message{}` record, `t:query/0` which represents a single `#dns_query{}` record,
`t:questions/0`, which represents a list of queries, etc.

It also exports functions for encoding and decoding messages,
TSIG supporting functions, and various utility functions for comparing domain names, converting
domain names into different cases, converting to and from label lists, etc.
""").

-export([decode_message/1, encode_message/1, encode_message/2]).
-export([verify_tsig/3, verify_tsig/4, add_tsig/5, add_tsig/6]).
-export([compare_dname/2, compare_labels/2, escape_label/1]).
-export([
    dname_to_upper/1,
    dname_to_lower/1,
    dname_to_labels/1,
    labels_to_dname/1,
    dname_to_lower_labels/1
]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-include_lib("dns_erlang/include/dns.hrl").

%% 2^31 - 1, the largest signed 32-bit integer value
-define(MAX_INT32, ((1 bsl 31) - 1)).

?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 2-bits integer").
-type uint2() :: 0..1.
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 4-bits integer").
-type uint4() :: 0..15.
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 8-bits integer").
-type uint8() :: 0..((1 bsl 8) - 1).
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 16-bits integer").
-type uint16() :: 0..((1 bsl 16) - 1).
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 32-bits integer").
-type uint32() :: 0..((1 bsl 32) - 1).
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 48-bits integer").
-type uint48() :: 0..((1 bsl 48) - 1).
?DOC(#{group => <<"Types: integer codes">>}).
?DOC("Unsigned 64-bits integer").
-type uint64() :: 0..((1 bsl 64) - 1).
?DOC(#{group => <<"Types: integer codes">>}).
-type opcode() :: uint4().
?DOC(#{group => <<"Types: integer codes">>}).
-type rcode() :: uint4().
?DOC(#{group => <<"Types: integer codes">>}).
-type eoptcode() :: uint16().
?DOC(#{group => <<"Types: integer codes">>}).
-type ercode() :: 0 | 16.
?DOC(#{group => <<"Types: integer codes">>}).
-type llqerrcode() :: 0..6.
?DOC(#{group => <<"Types: integer codes">>}).
-type llqopcode() :: 1..3.
-export_type([
    uint2/0,
    uint4/0,
    uint8/0,
    uint16/0,
    uint32/0,
    uint48/0,
    uint64/0,
    opcode/0,
    rcode/0,
    ercode/0,
    eoptcode/0,
    llqopcode/0,
    llqerrcode/0
]).

?DOC("""
DNS wire message format.

The general form is a 96bits header, followed by a variable number of questions,
answers, authorities, and additional records.
""").
-type message_bin() :: <<_:96, _:_*8>>.
?DOC("DNS Message ID. See RFC 1035: §4.1.1.").
-type message_id() :: uint16().
?DOC("""
Decoding errors.

Can be one of the following:
- `formerr`: the message was malformed.
- `truncated`: the message was partially decoded, as data was found missing from the message.
- `trailing_garbage`: the message was successfully decoded,
    but there was trailing garbage at the end of the message.
""").
-type decode_error() :: formerr | truncated | trailing_garbage.
?DOC("Domain name, expressed as a sequence of `t:label/0`, as defined in RFC 1035: §3.1.").
-type dname() :: binary().
?DOC("""
DNS labels. See RFC 1035: §2.3.1.

The labels must follow the rules for ARPANET host names. They must
start with a letter, end with a letter or digit, and have as interior
characters only letters, digits, and hyphen. There are also some
restrictions on the length. Labels must be 63 characters or less.
""").
-type label() :: binary().
?DOC("A list of `t:dns:label/0`").
-type labels() :: [label()].
?DOC("DNS Message class. See RFC 1035: §4.1.2.").
-type class() :: uint16().
?DOC("DNS Message class. See RFC 1035: §4.1.2.").
-type type() :: uint16().
?DOC("DNS Message class. See RFC 1035: §4.1.3.").
-type ttl() :: 0..?MAX_INT32.
?DOC("Unix timestamp in seconds.").
-type unix_time() :: 0..4294967295.
-export_type([
    message_bin/0,
    message_id/0,
    decode_error/0,
    dname/0,
    class/0,
    type/0,
    ttl/0,
    label/0,
    labels/0,
    unix_time/0
]).

?DOC(#{group => <<"Types: records">>}).
?DOC("Main DNS message structure.").
-type message() :: #dns_message{}.
?DOC(#{group => <<"Types: records">>}).
-type query() :: #dns_query{}.
?DOC(#{group => <<"Types: records">>}).
-type rr() :: #dns_rr{}.
?DOC(#{group => <<"Types: records">>}).
-type optrr() :: #dns_optrr{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_nsid() :: #dns_opt_nsid{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_ul() :: #dns_opt_ul{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_ecs() :: #dns_opt_ecs{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_llq() :: #dns_opt_llq{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_owner() :: #dns_opt_owner{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_cookie() :: #dns_opt_cookie{}.
?DOC(#{group => <<"Types: records">>}).
-type opt_unknown() :: #dns_opt_unknown{}.
?DOC(#{group => <<"Types: records">>}).
-type rrdata_rrsig() :: #dns_rrdata_rrsig{}.
?DOC(#{group => <<"Types: records">>}).
-type rrdata() ::
    binary()
    | #dns_rrdata_a{}
    | #dns_rrdata_aaaa{}
    | #dns_rrdata_afsdb{}
    | #dns_rrdata_caa{}
    | #dns_rrdata_cdnskey{}
    | #dns_rrdata_cds{}
    | #dns_rrdata_cert{}
    | #dns_rrdata_cname{}
    | #dns_rrdata_dhcid{}
    | #dns_rrdata_dlv{}
    | #dns_rrdata_dname{}
    | #dns_rrdata_dnskey{}
    | #dns_rrdata_ds{}
    | #dns_rrdata_hinfo{}
    | #dns_rrdata_ipseckey{}
    | #dns_rrdata_key{}
    | #dns_rrdata_kx{}
    | #dns_rrdata_loc{}
    | #dns_rrdata_mb{}
    | #dns_rrdata_mg{}
    | #dns_rrdata_minfo{}
    | #dns_rrdata_mr{}
    | #dns_rrdata_mx{}
    | #dns_rrdata_naptr{}
    | #dns_rrdata_ns{}
    | #dns_rrdata_nsec{}
    | #dns_rrdata_nsec3{}
    | #dns_rrdata_nsec3param{}
    | #dns_rrdata_nxt{}
    | #dns_rrdata_ptr{}
    | #dns_rrdata_rp{}
    | #dns_rrdata_rrsig{}
    | #dns_rrdata_rt{}
    | #dns_rrdata_soa{}
    | #dns_rrdata_spf{}
    | #dns_rrdata_srv{}
    | #dns_rrdata_svcb{}
    | #dns_rrdata_sshfp{}
    | #dns_rrdata_tlsa{}
    | #dns_rrdata_tsig{}
    | #dns_rrdata_txt{}.
?DOC(#{group => <<"Types: records">>}).
-type records() :: additional() | answers() | authority() | questions().
?DOC(#{group => <<"Types: records">>}).
-type optrr_elem() ::
    opt_nsid()
    | opt_ul()
    | opt_unknown()
    | opt_ecs()
    | opt_llq()
    | opt_owner()
    | opt_cookie().
?DOC(#{group => <<"Types: records">>}).
-type questions() :: [query()].
?DOC(#{group => <<"Types: records">>}).
-type answers() :: [rr()].
?DOC(#{group => <<"Types: records">>}).
-type authority() :: [rr()].
?DOC(#{group => <<"Types: records">>}).
-type additional() :: [optrr() | rr()].
-export_type([
    message/0,
    records/0,
    query/0,
    rr/0,
    optrr/0,
    questions/0,
    answers/0,
    authority/0,
    additional/0,
    rrdata/0,
    opt_nsid/0,
    opt_ul/0,
    opt_ecs/0,
    opt_llq/0,
    opt_owner/0,
    opt_unknown/0,
    optrr_elem/0,
    rrdata_rrsig/0
]).

?DOC(#{group => <<"Types: TSIG">>}).
-type tsig_mac() :: binary().
?DOC(#{group => <<"Types: TSIG">>}).
-type tsig_error() :: 0 | 16..18.
?DOC(#{group => <<"Types: TSIG">>}).
-type tsig_alg() :: binary().
?DOC(#{group => <<"Types: TSIG">>}).
-type alg() ::
    ?DNS_ALG_DSA
    | ?DNS_ALG_NSEC3DSA
    | ?DNS_ALG_RSASHA1
    | ?DNS_ALG_NSEC3RSASHA1
    | ?DNS_ALG_RSASHA256
    | ?DNS_ALG_RSASHA512.
-export_type([
    alg/0,
    tsig_mac/0,
    tsig_error/0,
    tsig_alg/0
]).

?DOC(#{group => <<"Types: options">>}).
-type svcb_svc_params() :: #{
    1..6 => none | char() | binary()
}.
?DOC(#{group => <<"Types: options">>}).
-type encode_message_opts() :: #{
    max_size => 512..65535,
    tc_mode => default | axfr | llq_event,
    tsig => encode_tsig_opts()
}.
?DOC(#{group => <<"Types: options">>}).
-type encode_tsig_opts() :: #{
    name := dname(),
    alg := tsig_alg(),
    msgid => message_id(),
    secret => binary(),
    errcode => tsig_error(),
    other => binary(),
    time => unix_time(),
    fudge => non_neg_integer(),
    mac => tsig_mac(),
    tail => boolean()
}.
?DOC(#{group => <<"Types: options">>}).
-type tsig_opts() :: #{
    time => unix_time(),
    fudge => non_neg_integer(),
    mac => tsig_mac(),
    tail => boolean(),
    atom() => _
}.
-export_type([
    svcb_svc_params/0,
    encode_message_opts/0,
    encode_tsig_opts/0,
    tsig_opts/0
]).

%%%===================================================================
%%% Message body functions
%%%===================================================================

?DOC(#{group => <<"Functions: parsing">>}).
?DOC("Decode a binary DNS message.").
-spec decode_message(message_bin()) ->
    {decode_error(), message() | undefined, binary()} | message().
decode_message(MsgBin) ->
    dns_decode:decode(MsgBin).

?DOC(#{group => <<"Functions: parsing">>}).
?DOC("Encode a `t:message/0` record.").
-spec encode_message(message()) -> message_bin().
encode_message(Msg) ->
    dns_encode:encode(Msg).

?DOC(#{group => <<"Functions: parsing">>}).
?DOC("Encode a dns_message record - will truncate the message as needed.").
-spec encode_message(message(), encode_message_opts()) ->
    {false, message_bin()}
    | {false, message_bin(), tsig_mac()}
    | {true, message_bin(), message()}
    | {true, message_bin(), tsig_mac(), message()}.
encode_message(Msg, Opts) ->
    dns_encode:encode(Msg, Opts).

%%%===================================================================
%%% TSIG functions
%%%===================================================================

?DOC(#{group => <<"Functions: TSIG">>}).
?DOC(#{equiv => verify_tsig(MsgBin, Name, Secret, #{})}).
-spec verify_tsig(message_bin(), dname(), binary()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret) ->
    dns_tsig:verify_tsig(MsgBin, Name, Secret).

?DOC(#{group => <<"Functions: TSIG">>}).
?DOC("Verifies a TSIG message signature.").
-spec verify_tsig(message_bin(), dname(), binary(), tsig_opts()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret, Options) ->
    dns_tsig:verify_tsig(MsgBin, Name, Secret, Options).

?DOC(#{group => <<"Functions: TSIG">>}).
?DOC(#{equiv => add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg})}).
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode) ->
    dns_tsig:add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg}).

?DOC(#{group => <<"Functions: TSIG">>}).
?DOC("""
Generates and then appends a TSIG RR to a message.

Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
""").
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error(), encode_tsig_opts()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    dns_tsig:add_tsig(Msg, Alg, Name, Secret, ErrCode, Options).

%%%===================================================================
%%% Domain name functions
%%%===================================================================

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Splits a dname into a list of labels in lowercase and removes unneeded escapes.").
-spec dname_to_lower_labels(dname()) -> labels().
dname_to_lower_labels(Name) ->
    dname_to_labels(dname_to_lower(Name)).

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Splits a dname into a list of labels and removes unneeded escapes.").
-spec dname_to_labels(dname()) -> labels().
dname_to_labels(<<>>) ->
    [];
dname_to_labels(<<$.>>) ->
    [];
dname_to_labels(Name) ->
    do_dname_to_labels(<<>>, Name).

-spec do_dname_to_labels(binary(), binary()) -> [binary(), ...].
do_dname_to_labels(Label, <<>>) ->
    [Label];
do_dname_to_labels(Label, <<$.>>) ->
    [Label];
do_dname_to_labels(Label, <<$., Cs/binary>>) ->
    [Label | do_dname_to_labels(<<>>, Cs)];
do_dname_to_labels(Label, <<"\\.", Cs/binary>>) ->
    do_dname_to_labels(<<Label/binary, $.>>, Cs);
do_dname_to_labels(Label, <<"\\\\", Cs/binary>>) ->
    do_dname_to_labels(<<Label/binary, $\\>>, Cs);
do_dname_to_labels(Label, <<C, Cs/binary>>) ->
    do_dname_to_labels(<<Label/binary, C>>, Cs).

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Compare two domain names insensitive of case.").
-spec compare_dname(dname(), dname()) -> boolean().
compare_dname(Name, Name) ->
    true;
compare_dname(NameA, NameB) ->
    dname_to_lower(NameA) =:= dname_to_lower(NameB).

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Compare two domain names insensitive of case.").
-spec compare_labels(labels(), labels()) -> boolean().
compare_labels(LabelsA, LabelsB) when is_list(LabelsA), is_list(LabelsB) ->
    do_compare_labels(LabelsA, LabelsB).

do_compare_labels([], []) ->
    true;
do_compare_labels([LA | LabelsA], [LA | LabelsB]) ->
    do_compare_labels(LabelsA, LabelsB);
do_compare_labels([LA | LabelsA], [LB | LabelsB]) ->
    dname_to_lower(LA) =:= dname_to_lower(LB) andalso do_compare_labels(LabelsA, LabelsB);
do_compare_labels([], [_ | _]) ->
    false;
do_compare_labels([_ | _], []) ->
    false.

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Escapes dots in a DNS label").
-spec escape_label(label()) -> label().
escape_label(Label) when is_binary(Label) ->
    do_escape_label(<<>>, Label).

-spec do_escape_label(binary(), binary()) -> binary().
do_escape_label(Label, <<>>) ->
    Label;
do_escape_label(Cur, <<$\\, Rest/binary>>) ->
    do_escape_label(<<Cur/binary, "\\\\">>, Rest);
do_escape_label(Cur, <<$., Rest/binary>>) ->
    do_escape_label(<<Cur/binary, "\\.">>, Rest);
do_escape_label(Cur, <<C, Rest/binary>>) ->
    do_escape_label(<<Cur/binary, C>>, Rest).

?DOC(false).
-spec labels_to_dname(labels()) -> dname().
labels_to_dname(Labels) ->
    <<$., DName/binary>> = <<<<$., (escape_label(Label))/binary>> || Label <- Labels>>,
    DName.

-define(UP(X), (upper(X)):8).
?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Returns provided name with case-insensitive characters in uppercase.").
-spec dname_to_upper(dname()) -> dname().
dname_to_upper(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G), ?UP(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
dname_to_upper(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F), ?UP(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
dname_to_upper(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E), ?UP(F)>> || <<A, B, C, D, E, F>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D), ?UP(E)>> || <<A, B, C, D, E>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C), ?UP(D)>> || <<A, B, C, D>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?UP(A), ?UP(B), ?UP(C)>> || <<A, B, C>> <= Data>>;
dname_to_upper(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?UP(A), ?UP(B)>> || <<A, B>> <= Data>>;
dname_to_upper(Data) ->
    <<<<?UP(N)>> || <<N>> <= Data>>.

-define(LOW(X), (lower(X)):8).
?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Returns provided name with case-insensitive characters in lowercase.").
-spec dname_to_lower(dname()) -> dname().
dname_to_lower(Data) when byte_size(Data) rem 8 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G), ?LOW(H)>>
     || <<A, B, C, D, E, F, G, H>> <= Data
    >>;
dname_to_lower(Data) when byte_size(Data) rem 7 =:= 0 ->
    <<
        <<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F), ?LOW(G)>>
     || <<A, B, C, D, E, F, G>> <= Data
    >>;
dname_to_lower(Data) when byte_size(Data) rem 6 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E), ?LOW(F)>> || <<A, B, C, D, E, F>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 5 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D), ?LOW(E)>> || <<A, B, C, D, E>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 4 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C), ?LOW(D)>> || <<A, B, C, D>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 3 =:= 0 ->
    <<<<?LOW(A), ?LOW(B), ?LOW(C)>> || <<A, B, C>> <= Data>>;
dname_to_lower(Data) when byte_size(Data) rem 2 =:= 0 ->
    <<<<?LOW(A), ?LOW(B)>> || <<A, B>> <= Data>>;
dname_to_lower(Data) ->
    <<<<?LOW(N)>> || <<N>> <= Data>>.

lower(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104,
            105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
            122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
            139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
            156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
            173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
            190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
            207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
            224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
            241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
    ).

upper(X) ->
    element(
        X + 1,
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
            81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131,
            132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
            149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
            166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
            183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
            217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            251, 252, 253, 254, 255}
    ).

%%%===================================================================
%%% Miscellaneous functions
%%%===================================================================

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Returns a random integer suitable for use as DNS message identifier.").
-spec random_id() -> message_id().
random_id() ->
    rand:uniform(65535).

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Return current unix time in seconds.").
-spec unix_time() -> unix_time().
unix_time() ->
    erlang:system_time(second).

?DOC(#{group => <<"Functions: utilities">>}).
?DOC("Return the unix time in seconds from a timestamp or universal time.").
-spec unix_time(erlang:timestamp() | calendar:datetime1970()) -> unix_time().
unix_time({_MegaSecs, _Secs, _MicroSecs} = NowTime) ->
    UniversalTime = calendar:now_to_universal_time(NowTime),
    unix_time(UniversalTime);
unix_time({{_, _, _}, {_, _, _}} = UniversalTime) ->
    % From OTP28, we can use calendar:universal_time_to_system_time(UniversalTime),
    Epoch = {{1970, 1, 1}, {0, 0, 0}},
    (calendar:datetime_to_gregorian_seconds(UniversalTime) -
        calendar:datetime_to_gregorian_seconds(Epoch)).
