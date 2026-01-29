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
-moduledoc """
The `dns` module is the primary entry point for the functionality in this library.
The module exports various types used in type specs, such as `t:message/0`, which indicates
a `#dns_message{}` record, `t:query/0` which represents a single `#dns_query{}` record,
`t:questions/0`, which represents a list of queries, etc.

It also exports functions for encoding and decoding messages,
TSIG supporting functions, and various utility functions for comparing domain names, converting
domain names into different cases, converting to and from label lists, etc.
""".

-export([decode_message/1, decode_query/1, encode_message/1, encode_message/2]).
-export([verify_tsig/3, verify_tsig/4, add_tsig/5, add_tsig/6]).
-export([unix_time/0, unix_time/1]).
-export([random_id/0]).

-include_lib("dns_erlang/include/dns.hrl").

%% 2^31 - 1, the largest signed 32-bit integer value
-define(MAX_INT32, ((1 bsl 31) - 1)).

-doc #{group => "Types: integer codes"}.
-doc "Unsigned 2-bits integer".
-type uint2() :: 0..1.
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 4-bits integer".
-type uint4() :: 0..15.
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 8-bits integer".
-type uint8() :: 0..((1 bsl 8) - 1).
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 16-bits integer".
-type uint16() :: 0..((1 bsl 16) - 1).
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 32-bits integer".
-type uint32() :: 0..((1 bsl 32) - 1).
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 48-bits integer".
-type uint48() :: 0..((1 bsl 48) - 1).
-doc #{group => "Types: integer codes"}.
-doc "Unsigned 64-bits integer".
-type uint64() :: 0..((1 bsl 64) - 1).
-doc #{group => "Types: integer codes"}.
-doc "DNS opcode. See RFC 1035: §4.1.1.".
-type opcode() :: uint4().
-doc #{group => "Types: integer codes"}.
-doc "DNS Return code. See RFC 1035: §4.1.1.".
-type rcode() :: uint4().
-doc #{group => "Types: integer codes"}.
-type eoptcode() :: uint16().
-doc #{group => "Types: integer codes"}.
-type ercode() :: 0 | 16.
-doc #{group => "Types: integer codes"}.
-type llqerrcode() :: 0..6.
-doc #{group => "Types: integer codes"}.
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

-doc #{group => "Types: strings"}.
-doc """
DNS wire message format.

The general form is a 96bits header, followed by a variable number of questions,
answers, authorities, and additional records.
""".
-type message_bin() :: <<_:96, _:_*8>>.

-doc #{group => "Types: integer codes"}.
-doc "DNS Message ID. See RFC 1035: §4.1.1.".
-type message_id() :: uint16().

-doc #{group => "Types: integer codes"}.
-doc """
Decoding errors.

Can be one of the following:
- `formerr`: the message was malformed.
- `truncated`: the message was partially decoded, as data was found missing from the message.
- `trailing_garbage`: the message was successfully decoded,
    but there was trailing garbage at the end of the message.
- `notimp`: the opcode is not implemented (e.g., IQUERY, STATUS, DSO).
    The message struct contains minimal fields needed to construct a NOTIMP response.
""".
-type decode_error() :: formerr | truncated | notimp | trailing_garbage.

-doc #{group => "Types: strings"}.
-doc "Domain name, expressed as a sequence of `t:label/0`, as defined in RFC 1035: §3.1.".
-type dname() :: binary().

-doc #{group => "Types: strings"}.
-doc """
DNS labels. See RFC 1035: §2.3.1.

The labels must follow the rules for ARPANET host names. They must
start with a letter, end with a letter or digit, and have as interior
characters only letters, digits, and hyphen. There are also some
restrictions on the length. Labels must be 63 characters or less.
""".
-type label() :: binary().
-doc #{group => "Types: strings"}.
-doc "A list of `t:dns:label/0`".
-type labels() :: [label()].
-doc #{group => "Types: integer codes"}.
-doc "DNS Message class. See RFC 1035: §4.1.2.".
-type class() :: uint16().
-doc #{group => "Types: integer codes"}.
-doc "DNS Message class. See RFC 1035: §4.1.2.".
-type type() :: uint16().
-doc #{group => "Types: integer codes"}.
-doc "DNS Message class. See RFC 1035: §4.1.3.".
-type ttl() :: 0..?MAX_INT32.
-doc #{group => "Types: integer codes"}.
-doc "Unix timestamp in seconds.".
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

-doc #{group => "Types: records"}.
-doc "Main DNS message structure.".
-type message() :: #dns_message{}.
-doc #{group => "Types: records"}.
-type query() :: #dns_query{}.
-doc #{group => "Types: records"}.
-type rr() :: #dns_rr{}.
-doc #{group => "Types: records"}.
-type optrr() :: #dns_optrr{}.
-doc #{group => "Types: records"}.
-type opt_nsid() :: #dns_opt_nsid{}.
-doc #{group => "Types: records"}.
-type opt_ul() :: #dns_opt_ul{}.
-doc #{group => "Types: records"}.
-type opt_ecs() :: #dns_opt_ecs{}.
-doc #{group => "Types: records"}.
-type opt_llq() :: #dns_opt_llq{}.
-doc #{group => "Types: records"}.
-type opt_owner() :: #dns_opt_owner{}.
-doc #{group => "Types: records"}.
-type opt_cookie() :: #dns_opt_cookie{}.
-doc #{group => "Types: records"}.
-type opt_ede() :: #dns_opt_ede{}.
-doc #{group => "Types: records"}.
-type opt_unknown() :: #dns_opt_unknown{}.
-doc #{group => "Types: records"}.
-type rrdata_rrsig() :: #dns_rrdata_rrsig{}.
-doc #{group => "Types: records"}.
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
    | #dns_rrdata_eui48{}
    | #dns_rrdata_eui64{}
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
    | #dns_rrdata_csync{}
    | #dns_rrdata_dsync{}
    | #dns_rrdata_openpgpkey{}
    | #dns_rrdata_ptr{}
    | #dns_rrdata_rp{}
    | #dns_rrdata_rrsig{}
    | #dns_rrdata_rt{}
    | #dns_rrdata_soa{}
    | #dns_rrdata_spf{}
    | #dns_rrdata_srv{}
    | #dns_rrdata_svcb{}
    | #dns_rrdata_https{}
    | #dns_rrdata_sshfp{}
    | #dns_rrdata_tlsa{}
    | #dns_rrdata_smimea{}
    | #dns_rrdata_tsig{}
    | #dns_rrdata_txt{}
    | #dns_rrdata_uri{}
    | #dns_rrdata_resinfo{}
    | #dns_rrdata_wallet{}
    | #dns_rrdata_zonemd{}.
-doc #{group => "Types: records"}.
-type records() :: additional() | answers() | authority() | questions().
-doc #{group => "Types: records"}.
-type optrr_elem() ::
    opt_nsid()
    | opt_ul()
    | opt_unknown()
    | opt_ecs()
    | opt_llq()
    | opt_owner()
    | opt_cookie()
    | opt_ede().
-doc #{group => "Types: records"}.
-type questions() :: [query()].
-doc #{group => "Types: records"}.
-type answers() :: [rr()].
-doc #{group => "Types: records"}.
-type authority() :: [rr()].
-doc #{group => "Types: records"}.
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

-doc #{group => "Types: TSIG"}.
-type tsig_mac() :: binary().
-doc #{group => "Types: TSIG"}.
-type tsig_error() :: 0 | 16..18.
-doc #{group => "Types: TSIG"}.
-type tsig_alg() :: binary().
-doc #{group => "Types: TSIG"}.
-type alg() ::
    ?DNS_ALG_DSA
    | ?DNS_ALG_NSEC3DSA
    | ?DNS_ALG_RSASHA1
    | ?DNS_ALG_NSEC3RSASHA1
    | ?DNS_ALG_RSASHA256
    | ?DNS_ALG_RSASHA512
    | ?DNS_ALG_ECDSAP256SHA256
    | ?DNS_ALG_ECDSAP384SHA384
    | ?DNS_ALG_ED25519
    | ?DNS_ALG_ED448.
-export_type([
    alg/0,
    tsig_mac/0,
    tsig_error/0,
    tsig_alg/0
]).

-doc #{group => "Types: options"}.
-type svcb_svc_params() :: #{
    ?DNS_SVCB_PARAM_MANDATORY => [dns:uint16()],
    ?DNS_SVCB_PARAM_ALPN => [binary()],
    ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none,
    ?DNS_SVCB_PARAM_PORT => inet:port_number(),
    ?DNS_SVCB_PARAM_ECH => binary(),
    ?DNS_SVCB_PARAM_IPV4HINT => [inet:ip4_address()],
    ?DNS_SVCB_PARAM_IPV6HINT => [inet:ip6_address()],
    uint16() => none | binary()
}.
-doc #{group => "Types: options"}.
-type encode_message_opts() :: #{
    max_size => 512..65535,
    tc_mode => default | axfr | llq_event,
    tsig => encode_tsig_opts()
}.
-doc #{group => "Types: options"}.
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
-doc #{group => "Types: options"}.
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

-doc #{group => "Functions: parsing"}.
-doc "Decode a binary DNS message.".
-spec decode_message(message_bin()) ->
    {decode_error(), message() | undefined, binary()} | message().
decode_message(MsgBin) ->
    dns_decode:decode(MsgBin).

-doc #{group => "Functions: parsing"}.
-doc """
Decode a binary DNS query message with strict header validation.

Performs header guard checks before decoding the message body to prevent DoS attacks.
For standard queries (opcode 0), validates that:
- ANCount = 0 (queries should not have answers)
- NSCount = 0 (queries should not have authority records)
- QDCount = 1 (standard queries must have exactly one question)

For NOTIFY (opcode 4) and UPDATE (opcode 5), allows decoding to proceed.
For other opcodes, falls back to standard decoding.
""".
-spec decode_query(message_bin()) ->
    {decode_error(), message() | undefined, binary()}
    | message().
decode_query(MsgBin) ->
    dns_decode:decode_query(MsgBin).

-doc #{group => "Functions: parsing"}.
-doc "Encode a `t:message/0` record.".
-spec encode_message(message()) -> message_bin().
encode_message(Msg) ->
    dns_encode:encode(Msg).

-doc #{group => "Functions: parsing"}.
-doc "Encode a dns_message record - will truncate the message as needed.".
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

-doc #{group => "Functions: TSIG"}.
-doc #{equiv => verify_tsig(MsgBin, Name, Secret, #{})}.
-spec verify_tsig(message_bin(), dname(), binary()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret) ->
    dns_tsig:verify_tsig(MsgBin, Name, Secret).

-doc #{group => "Functions: TSIG"}.
-doc "Verifies a TSIG message signature.".
-spec verify_tsig(message_bin(), dname(), binary(), tsig_opts()) ->
    {ok, tsig_mac()} | {error, tsig_error()}.
verify_tsig(MsgBin, Name, Secret, Options) ->
    dns_tsig:verify_tsig(MsgBin, Name, Secret, Options).

-doc #{group => "Functions: TSIG"}.
-doc #{equiv => add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg})}.
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode) ->
    dns_tsig:add_tsig(Msg, Alg, Name, Secret, ErrCode, #{name => Name, alg => Alg}).

-doc #{group => "Functions: TSIG"}.
-doc """
Generates and then appends a TSIG RR to a message.

Supports MD5, SHA1, SHA224, SHA256, SHA384 and SHA512 algorithms.
""".
-spec add_tsig(message(), tsig_alg(), dname(), binary(), tsig_error(), encode_tsig_opts()) ->
    message().
add_tsig(Msg, Alg, Name, Secret, ErrCode, Options) ->
    dns_tsig:add_tsig(Msg, Alg, Name, Secret, ErrCode, Options).

%%%===================================================================
%%% Domain name functions
%%%===================================================================
%%% Miscellaneous functions
%%%===================================================================

-doc #{group => "Functions: utilities"}.
-doc "Returns a random integer suitable for use as DNS message identifier.".
-spec random_id() -> message_id().
random_id() ->
    rand:uniform(65535).

-doc #{group => "Functions: utilities"}.
-doc "Return current unix time in seconds.".
-spec unix_time() -> unix_time().
unix_time() ->
    erlang:system_time(second).

-doc #{group => "Functions: utilities"}.
-doc "Return the unix time in seconds from a timestamp or universal time.".
-spec unix_time(erlang:timestamp() | calendar:datetime1970()) -> unix_time().
unix_time({_MegaSecs, _Secs, _MicroSecs} = NowTime) ->
    UniversalTime = calendar:now_to_universal_time(NowTime),
    unix_time(UniversalTime);
unix_time({{_, _, _}, {_, _, _}} = UniversalTime) ->
    % From OTP28, we can use calendar:universal_time_to_system_time(UniversalTime),
    Epoch = {{1970, 1, 1}, {0, 0, 0}},
    (calendar:datetime_to_gregorian_seconds(UniversalTime) -
        calendar:datetime_to_gregorian_seconds(Epoch)).
