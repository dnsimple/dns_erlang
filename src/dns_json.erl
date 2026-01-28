-module(dns_json).
-moduledoc {file, "JSON_FORMAT.md"}.
-moduledoc #{since => "v5.0.0"}.

-export([to_map/1, from_map/1]).

-include_lib("dns_erlang/include/dns.hrl").

-doc "Converts a DNS record to a map representation suitable for JSON encoding.".
-spec to_map(tuple()) -> map().
to_map(#dns_rr{name = Name, type = Type, class = Class, ttl = Ttl, data = Data}) ->
    TypeBin =
        case dns_names:type_name(Type) of
            undefined -> integer_to_binary(Type);
            TB when is_binary(TB) -> TB
        end,
    ClassBin =
        case dns_names:class_name(Class) of
            undefined -> integer_to_binary(Class);
            CB when is_binary(CB) -> CB
        end,
    DataMap = to_map_rrdata(Data),
    #{
        ~"name" => Name,
        ~"type" => TypeBin,
        ~"class" => ClassBin,
        ~"ttl" => Ttl,
        ~"data" => DataMap
    };
to_map(Record) when is_tuple(Record) ->
    Tag = element(1, Record),
    is_rrdata_tag(Tag) andalso erlang:error({rrdata_requires_wrapper, Tag}),
    Fields = record_fields(Tag),
    Values = tl(tuple_to_list(Record)),
    DataMap = lists:foldl(
        fun({Field, Value}, Acc) ->
            NewValue = to_map_value(Tag, Field, Value),
            FieldBin = atom_to_binary(Field),
            Acc#{FieldBin => NewValue}
        end,
        #{},
        lists:zip(Fields, Values)
    ),
    RecordKey = record_key_name(Tag),
    #{RecordKey => DataMap}.

-doc "Converts a map representation back to a DNS record.".
-spec from_map(map()) -> tuple().
from_map(
    #{~"name" := Name, ~"type" := TypeBin, ~"ttl" := Ttl, ~"data" := DataMap} = Map
) when is_binary(TypeBin) ->
    Type = binary_to_dns_type(TypeBin),
    Class =
        case maps:get(~"class", Map, undefined) of
            undefined ->
                ?DNS_CLASS_IN;
            ClassBin when is_binary(ClassBin) ->
                case dns_names:name_class(ClassBin) of
                    undefined -> ?DNS_CLASS_IN;
                    ClassInt -> ClassInt
                end;
            ClassInt when is_integer(ClassInt) -> ClassInt
        end,
    %% Convert the data map to RRDATA record
    Data = from_map_rrdata(Type, DataMap),
    #dns_rr{
        name = Name,
        type = Type,
        class = Class,
        ttl = Ttl,
        data = Data
    };
from_map(Map) when is_map(Map), 1 =:= map_size(Map) ->
    [{Key, DataMap}] = maps:to_list(Map),
    Tag = record_type_from_key(Key),
    is_binary(Key) orelse erlang:error({invalid_record_key, Key, Map}),
    undefined =/= Tag orelse erlang:error({unknown_record_key, Key, Map}),
    is_rrdata_tag(Tag) andalso erlang:error({rrdata_requires_wrapper, Tag}),
    Fields = record_fields(Tag),
    Values = [
        from_map_field(Tag, Field, maps:get(atom_to_binary(Field), DataMap, undefined))
     || Field <- Fields
    ],
    list_to_tuple([Tag | Values]);
from_map(Map) ->
    erlang:error({invalid_map_format, Map}).

%% Helper to map record type atom to JSON key name
%% Other records use descriptive names (message, query, rr, OPT, etc.)
%% Note: RRDATA records must be wrapped in dns_rr, so they don't need key names
-spec record_key_name(atom()) -> binary().
record_key_name(dns_message) -> ~"message";
record_key_name(dns_query) -> ~"query";
record_key_name(dns_optrr) -> ~"OPT";
record_key_name(dns_opt_llq) -> ?DNS_EOPTCODE_LLQ_BSTR;
record_key_name(dns_opt_nsid) -> ?DNS_EOPTCODE_NSID_BSTR;
record_key_name(dns_opt_owner) -> ?DNS_EOPTCODE_OWNER_BSTR;
record_key_name(dns_opt_ul) -> ?DNS_EOPTCODE_UL_BSTR;
record_key_name(dns_opt_ecs) -> ?DNS_EOPTCODE_ECS_BSTR;
record_key_name(dns_opt_cookie) -> ?DNS_EOPTCODE_COOKIE_BSTR;
record_key_name(dns_opt_ede) -> ?DNS_EOPTCODE_EDE_BSTR;
record_key_name(dns_opt_unknown) -> ~"OPT_UNKNOWN".

%% Helper to map JSON key name back to record type atom
%% Note: RRDATA records are only used internally via type_to_rrdata_tag, not for standalone parsing
-spec record_type_from_key(undefined | binary()) -> atom() | undefined.
record_type_from_key(~"message") -> dns_message;
record_type_from_key(~"query") -> dns_query;
record_type_from_key(~"rr") -> dns_rr;
record_type_from_key(~"OPT") -> dns_optrr;
record_type_from_key(~"OPT_UNKNOWN") -> dns_opt_unknown;
%% RRDATA records
record_type_from_key(?DNS_TYPE_A_BSTR) -> dns_rrdata_a;
record_type_from_key(?DNS_TYPE_AAAA_BSTR) -> dns_rrdata_aaaa;
record_type_from_key(?DNS_TYPE_AFSDB_BSTR) -> dns_rrdata_afsdb;
record_type_from_key(?DNS_TYPE_CAA_BSTR) -> dns_rrdata_caa;
record_type_from_key(?DNS_TYPE_CERT_BSTR) -> dns_rrdata_cert;
record_type_from_key(?DNS_TYPE_CNAME_BSTR) -> dns_rrdata_cname;
record_type_from_key(?DNS_TYPE_DHCID_BSTR) -> dns_rrdata_dhcid;
record_type_from_key(?DNS_TYPE_DNAME_BSTR) -> dns_rrdata_dname;
record_type_from_key(?DNS_TYPE_OPENPGPKEY_BSTR) -> dns_rrdata_openpgpkey;
record_type_from_key(?DNS_TYPE_DNSKEY_BSTR) -> dns_rrdata_dnskey;
record_type_from_key(?DNS_TYPE_CDNSKEY_BSTR) -> dns_rrdata_cdnskey;
record_type_from_key(?DNS_TYPE_DS_BSTR) -> dns_rrdata_ds;
record_type_from_key(?DNS_TYPE_CDS_BSTR) -> dns_rrdata_cds;
record_type_from_key(?DNS_TYPE_DLV_BSTR) -> dns_rrdata_dlv;
record_type_from_key(?DNS_TYPE_ZONEMD_BSTR) -> dns_rrdata_zonemd;
record_type_from_key(?DNS_TYPE_HINFO_BSTR) -> dns_rrdata_hinfo;
record_type_from_key(?DNS_TYPE_IPSECKEY_BSTR) -> dns_rrdata_ipseckey;
record_type_from_key(?DNS_TYPE_KEY_BSTR) -> dns_rrdata_key;
record_type_from_key(?DNS_TYPE_KX_BSTR) -> dns_rrdata_kx;
record_type_from_key(?DNS_TYPE_LOC_BSTR) -> dns_rrdata_loc;
record_type_from_key(?DNS_TYPE_MB_BSTR) -> dns_rrdata_mb;
record_type_from_key(?DNS_TYPE_MG_BSTR) -> dns_rrdata_mg;
record_type_from_key(?DNS_TYPE_MINFO_BSTR) -> dns_rrdata_minfo;
record_type_from_key(?DNS_TYPE_MR_BSTR) -> dns_rrdata_mr;
record_type_from_key(?DNS_TYPE_MX_BSTR) -> dns_rrdata_mx;
record_type_from_key(?DNS_TYPE_NAPTR_BSTR) -> dns_rrdata_naptr;
record_type_from_key(?DNS_TYPE_NS_BSTR) -> dns_rrdata_ns;
record_type_from_key(?DNS_TYPE_NSEC_BSTR) -> dns_rrdata_nsec;
record_type_from_key(?DNS_TYPE_NSEC3_BSTR) -> dns_rrdata_nsec3;
record_type_from_key(?DNS_TYPE_NSEC3PARAM_BSTR) -> dns_rrdata_nsec3param;
record_type_from_key(?DNS_TYPE_CSYNC_BSTR) -> dns_rrdata_csync;
record_type_from_key(?DNS_TYPE_DSYNC_BSTR) -> dns_rrdata_dsync;
record_type_from_key(?DNS_TYPE_NXT_BSTR) -> dns_rrdata_nxt;
record_type_from_key(?DNS_TYPE_PTR_BSTR) -> dns_rrdata_ptr;
record_type_from_key(?DNS_TYPE_RP_BSTR) -> dns_rrdata_rp;
record_type_from_key(?DNS_TYPE_RRSIG_BSTR) -> dns_rrdata_rrsig;
record_type_from_key(?DNS_TYPE_RT_BSTR) -> dns_rrdata_rt;
record_type_from_key(?DNS_TYPE_SOA_BSTR) -> dns_rrdata_soa;
record_type_from_key(?DNS_TYPE_SPF_BSTR) -> dns_rrdata_spf;
record_type_from_key(?DNS_TYPE_SRV_BSTR) -> dns_rrdata_srv;
record_type_from_key(?DNS_TYPE_SSHFP_BSTR) -> dns_rrdata_sshfp;
record_type_from_key(?DNS_TYPE_SVCB_BSTR) -> dns_rrdata_svcb;
record_type_from_key(?DNS_TYPE_HTTPS_BSTR) -> dns_rrdata_https;
record_type_from_key(?DNS_TYPE_TLSA_BSTR) -> dns_rrdata_tlsa;
record_type_from_key(?DNS_TYPE_SMIMEA_BSTR) -> dns_rrdata_smimea;
record_type_from_key(?DNS_TYPE_TSIG_BSTR) -> dns_rrdata_tsig;
record_type_from_key(?DNS_TYPE_TXT_BSTR) -> dns_rrdata_txt;
record_type_from_key(?DNS_TYPE_URI_BSTR) -> dns_rrdata_uri;
record_type_from_key(?DNS_TYPE_EUI48_BSTR) -> dns_rrdata_eui48;
record_type_from_key(?DNS_TYPE_EUI64_BSTR) -> dns_rrdata_eui64;
record_type_from_key(?DNS_TYPE_RESINFO_BSTR) -> dns_rrdata_resinfo;
record_type_from_key(?DNS_TYPE_WALLET_BSTR) -> dns_rrdata_wallet;
record_type_from_key(?DNS_EOPTCODE_LLQ_BSTR) -> dns_opt_llq;
record_type_from_key(?DNS_EOPTCODE_NSID_BSTR) -> dns_opt_nsid;
record_type_from_key(?DNS_EOPTCODE_OWNER_BSTR) -> dns_opt_owner;
record_type_from_key(?DNS_EOPTCODE_UL_BSTR) -> dns_opt_ul;
record_type_from_key(?DNS_EOPTCODE_ECS_BSTR) -> dns_opt_ecs;
record_type_from_key(?DNS_EOPTCODE_COOKIE_BSTR) -> dns_opt_cookie;
record_type_from_key(?DNS_EOPTCODE_EDE_BSTR) -> dns_opt_ede;
record_type_from_key(_) -> undefined.

%% Convert RRDATA record to a flat map
-spec to_map_rrdata(tuple() | binary()) -> map().
to_map_rrdata(Record) when is_tuple(Record) ->
    Tag = element(1, Record),
    Fields = record_fields(Tag),
    Values = tl(tuple_to_list(Record)),
    lists:foldl(
        fun({Field, Value}, Acc) ->
            NewValue = to_map_value(Tag, Field, Value),
            FieldBin = field_name(Tag, Field),
            Acc#{FieldBin => NewValue}
        end,
        #{},
        lists:zip(Fields, Values)
    );
to_map_rrdata(Binary) when is_binary(Binary) ->
    %% For unknown/unsupported record types, data is a raw binary
    %% Encode as base64 for JSON representation
    #{~"data" => base64:encode(Binary)}.

%% Check if a tag is an RRDATA record
%% RRDATA records must be wrapped in dns_rr
-spec is_rrdata_tag(atom()) -> boolean().
is_rrdata_tag(Tag) when is_atom(Tag) ->
    string:prefix(atom_to_list(Tag), "dns_rrdata_") =/= nomatch.

-spec field_name(atom(), atom()) -> binary().
field_name(dns_rrdata_txt, txt) -> ~"txts";
field_name(dns_rrdata_sshfp, fp_type) -> ~"fptype";
field_name(_Tag, Field) -> atom_to_binary(Field).

%% Convert binary DNS type name to type integer
-spec binary_to_dns_type(binary()) -> dns:type().
binary_to_dns_type(TypeBin) when is_binary(TypeBin) ->
    case dns_names:name_type(TypeBin) of
        undefined ->
            case string:to_integer(TypeBin) of
                {TypeNum, <<>>} when is_integer(TypeNum) -> TypeNum;
                _ -> erlang:error({unknown_type_name, TypeBin})
            end;
        Type ->
            Type
    end.

%% Convert a data map to RRDATA record based on type
-spec from_map_rrdata(dns:type(), map()) -> tuple() | binary().
from_map_rrdata(Type, DataMap) ->
    %% Try to map DNS type to RRDATA record tag
    case type_to_rrdata_tag(Type) of
        undefined ->
            %% Unknown type - decode base64 binary if present
            case DataMap of
                #{~"data" := Base64Data} ->
                    base64:decode(Base64Data);
                _ ->
                    erlang:error({unknown_type_cannot_convert_to_rrdata, Type})
            end;
        Tag when is_atom(Tag) ->
            %% Known type - convert to record
            Fields = record_fields(Tag),
            Values = [
                from_map_field(
                    Tag, Field, maps:get(field_name(Tag, Field), DataMap, undefined)
                )
             || Field <- Fields
            ],
            list_to_tuple([Tag | Values])
    end.

%% Convert DNS type to RRDATA record tag
-spec type_to_rrdata_tag(dns:type()) -> atom() | no_return().
type_to_rrdata_tag(Type) when is_integer(Type) ->
    TypeName = dns_names:type_name(Type),
    record_type_from_key(TypeName).

%% Helper to get record fields (needed because record_info requires literal atoms)
-spec record_fields(atom()) -> [atom()].
record_fields(dns_message) -> record_info(fields, dns_message);
record_fields(dns_query) -> record_info(fields, dns_query);
record_fields(dns_rr) -> record_info(fields, dns_rr);
record_fields(dns_rrdata_a) -> record_info(fields, dns_rrdata_a);
record_fields(dns_rrdata_afsdb) -> record_info(fields, dns_rrdata_afsdb);
record_fields(dns_rrdata_aaaa) -> record_info(fields, dns_rrdata_aaaa);
record_fields(dns_rrdata_caa) -> record_info(fields, dns_rrdata_caa);
record_fields(dns_rrdata_cname) -> record_info(fields, dns_rrdata_cname);
record_fields(dns_rrdata_dhcid) -> record_info(fields, dns_rrdata_dhcid);
record_fields(dns_rrdata_dname) -> record_info(fields, dns_rrdata_dname);
record_fields(dns_rrdata_openpgpkey) -> record_info(fields, dns_rrdata_openpgpkey);
record_fields(dns_rrdata_dnskey) -> record_info(fields, dns_rrdata_dnskey);
record_fields(dns_rrdata_cdnskey) -> record_info(fields, dns_rrdata_cdnskey);
record_fields(dns_rrdata_key) -> record_info(fields, dns_rrdata_key);
record_fields(dns_rrdata_mx) -> record_info(fields, dns_rrdata_mx);
record_fields(dns_rrdata_kx) -> record_info(fields, dns_rrdata_kx);
record_fields(dns_rrdata_ns) -> record_info(fields, dns_rrdata_ns);
record_fields(dns_rrdata_ptr) -> record_info(fields, dns_rrdata_ptr);
record_fields(dns_rrdata_rrsig) -> record_info(fields, dns_rrdata_rrsig);
record_fields(dns_rrdata_soa) -> record_info(fields, dns_rrdata_soa);
record_fields(dns_rrdata_srv) -> record_info(fields, dns_rrdata_srv);
record_fields(dns_rrdata_txt) -> record_info(fields, dns_rrdata_txt);
record_fields(dns_rrdata_hinfo) -> record_info(fields, dns_rrdata_hinfo);
record_fields(dns_rrdata_eui48) -> record_info(fields, dns_rrdata_eui48);
record_fields(dns_rrdata_eui64) -> record_info(fields, dns_rrdata_eui64);
record_fields(dns_rrdata_ipseckey) -> record_info(fields, dns_rrdata_ipseckey);
record_fields(dns_rrdata_loc) -> record_info(fields, dns_rrdata_loc);
record_fields(dns_rrdata_mb) -> record_info(fields, dns_rrdata_mb);
record_fields(dns_rrdata_mg) -> record_info(fields, dns_rrdata_mg);
record_fields(dns_rrdata_minfo) -> record_info(fields, dns_rrdata_minfo);
record_fields(dns_rrdata_mr) -> record_info(fields, dns_rrdata_mr);
record_fields(dns_rrdata_nsec) -> record_info(fields, dns_rrdata_nsec);
record_fields(dns_rrdata_nsec3) -> record_info(fields, dns_rrdata_nsec3);
record_fields(dns_rrdata_nsec3param) -> record_info(fields, dns_rrdata_nsec3param);
record_fields(dns_rrdata_csync) -> record_info(fields, dns_rrdata_csync);
record_fields(dns_rrdata_dsync) -> record_info(fields, dns_rrdata_dsync);
record_fields(dns_rrdata_tlsa) -> record_info(fields, dns_rrdata_tlsa);
record_fields(dns_rrdata_smimea) -> record_info(fields, dns_rrdata_smimea);
record_fields(dns_rrdata_nxt) -> record_info(fields, dns_rrdata_nxt);
record_fields(dns_rrdata_rp) -> record_info(fields, dns_rrdata_rp);
record_fields(dns_rrdata_rt) -> record_info(fields, dns_rrdata_rt);
record_fields(dns_rrdata_spf) -> record_info(fields, dns_rrdata_spf);
record_fields(dns_rrdata_sshfp) -> record_info(fields, dns_rrdata_sshfp);
record_fields(dns_rrdata_svcb) -> record_info(fields, dns_rrdata_svcb);
record_fields(dns_rrdata_https) -> record_info(fields, dns_rrdata_https);
record_fields(dns_rrdata_naptr) -> record_info(fields, dns_rrdata_naptr);
record_fields(dns_rrdata_ds) -> record_info(fields, dns_rrdata_ds);
record_fields(dns_rrdata_cds) -> record_info(fields, dns_rrdata_cds);
record_fields(dns_rrdata_dlv) -> record_info(fields, dns_rrdata_dlv);
record_fields(dns_rrdata_zonemd) -> record_info(fields, dns_rrdata_zonemd);
record_fields(dns_rrdata_cert) -> record_info(fields, dns_rrdata_cert);
record_fields(dns_rrdata_tsig) -> record_info(fields, dns_rrdata_tsig);
record_fields(dns_rrdata_uri) -> record_info(fields, dns_rrdata_uri);
record_fields(dns_rrdata_resinfo) -> record_info(fields, dns_rrdata_resinfo);
record_fields(dns_rrdata_wallet) -> record_info(fields, dns_rrdata_wallet);
record_fields(dns_optrr) -> record_info(fields, dns_optrr);
record_fields(dns_opt_llq) -> record_info(fields, dns_opt_llq);
record_fields(dns_opt_nsid) -> record_info(fields, dns_opt_nsid);
record_fields(dns_opt_owner) -> record_info(fields, dns_opt_owner);
record_fields(dns_opt_ul) -> record_info(fields, dns_opt_ul);
record_fields(dns_opt_ecs) -> record_info(fields, dns_opt_ecs);
record_fields(dns_opt_cookie) -> record_info(fields, dns_opt_cookie);
record_fields(dns_opt_ede) -> record_info(fields, dns_opt_ede);
record_fields(dns_opt_unknown) -> record_info(fields, dns_opt_unknown);
record_fields(Other) -> erlang:error({unknown_record_type, Other}).

to_map_value(dns_message, questions, Value) when is_list(Value) ->
    [to_map(V) || V <- Value];
to_map_value(dns_message, answers, Value) when is_list(Value) ->
    [to_map(V) || V <- Value];
to_map_value(dns_message, authority, Value) when is_list(Value) ->
    [to_map(V) || V <- Value];
to_map_value(dns_message, additional, Value) when is_list(Value) ->
    [to_map(V) || V <- Value];
to_map_value(dns_optrr, data, Value) when is_list(Value) ->
    [to_map(V) || V <- Value];
to_map_value(Tag, ip, Value) when
    (Tag =:= dns_rrdata_a orelse Tag =:= dns_rrdata_aaaa) andalso is_tuple(Value)
->
    list_to_binary(inet:ntoa(Value));
to_map_value(Tag, public_key, Value) when
    is_list(Value) andalso (dns_rrdata_dnskey =:= Tag orelse dns_rrdata_cdnskey =:= Tag)
->
    base64:encode(to_map_dnskey_publickey(Value));
to_map_value(dns_rrdata_key, public_key, Value) when is_binary(Value) ->
    base64:encode(iolist_to_binary(Value));
to_map_value(Tag, salt, Value) when
    (Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param) andalso is_binary(Value)
->
    case Value of
        <<>> -> ~"-";
        _ -> binary:encode_hex(Value)
    end;
to_map_value(dns_rrdata_nsec3, hash, Value) when is_binary(Value) ->
    base32:encode(Value, [hex]);
to_map_value(dns_rrdata_ipseckey, gateway, Value) when is_tuple(Value) ->
    list_to_binary(inet:ntoa(Value));
to_map_value(dns_rrdata_ipseckey, gateway, Value) when is_binary(Value) ->
    Value;
to_map_value(Tag, svc_params, Value) when
    (Tag =:= dns_rrdata_svcb orelse Tag =:= dns_rrdata_https) andalso is_map(Value)
->
    dns_svcb_params:to_json(Value);
to_map_value(Tag, Field, Value) when is_binary(Value) ->
    encode_field(Tag, Field, Value);
to_map_value(_Tag, _Field, Value) ->
    Value.

%% Encode binary fields based on tag and field name
-spec encode_field(atom(), atom(), binary()) -> binary().
encode_field(dns_rrdata_cert, cert, Value) -> base64:encode(Value);
encode_field(dns_rrdata_dhcid, data, Value) -> base64:encode(Value);
encode_field(dns_rrdata_openpgpkey, data, Value) -> base64:encode(Value);
encode_field(dns_rrdata_dnskey, public_key, Value) -> base64:encode(Value);
encode_field(dns_rrdata_cdnskey, public_key, Value) -> base64:encode(Value);
encode_field(dns_rrdata_ipseckey, public_key, Value) -> base64:encode(Value);
encode_field(dns_rrdata_rrsig, signature, Value) -> base64:encode(Value);
encode_field(dns_rrdata_smimea, certificate, Value) -> base64:encode(Value);
encode_field(dns_rrdata_tsig, mac, Value) -> base64:encode(Value);
encode_field(dns_rrdata_wallet, data, Value) -> base64:encode(Value);
encode_field(dns_rrdata_ds, digest, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_cds, digest, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_dlv, digest, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_zonemd, hash, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_sshfp, fp, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_eui48, address, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_eui64, address, Value) -> binary:encode_hex(Value);
encode_field(dns_rrdata_tsig, other, Value) -> binary:encode_hex(Value);
encode_field(dns_opt_nsid, data, Value) -> binary:encode_hex(Value);
encode_field(dns_opt_owner, _Field, Value) -> binary:encode_hex(Value);
encode_field(dns_opt_ecs, _Field, Value) -> binary:encode_hex(Value);
encode_field(dns_opt_unknown, bin, Value) -> binary:encode_hex(Value);
encode_field(_Tag, _Field, Value) -> Value.

%% Convert JSON-friendly values back to record field values
from_map_field(dns_message, questions, Value) when is_list(Value) ->
    [from_map(V) || V <- Value];
from_map_field(dns_message, answers, Value) when is_list(Value) ->
    [from_map(V) || V <- Value];
from_map_field(dns_message, authority, Value) when is_list(Value) ->
    [from_map(V) || V <- Value];
from_map_field(dns_message, additional, Value) when is_list(Value) ->
    [from_map(V) || V <- Value];
from_map_field(dns_optrr, data, Value) when is_list(Value) ->
    [from_map(V) || V <- Value];
from_map_field(dns_rrdata_a, ip, Value) when is_binary(Value) ->
    case inet:parse_ipv4strict_address(binary_to_list(Value)) of
        {ok, Tuple} -> Tuple;
        {error, _} -> erlang:error({invalid_ip, Value})
    end;
from_map_field(dns_rrdata_aaaa, ip, Value) when is_binary(Value) ->
    case inet:parse_ipv6strict_address(binary_to_list(Value)) of
        {ok, Tuple} -> Tuple;
        {error, _} -> erlang:error({invalid_ip, Value})
    end;
from_map_field(dns_rrdata_dnskey, public_key, Value) when is_binary(Value) ->
    from_map_dnskey_publickey(base64:decode(Value));
from_map_field(dns_rrdata_cdnskey, public_key, Value) when is_binary(Value) ->
    from_map_dnskey_publickey(base64:decode(Value));
from_map_field(Tag, salt, ~"-") when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    <<>>;
from_map_field(dns_rrdata_nsec3, hash, Value) when is_binary(Value) ->
    base32:decode(Value, [hex]);
from_map_field(dns_rrdata_ipseckey, gateway, Value) when is_binary(Value) ->
    case inet:parse_address(binary_to_list(Value)) of
        {ok, Tuple} -> Tuple;
        {error, _} -> Value
    end;
from_map_field(Tag, svc_params, Value) when
    (Tag =:= dns_rrdata_svcb orelse Tag =:= dns_rrdata_https) andalso is_map(Value)
->
    dns_svcb_params:from_json(Value);
from_map_field(Tag, Field, Value) when is_binary(Value) ->
    decode_field(Tag, Field, Value);
from_map_field(_Tag, _Field, Value) ->
    Value.

%% Decode binary fields based on tag and field name
-spec decode_field(atom(), atom(), binary()) -> binary() | [integer()].
decode_field(dns_rrdata_cert, cert, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_dhcid, data, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_openpgpkey, data, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_key, public_key, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_ipseckey, public_key, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_rrsig, signature, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_smimea, certificate, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_tsig, mac, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_wallet, data, Value) ->
    base64:decode(Value);
decode_field(dns_rrdata_ds, digest, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_cds, digest, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_dlv, digest, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_zonemd, hash, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_sshfp, fp, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_eui48, address, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_eui64, address, Value) ->
    binary:decode_hex(Value);
decode_field(dns_rrdata_tsig, other, Value) ->
    binary:decode_hex(Value);
decode_field(Tag, salt, Value) when
    Tag =:= dns_rrdata_nsec3 orelse Tag =:= dns_rrdata_nsec3param
->
    binary:decode_hex(Value);
decode_field(dns_opt_nsid, data, Value) ->
    binary:decode_hex(Value);
decode_field(dns_opt_owner, _Field, Value) ->
    binary:decode_hex(Value);
decode_field(dns_opt_ecs, _Field, Value) ->
    binary:decode_hex(Value);
decode_field(dns_opt_unknown, bin, Value) ->
    binary:decode_hex(Value);
decode_field(_Tag, _Field, Value) ->
    Value.

%% Helper to decode DNSKEY public key (handles both binary and list formats)
-spec from_map_dnskey_publickey(binary()) -> binary() | [integer()].
from_map_dnskey_publickey(<<>>) ->
    [];
from_map_dnskey_publickey(<<L:32, I:L/unit:8, Rest/binary>>) ->
    [I | from_map_dnskey_publickey(Rest)];
from_map_dnskey_publickey(PK) ->
    PK.

%% Handle list of integers (RSA key components)
-spec to_map_dnskey_publickey([integer()]) -> binary().
to_map_dnskey_publickey(Ints) ->
    lists:foldl(
        fun(I, Acc) ->
            BI = binary:encode_unsigned(I),
            <<Acc/binary, (byte_size(BI)):32, BI/binary>>
        end,
        <<>>,
        Ints
    ).
