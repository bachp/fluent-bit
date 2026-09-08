/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Map the records produced by Fluent Bit's built-in syslog-rfc5424 parser onto
 * the OpenTelemetry logs data model.
 */

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <cfl/cfl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SO_SYSLOG_PREFIX     "syslog."
#define SO_SYSLOG_PREFIX_LEN (sizeof(SO_SYSLOG_PREFIX) - 1)
#define SO_SIG_SEP           '\x1f'

struct so_ctx {
    flb_sds_t body_key;
    struct flb_processor_instance *ins;
};

struct so_pending {
    struct flb_mp_chunk_record *record;
    struct cfl_kvlist *resource;
    cfl_sds_t signature;
    struct cfl_list _head;
};

static const struct {
    int number;
    const char *text;
} so_severity[] = {
    {21, "emerg"},
    {19, "alert"},
    {18, "crit"},
    {17, "err"},
    {13, "warning"},
    {10, "notice"},
    { 9, "info"},
    { 5, "debug"}
};

static int so_key_equals(const char *key, size_t key_len, const char *expected)
{
    size_t expected_len;

    expected_len = strlen(expected);

    return key_len == expected_len &&
           memcmp(key, expected, expected_len) == 0;
}

static int so_is_nil(struct cfl_variant *value)
{
    return value->type == CFL_VARIANT_STRING &&
           cfl_variant_size_get(value) == 1 &&
           value->data.as_string[0] == '-';
}

static int so_is_sd_name_character(char character)
{
    unsigned char value;

    value = (unsigned char) character;

    return value >= 33 && value <= 126 &&
           character != '=' && character != ']' && character != '"';
}

static int so_parse_priority(struct cfl_variant *value, int *priority)
{
    int i;
    int result;
    size_t len;
    const char *text;

    if (value->type != CFL_VARIANT_STRING) {
        return FLB_FALSE;
    }

    text = value->data.as_string;
    len = cfl_variant_size_get(value);
    if (len == 0 || len > 3 || (len > 1 && text[0] == '0')) {
        return FLB_FALSE;
    }

    result = 0;
    for (i = 0; i < len; i++) {
        if (text[i] < '0' || text[i] > '9') {
            return FLB_FALSE;
        }
        result = result * 10 + (text[i] - '0');
    }

    if (result > 191) {
        return FLB_FALSE;
    }

    *priority = result;

    return FLB_TRUE;
}

static struct cfl_variant *so_variant_clone(struct cfl_variant *value);

static struct cfl_array *so_array_clone(struct cfl_array *array)
{
    size_t index;
    struct cfl_array *copy;
    struct cfl_variant *entry;

    copy = cfl_array_create(array->entry_count > 0 ? array->entry_count : 1);
    if (!copy) {
        return NULL;
    }

    for (index = 0; index < array->entry_count; index++) {
        entry = so_variant_clone(array->entries[index]);
        if (!entry || cfl_array_append(copy, entry) != 0) {
            if (entry) {
                cfl_variant_destroy(entry);
            }
            cfl_array_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

static struct cfl_kvlist *so_kvlist_clone(struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_kvlist *copy;
    struct cfl_kvpair *pair;
    struct cfl_variant *value;

    copy = cfl_kvlist_create();
    if (!copy) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        value = so_variant_clone(pair->val);
        if (!value ||
            cfl_kvlist_insert_s(copy, pair->key, cfl_sds_len(pair->key),
                                value) != 0) {
            if (value) {
                cfl_variant_destroy(value);
            }
            cfl_kvlist_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

static struct cfl_variant *so_variant_clone(struct cfl_variant *value)
{
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *copy;

    switch (value->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s(value->data.as_string,
                                                cfl_variant_size_get(value),
                                                CFL_FALSE);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes(value->data.as_bytes,
                                             cfl_variant_size_get(value),
                                             CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(value->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(value->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64(value->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(value->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null();
    case CFL_VARIANT_ARRAY:
        array = so_array_clone(value->data.as_array);
        if (!array) {
            return NULL;
        }
        copy = cfl_variant_create_from_array(array);
        if (!copy) {
            cfl_array_destroy(array);
        }
        return copy;
    case CFL_VARIANT_KVLIST:
        kvlist = so_kvlist_clone(value->data.as_kvlist);
        if (!kvlist) {
            return NULL;
        }
        copy = cfl_variant_create_from_kvlist(kvlist);
        if (!copy) {
            cfl_kvlist_destroy(kvlist);
        }
        return copy;
    default:
        return NULL;
    }
}

static struct cfl_kvlist *so_get_or_create_kvlist(struct cfl_kvlist *parent,
                                                  const char *key)
{
    struct cfl_kvlist *kvlist;
    struct cfl_variant *value;

    value = cfl_kvlist_fetch_s(parent, (char *) key, strlen(key));
    if (value) {
        if (value->type != CFL_VARIANT_KVLIST) {
            return NULL;
        }
        return value->data.as_kvlist;
    }

    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        return NULL;
    }

    if (cfl_kvlist_insert_kvlist_s(parent, (char *) key, strlen(key),
                                   kvlist) != 0) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }

    return kvlist;
}

static void so_kvlist_clear(struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *pair;

    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        cfl_kvpair_destroy(pair);
    }
}

static int so_insert_copy(struct cfl_kvlist *target, const char *key,
                          size_t key_len, struct cfl_variant *value)
{
    struct cfl_variant *copy;

    copy = so_variant_clone(value);
    if (!copy) {
        return -1;
    }

    if (cfl_kvlist_insert_s(target, (char *) key, key_len, copy) != 0) {
        cfl_variant_destroy(copy);
        return -1;
    }

    return 0;
}

/*
 * Preserve repeated structured-data parameters as arrays. RFC 5424 explicitly
 * permits origin.ip to occur more than once.
 */
static int so_insert_string(struct cfl_kvlist *target, const char *key,
                            size_t key_len, const char *value, size_t value_len)
{
    struct cfl_array *array;
    struct cfl_variant *current;
    struct cfl_variant *replacement;

    current = cfl_kvlist_fetch_case_s(target, (char *) key, key_len);
    if (!current) {
        return cfl_kvlist_insert_string_s(target, (char *) key, key_len,
                                          (char *) value, value_len, CFL_FALSE);
    }

    if (current->type == CFL_VARIANT_ARRAY) {
        return cfl_array_append_string_s(current->data.as_array, (char *) value,
                                         value_len, CFL_FALSE);
    }

    if (current->type != CFL_VARIANT_STRING) {
        return -1;
    }

    array = cfl_array_create(2);
    if (!array) {
        return -1;
    }

    if (cfl_array_append_string_s(array, current->data.as_string,
                                  cfl_variant_size_get(current),
                                  CFL_FALSE) != 0 ||
        cfl_array_append_string_s(array, (char *) value, value_len,
                                  CFL_FALSE) != 0) {
        cfl_array_destroy(array);
        return -1;
    }

    replacement = cfl_variant_create_from_array(array);
    if (!replacement) {
        cfl_array_destroy(array);
        return -1;
    }

    cfl_kvlist_remove_ex(target, (char *) key,
                         CFL_KVLIST_MATCH_CASE_SENSITIVE);
    if (cfl_kvlist_insert_s(target, (char *) key, key_len, replacement) != 0) {
        cfl_variant_destroy(replacement);
        return -1;
    }

    return 0;
}

static int so_insert_prefixed_copy(struct cfl_kvlist *target, const char *name,
                                   size_t name_len, struct cfl_variant *value)
{
    int result;
    char *key;

    key = flb_malloc(SO_SYSLOG_PREFIX_LEN + name_len + 1);
    if (!key) {
        flb_errno();
        return -1;
    }

    memcpy(key, SO_SYSLOG_PREFIX, SO_SYSLOG_PREFIX_LEN);
    memcpy(key + SO_SYSLOG_PREFIX_LEN, name, name_len);
    key[SO_SYSLOG_PREFIX_LEN + name_len] = '\0';

    result = so_insert_copy(target, key, SO_SYSLOG_PREFIX_LEN + name_len,
                            value);
    flb_free(key);

    return result;
}

static int so_insert_sd_parameter(struct cfl_kvlist *attributes,
                                  struct cfl_kvlist *resource,
                                  const char *sd_id, size_t sd_id_len,
                                  const char *name, size_t name_len,
                                  const char *value, size_t value_len)
{
    int result;
    size_t key_len;
    char *key;

    if (so_key_equals(sd_id, sd_id_len, "origin") == FLB_TRUE &&
        so_key_equals(name, name_len, "swVersion") == FLB_TRUE) {
        return so_insert_string(resource, "service.version", 15,
                                value, value_len);
    }

    if (so_key_equals(sd_id, sd_id_len, "origin") == FLB_TRUE &&
        so_key_equals(name, name_len, "ip") == FLB_TRUE) {
        return so_insert_string(attributes, "client.address", 14,
                                value, value_len);
    }

    key_len = SO_SYSLOG_PREFIX_LEN + sd_id_len + 1 + name_len;
    key = flb_malloc(key_len + 1);
    if (!key) {
        flb_errno();
        return -1;
    }

    memcpy(key, SO_SYSLOG_PREFIX, SO_SYSLOG_PREFIX_LEN);
    memcpy(key + SO_SYSLOG_PREFIX_LEN, sd_id, sd_id_len);
    key[SO_SYSLOG_PREFIX_LEN + sd_id_len] = '.';
    memcpy(key + SO_SYSLOG_PREFIX_LEN + sd_id_len + 1, name, name_len);
    key[key_len] = '\0';

    result = so_insert_string(attributes, key, key_len, value, value_len);
    flb_free(key);

    return result;
}

static int so_unescape_parameter(const char *input, size_t input_len,
                                 flb_sds_t *output)
{
    size_t index;
    flb_sds_t result;
    flb_sds_t tmp;

    result = flb_sds_create_size(input_len);
    if (!result) {
        return -1;
    }

    for (index = 0; index < input_len; index++) {
        if (input[index] == '\\' && index + 1 < input_len &&
            (input[index + 1] == '"' || input[index + 1] == '\\' ||
             input[index + 1] == ']')) {
            index++;
        }

        tmp = flb_sds_cat(result, &input[index], 1);
        if (!tmp) {
            flb_sds_destroy(result);
            return -1;
        }
        result = tmp;
    }

    *output = result;

    return 0;
}

/*
 * Parse RFC 5424 STRUCTURED-DATA. On malformed input, return FLB_FALSE so the
 * caller can retain the original value instead of losing it.
 */
static int so_parse_structured_data_into(struct cfl_kvlist *attributes,
                                         struct cfl_kvlist *resource,
                                         const char *input, size_t input_len)
{
    size_t index;
    size_t name_end;
    size_t name_start;
    size_t sd_id_len;
    size_t sd_id_start;
    size_t value_start;
    flb_sds_t value;

    if (input_len == 1 && input[0] == '-') {
        return FLB_TRUE;
    }

    index = 0;
    while (index < input_len) {
        if (input[index] != '[') {
            return FLB_FALSE;
        }
        index++;
        sd_id_start = index;

        while (index < input_len && input[index] != ' ' && input[index] != ']') {
            if (so_is_sd_name_character(input[index]) == FLB_FALSE) {
                return FLB_FALSE;
            }
            index++;
        }
        if (index == sd_id_start || index - sd_id_start > 32) {
            return FLB_FALSE;
        }
        sd_id_len = index - sd_id_start;

        while (index < input_len && input[index] != ']') {
            if (input[index] != ' ') {
                return FLB_FALSE;
            }
            index++;
            name_start = index;

            while (index < input_len && input[index] != '=') {
                if (so_is_sd_name_character(input[index]) == FLB_FALSE) {
                    return FLB_FALSE;
                }
                index++;
            }
            if (index == name_start || index - name_start > 32 ||
                index + 1 >= input_len || input[index + 1] != '"') {
                return FLB_FALSE;
            }

            name_end = index;
            index += 2;
            value_start = index;
            while (index < input_len) {
                if (input[index] == '\\' && index + 1 < input_len) {
                    index += 2;
                    continue;
                }
                if (input[index] == '"') {
                    break;
                }
                index++;
            }
            if (index >= input_len) {
                return FLB_FALSE;
            }

            if (so_unescape_parameter(input + value_start,
                                      index - value_start, &value) != 0) {
                return -1;
            }

            if (so_insert_sd_parameter(attributes, resource,
                                       input + sd_id_start,
                                       sd_id_len,
                                       input + name_start,
                                       name_end - name_start,
                                       value, flb_sds_len(value)) != 0) {
                flb_sds_destroy(value);
                return -1;
            }
            flb_sds_destroy(value);
            index++;
        }

        if (index >= input_len || input[index] != ']') {
            return FLB_FALSE;
        }
        index++;
    }

    return FLB_TRUE;
}

static int so_merge_parsed_values(struct cfl_kvlist *target,
                                  struct cfl_kvlist *parsed)
{
    size_t index;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *entry;

    cfl_list_foreach(head, &parsed->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair->val->type == CFL_VARIANT_STRING) {
            if (so_insert_string(target, pair->key, cfl_sds_len(pair->key),
                                 pair->val->data.as_string,
                                 cfl_variant_size_get(pair->val)) != 0) {
                return -1;
            }
            continue;
        }

        if (pair->val->type != CFL_VARIANT_ARRAY) {
            return -1;
        }

        for (index = 0; index < pair->val->data.as_array->entry_count; index++) {
            entry = pair->val->data.as_array->entries[index];
            if (entry->type != CFL_VARIANT_STRING ||
                so_insert_string(target, pair->key, cfl_sds_len(pair->key),
                                 entry->data.as_string,
                                 cfl_variant_size_get(entry)) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int so_parse_structured_data(struct cfl_kvlist *attributes,
                                    struct cfl_kvlist *resource,
                                    const char *input, size_t input_len)
{
    int result;
    struct cfl_kvlist *parsed_attributes;
    struct cfl_kvlist *parsed_resource;

    parsed_attributes = cfl_kvlist_create();
    parsed_resource = cfl_kvlist_create();
    if (!parsed_attributes || !parsed_resource) {
        if (parsed_attributes) {
            cfl_kvlist_destroy(parsed_attributes);
        }
        if (parsed_resource) {
            cfl_kvlist_destroy(parsed_resource);
        }
        return -1;
    }

    result = so_parse_structured_data_into(parsed_attributes, parsed_resource,
                                           input, input_len);
    if (result == FLB_TRUE &&
        (so_merge_parsed_values(attributes, parsed_attributes) != 0 ||
         so_merge_parsed_values(resource, parsed_resource) != 0)) {
        result = -1;
    }

    cfl_kvlist_destroy(parsed_attributes);
    cfl_kvlist_destroy(parsed_resource);

    return result;
}

static int so_signature_append(cfl_sds_t *signature,
                               const char *value, size_t value_len)
{
    cfl_sds_t tmp;

    tmp = cfl_sds_cat(*signature, value, value_len);
    if (!tmp) {
        return -1;
    }
    *signature = tmp;

    tmp = cfl_sds_cat(*signature, (const char[]) {SO_SIG_SEP}, 1);
    if (!tmp) {
        return -1;
    }
    *signature = tmp;

    return 0;
}

static cfl_sds_t so_resource_signature(struct cfl_kvlist *resource)
{
    int index;
    size_t entry_index;
    cfl_sds_t signature;
    struct cfl_variant *entry;
    struct cfl_variant *value;
    const char *keys[] = {"host.name", "service.version", NULL};

    signature = cfl_sds_create_size(64);
    if (!signature) {
        return NULL;
    }

    for (index = 0; keys[index] != NULL; index++) {
        value = cfl_kvlist_fetch_s(resource, (char *) keys[index],
                                   strlen(keys[index]));
        if (!value) {
            continue;
        }

        if (so_signature_append(&signature, keys[index],
                                strlen(keys[index])) != 0) {
            cfl_sds_destroy(signature);
            return NULL;
        }

        if (value->type == CFL_VARIANT_STRING &&
            so_signature_append(&signature, value->data.as_string,
                                cfl_variant_size_get(value)) != 0) {
            cfl_sds_destroy(signature);
            return NULL;
        }

        if (value->type == CFL_VARIANT_ARRAY) {
            for (entry_index = 0;
                 entry_index < value->data.as_array->entry_count;
                 entry_index++) {
                entry = value->data.as_array->entries[entry_index];
                if (entry->type != CFL_VARIANT_STRING ||
                    so_signature_append(&signature, entry->data.as_string,
                                        cfl_variant_size_get(entry)) != 0) {
                    cfl_sds_destroy(signature);
                    return NULL;
                }
            }
        }

        if (value->type != CFL_VARIANT_STRING &&
            value->type != CFL_VARIANT_ARRAY) {
                cfl_sds_destroy(signature);
                return NULL;
        }
    }

    return signature;
}

static int so_map_record(struct so_ctx *ctx, struct flb_mp_chunk_record *record,
                         struct cfl_kvlist **out_resource)
{
    int priority;
    int structured_result;
    size_t key_len;
    const char *key;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *body;
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *otlp;
    struct cfl_kvlist *resource;
    struct cfl_variant *message;

    priority = -1;
    message = NULL;

    if (!record->cobj_record || !record->cobj_record->variant ||
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        flb_plg_debug(ctx->ins, "skipping record with a non-map body");
        return 0;
    }

    if (!record->cobj_metadata || !record->cobj_metadata->variant ||
        record->cobj_metadata->variant->type != CFL_VARIANT_KVLIST) {
        flb_plg_error(ctx->ins, "record has no metadata map");
        return -1;
    }

    body = record->cobj_record->variant->data.as_kvlist;
    metadata = record->cobj_metadata->variant->data.as_kvlist;

    otlp = so_get_or_create_kvlist(metadata, "otlp");
    if (!otlp) {
        flb_plg_error(ctx->ins, "could not access the OTLP metadata of a record");
        return -1;
    }

    attributes = so_get_or_create_kvlist(otlp, "attributes");
    if (!attributes) {
        flb_plg_error(ctx->ins, "could not access the OTLP attributes of a record");
        return -1;
    }

    resource = cfl_kvlist_create();
    if (!resource) {
        flb_errno();
        return -1;
    }

    if (cfl_kvlist_insert_int64_s(attributes, "syslog.version", 14, 1) != 0) {
        goto failure;
    }

    cfl_list_foreach(head, &body->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        key = pair->key;
        key_len = cfl_sds_len(pair->key);

        if (so_key_equals(key, key_len, "message") == FLB_TRUE) {
            message = pair->val;
            continue;
        }

        if (so_key_equals(key, key_len, "pri") == FLB_TRUE) {
            if (so_parse_priority(pair->val, &priority) == FLB_FALSE) {
                if (so_insert_prefixed_copy(attributes, "priority", 8,
                                            pair->val) != 0) {
                    goto failure;
                }
            }
            continue;
        }

        /* The parser already used this field to set the event timestamp. */
        if (so_key_equals(key, key_len, "time") == FLB_TRUE) {
            continue;
        }

        if (so_key_equals(key, key_len, "host") == FLB_TRUE) {
            if (so_is_nil(pair->val) == FLB_FALSE &&
                so_insert_copy(resource, "host.name", 9, pair->val) != 0) {
                goto failure;
            }
            continue;
        }

        if (so_key_equals(key, key_len, "ident") == FLB_TRUE) {
            if (so_is_nil(pair->val) == FLB_FALSE &&
                so_insert_copy(attributes, "syslog.identifier", 17,
                               pair->val) != 0) {
                goto failure;
            }
            continue;
        }

        if (so_key_equals(key, key_len, "pid") == FLB_TRUE) {
            if (so_is_nil(pair->val) == FLB_FALSE &&
                so_insert_copy(attributes, "syslog.procid", 13,
                               pair->val) != 0) {
                goto failure;
            }
            continue;
        }

        if (so_key_equals(key, key_len, "msgid") == FLB_TRUE) {
            if (so_is_nil(pair->val) == FLB_FALSE &&
                so_insert_copy(attributes, "syslog.msg.id", 13,
                               pair->val) != 0) {
                goto failure;
            }
            continue;
        }

        if (so_key_equals(key, key_len, "extradata") == FLB_TRUE) {
            if (pair->val->type != CFL_VARIANT_STRING) {
                if (so_insert_prefixed_copy(attributes, "structured_data", 15,
                                            pair->val) != 0) {
                    goto failure;
                }
                continue;
            }

            structured_result = so_parse_structured_data(
                attributes, resource, pair->val->data.as_string,
                cfl_variant_size_get(pair->val));
            if (structured_result < 0) {
                goto failure;
            }
            if (structured_result == FLB_FALSE &&
                so_insert_prefixed_copy(attributes, "structured_data", 15,
                                        pair->val) != 0) {
                goto failure;
            }
            continue;
        }

        /* Preserve fields added by the input or a preceding processor. */
        if (so_insert_copy(attributes, key, key_len, pair->val) != 0) {
            goto failure;
        }
    }

    if (priority >= 0) {
        if (cfl_kvlist_insert_int64_s(attributes, "syslog.facility.code", 20,
                                      priority / 8) != 0 ||
            cfl_kvlist_insert_int64_s(otlp, "severity_number", 15,
                                      so_severity[priority % 8].number) != 0 ||
            cfl_kvlist_insert_string_s(otlp, "severity_text", 13,
                                       (char *) so_severity[priority % 8].text,
                                       strlen(so_severity[priority % 8].text),
                                       CFL_FALSE) != 0) {
            goto failure;
        }
    }

    if (message) {
        message = so_variant_clone(message);
        if (!message) {
            goto failure;
        }
    }

    so_kvlist_clear(body);

    if (message &&
        cfl_kvlist_insert_s(body, ctx->body_key, flb_sds_len(ctx->body_key),
                            message) != 0) {
        cfl_variant_destroy(message);
        goto failure;
    }

    record->modified = FLB_TRUE;
    *out_resource = resource;

    return 0;

failure:
    flb_plg_error(ctx->ins, "could not map syslog record");
    cfl_kvlist_destroy(resource);

    return -1;
}

static struct flb_mp_chunk_record *so_group_start(struct cfl_list *list,
                                                  struct flb_mp_chunk_record *position,
                                                  struct cfl_kvlist *resource)
{
    struct cfl_kvlist *group;
    struct cfl_kvlist *meta;
    struct cfl_kvlist *resource_wrapper;
    struct cfl_kvlist *scope;
    struct cfl_object *cobj_meta;
    struct cfl_object *cobj_record;
    struct flb_mp_chunk_record *record;
    struct flb_time timestamp;

    group = NULL;
    meta = NULL;
    resource_wrapper = NULL;
    scope = NULL;
    cobj_meta = NULL;
    cobj_record = NULL;
    record = NULL;

    meta = cfl_kvlist_create();
    if (!meta ||
        cfl_kvlist_insert_string(meta, "schema", "otlp") != 0 ||
        cfl_kvlist_insert_int64(meta, "resource_id", 0) != 0 ||
        cfl_kvlist_insert_int64(meta, "scope_id", 0) != 0) {
        goto failure;
    }

    group = cfl_kvlist_create();
    resource_wrapper = cfl_kvlist_create();
    scope = cfl_kvlist_create();
    if (!group || !resource_wrapper || !scope) {
        goto failure;
    }

    if (cfl_kvlist_insert_kvlist_s(resource_wrapper, "attributes", 10,
                                   resource) != 0) {
        goto failure;
    }
    resource = NULL;

    if (cfl_kvlist_insert_kvlist(group, "resource", resource_wrapper) != 0) {
        goto failure;
    }
    resource_wrapper = NULL;

    if (cfl_kvlist_insert_kvlist(group, "scope", scope) != 0) {
        goto failure;
    }
    scope = NULL;

    cobj_meta = cfl_object_create();
    cobj_record = cfl_object_create();
    if (!cobj_meta || !cobj_record ||
        cfl_object_set(cobj_meta, CFL_OBJECT_KVLIST, meta) != 0 ||
        cfl_object_set(cobj_record, CFL_OBJECT_KVLIST, group) != 0) {
        goto failure;
    }
    meta = NULL;
    group = NULL;

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        goto failure;
    }

    flb_time_set(&timestamp, FLB_LOG_EVENT_GROUP_START, 0);
    flb_time_copy(&record->event.timestamp, &timestamp);
    record->modified = FLB_TRUE;
    record->cobj_metadata = cobj_meta;
    record->cobj_record = cobj_record;

    cfl_list_add_before(&record->_head, &position->_head, list);

    return record;

failure:
    if (scope) {
        cfl_kvlist_destroy(scope);
    }
    if (resource_wrapper) {
        cfl_kvlist_destroy(resource_wrapper);
    }
    if (group) {
        cfl_kvlist_destroy(group);
    }
    if (meta) {
        cfl_kvlist_destroy(meta);
    }
    if (cobj_meta) {
        cfl_object_destroy(cobj_meta);
    }
    if (cobj_record) {
        cfl_object_destroy(cobj_record);
    }

    return NULL;
}

static int so_group_end(struct cfl_list *list,
                        struct flb_mp_chunk_record *position)
{
    struct flb_mp_chunk_record *record;
    struct flb_time timestamp;

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        return -1;
    }

    flb_time_set(&timestamp, FLB_LOG_EVENT_GROUP_END, 0);
    flb_time_copy(&record->event.timestamp, &timestamp);
    record->modified = FLB_TRUE;
    record->cobj_metadata = NULL;
    record->cobj_record = NULL;

    cfl_list_add_before(&record->_head, position->_head.next, list);

    return 0;
}

static int so_group_merge(struct flb_mp_chunk_record *group,
                          struct cfl_kvlist *resource)
{
    struct cfl_list *head;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *wrapper;
    struct cfl_kvpair *pair;
    struct cfl_variant *value;

    if (!group->cobj_record || !group->cobj_record->variant ||
        group->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    wrapper = so_get_or_create_kvlist(
        group->cobj_record->variant->data.as_kvlist, "resource");
    if (!wrapper) {
        return -1;
    }

    attributes = so_get_or_create_kvlist(wrapper, "attributes");
    if (!attributes) {
        return -1;
    }

    cfl_list_foreach(head, &resource->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        cfl_kvlist_remove(attributes, pair->key);

        value = so_variant_clone(pair->val);
        if (!value ||
            cfl_kvlist_insert_s(attributes, pair->key,
                                cfl_sds_len(pair->key), value) != 0) {
            if (value) {
                cfl_variant_destroy(value);
            }
            return -1;
        }
    }

    group->modified = FLB_TRUE;

    return 0;
}

static void so_pending_destroy(struct cfl_list *pending)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct so_pending *entry;

    cfl_list_foreach_safe(head, tmp, pending) {
        entry = cfl_list_entry(head, struct so_pending, _head);
        cfl_list_del(&entry->_head);

        if (entry->resource) {
            cfl_kvlist_destroy(entry->resource);
        }
        if (entry->signature) {
            cfl_sds_destroy(entry->signature);
        }
        flb_free(entry);
    }
}

static int so_build_groups(struct so_ctx *ctx,
                           struct flb_mp_chunk_cobj *chunk_cobj,
                           struct cfl_list *pending)
{
    struct cfl_list *head;
    struct so_pending *entry;
    struct so_pending *previous;
    struct so_pending *run_start;

    previous = NULL;
    run_start = NULL;

    cfl_list_foreach(head, pending) {
        entry = cfl_list_entry(head, struct so_pending, _head);

        if (run_start &&
            cfl_sds_len(run_start->signature) == cfl_sds_len(entry->signature) &&
            memcmp(run_start->signature, entry->signature,
                   cfl_sds_len(entry->signature)) == 0) {
            previous = entry;
            continue;
        }

        if (previous && so_group_end(&chunk_cobj->records,
                                     previous->record) != 0) {
            flb_plg_error(ctx->ins, "could not create a group end record");
            return -1;
        }

        if (!so_group_start(&chunk_cobj->records, entry->record,
                            entry->resource)) {
            flb_plg_error(ctx->ins, "could not create a group start record");
            return -1;
        }
        entry->resource = NULL;
        run_start = entry;
        previous = entry;
    }

    if (previous && so_group_end(&chunk_cobj->records, previous->record) != 0) {
        flb_plg_error(ctx->ins, "could not create a group end record");
        return -1;
    }

    return 0;
}

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    struct so_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct so_ctx));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }
    ctx->ins = ins;

    if (flb_processor_instance_config_map_set(ins, (void *) ctx) == -1) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (!ctx->body_key || flb_sds_len(ctx->body_key) == 0) {
        flb_plg_error(ins, "'body_key' cannot be empty");
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ins->context = ctx;

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct so_ctx *ctx;

    ctx = data;
    if (ctx) {
        flb_free(ctx);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int record_type;
    int result;
    struct cfl_list pending;
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct flb_mp_chunk_record *group;
    struct flb_mp_chunk_record *record;
    struct so_ctx *ctx;
    struct so_pending *entry;
    struct cfl_kvlist *resource;

    chunk_cobj = chunk_data;
    ctx = ins->context;
    group = NULL;
    cfl_list_init(&pending);

    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) ==
           FLB_MP_CHUNK_RECORD_OK) {
        if (flb_log_event_decoder_get_record_type(&record->event,
                                                  &record_type) != 0) {
            flb_plg_error(ins, "record has invalid event type");
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group = record;
            continue;
        }
        if (record_type == FLB_LOG_EVENT_GROUP_END) {
            group = NULL;
            continue;
        }
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }

        resource = NULL;
        if (so_map_record(ctx, record, &resource) != 0) {
            goto failure;
        }
        if (!resource) {
            continue;
        }

        if (group) {
            result = so_group_merge(group, resource);
            cfl_kvlist_destroy(resource);
            if (result != 0) {
                flb_plg_error(ins, "could not merge resource attributes into "
                              "the existing group");
                goto failure;
            }
            continue;
        }

        entry = flb_calloc(1, sizeof(struct so_pending));
        if (!entry) {
            flb_errno();
            cfl_kvlist_destroy(resource);
            goto failure;
        }

        entry->record = record;
        entry->resource = resource;
        entry->signature = so_resource_signature(resource);
        if (!entry->signature) {
            flb_free(entry);
            cfl_kvlist_destroy(resource);
            goto failure;
        }

        cfl_list_add(&entry->_head, &pending);
    }

    if (!cfl_list_is_empty(&pending) &&
        so_build_groups(ctx, chunk_cobj, &pending) != 0) {
        goto failure;
    }

    so_pending_destroy(&pending);

    return FLB_PROCESSOR_SUCCESS;

failure:
    so_pending_destroy(&pending);

    return FLB_PROCESSOR_FAILURE;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "body_key", "message",
     0, FLB_TRUE, offsetof(struct so_ctx, body_key),
     "Record key that receives the RFC 5424 MSG field. The OpenTelemetry "
     "output uses it as the log record body."
    },
    {0}
};

struct flb_processor_plugin processor_syslog_otel_plugin = {
    .name               = "syslog_otel",
    .description        = "map RFC 5424 syslog fields to their OpenTelemetry "
                          "logs data model equivalents",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
