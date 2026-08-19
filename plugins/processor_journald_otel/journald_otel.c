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
 * Map systemd journal fields onto the OpenTelemetry logs data model, as
 * described in the "systemd-journald" section of the OpenTelemetry logs data
 * model appendix:
 *
 *   https://opentelemetry.io/docs/specs/otel/logs/data-model-appendix/
 *
 * The processor is meant to be attached to an 'in_systemd' input. The record
 * timestamp is left untouched: in_systemd already derives it from the journal
 * __REALTIME_TIMESTAMP field, which is what the data model asks for.
 */

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <cfl/cfl.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Prefix applied to journald fields that have no semantic convention mapping */
#define JO_UNMAPPED_PREFIX     "journald."
#define JO_UNMAPPED_PREFIX_LEN (sizeof(JO_UNMAPPED_PREFIX) - 1)

/* Separator used when building the resource signature of a record */
#define JO_SIG_SEP '\x1f'

struct jo_ctx {
    /* record key that receives the MESSAGE value (the OTLP log body) */
    flb_sds_t body_key;

    /* must match the 'strip_underscores' setting of the systemd input */
    int strip_underscores;

    struct flb_processor_instance *ins;
};

struct jo_field {
    const char *journald;
    const char *otel;
    int numeric;
};

/*
 * Journald fields that become OTLP log record attributes. The syslog.* names
 * follow the RFC5424 syslog mapping of the logs data model; they are not (yet)
 * part of the semantic conventions registry.
 *
 * SYSLOG_PID maps to syslog.pid rather than the RFC5424 syslog.procid because
 * journald defines it as a numeric client PID, while RFC5424 PROCID is an
 * implementation-defined string that is not necessarily a process ID.
 */
static const struct jo_field jo_log_attributes[] = {
    {"CODE_FILE",         "code.file.path",       FLB_FALSE},
    {"CODE_FUNC",         "code.function.name",   FLB_FALSE},
    {"CODE_LINE",         "code.line.number",     FLB_TRUE},
    {"SYSLOG_FACILITY",   "syslog.facility.code", FLB_TRUE},
    {"SYSLOG_IDENTIFIER", "syslog.identifier",    FLB_FALSE},
    {"SYSLOG_PID",        "syslog.pid",           FLB_TRUE},
    {"SYSLOG_TIMESTAMP",  "syslog.timestamp",     FLB_FALSE},
    {NULL, NULL, FLB_FALSE}
};

/*
 * Journald fields that become OTLP resource attributes. These are all trusted
 * fields (leading underscore), so they are consistent for every record emitted
 * by the same process.
 *
 * _COMM is deliberately absent: it is the value of /proc/[pid]/comm, which does
 * not semantically match process.executable.name. It is kept as journald._COMM
 * instead, and process.executable.name is derived from _EXE.
 */
static const struct jo_field jo_resource_attributes[] = {
    {"_HOSTNAME", "host.name",               FLB_FALSE},
    {"_PID",      "process.pid",             FLB_TRUE},
    {"_EXE",      "process.executable.path", FLB_FALSE},
    {"_CMDLINE",  "process.command_line",    FLB_FALSE},
    {NULL, NULL, FLB_FALSE}
};

/*
 * Syslog PRIORITY (0=emerg .. 7=debug) to OTLP SeverityNumber, following
 * appendix B of the logs data model. The original syslog level name is kept as
 * the severity text.
 */
static const struct {
    int number;
    const char *text;
} jo_severity[] = {
    {21, "emerg"},
    {19, "alert"},
    {18, "crit"},
    {17, "err"},
    {13, "warning"},
    {10, "notice"},
    { 9, "info"},
    { 5, "debug"}
};

/* A record that has been mapped and is waiting to be assigned to a group */
struct jo_pending {
    struct flb_mp_chunk_record *record;
    struct cfl_kvlist *resource;   /* resource attributes of this record */
    cfl_sds_t signature;           /* canonical form of 'resource' */
    struct cfl_list _head;
};

/* -------------------------------------------------------------------------
 * helpers
 * ------------------------------------------------------------------------- */

/*
 * Compare a journald field name coming from the record against a name from one
 * of the mapping tables. When the systemd input runs with 'strip_underscores'
 * the leading underscore of trusted fields has already been removed, so the
 * expected name has to be shortened accordingly.
 */
static int jo_key_matches(struct jo_ctx *ctx, const char *expected,
                          const char *name, size_t name_len)
{
    size_t len;

    if (ctx->strip_underscores == FLB_TRUE && expected[0] == '_') {
        expected++;
    }

    len = strlen(expected);
    if (len != name_len) {
        return FLB_FALSE;
    }

    return strncmp(expected, name, len) == 0 ? FLB_TRUE : FLB_FALSE;
}

static const struct jo_field *jo_field_lookup(struct jo_ctx *ctx,
                                              const struct jo_field *table,
                                              const char *name, size_t name_len)
{
    int i;

    for (i = 0; table[i].journald != NULL; i++) {
        if (jo_key_matches(ctx, table[i].journald, name, name_len) == FLB_TRUE) {
            return &table[i];
        }
    }

    return NULL;
}

/*
 * Parse a journald value as a base 10 int64. Journald delivers every field as
 * a string, so numeric semantic convention attributes have to be converted
 * explicitly. Returns FLB_FALSE when the value is not a valid integer, in
 * which case the caller must not use the semantic convention name for it.
 */
static int jo_parse_int64(const char *buf, size_t len, int64_t *out)
{
    char tmp[32];
    char *end;
    long long value;

    if (len == 0 || len >= sizeof(tmp)) {
        return FLB_FALSE;
    }

    memcpy(tmp, buf, len);
    tmp[len] = '\0';

    errno = 0;
    value = strtoll(tmp, &end, 10);
    if (errno != 0 || end == tmp || *end != '\0') {
        return FLB_FALSE;
    }

    *out = (int64_t) value;

    return FLB_TRUE;
}

static struct cfl_variant *jo_variant_clone(struct cfl_variant *var);

static struct cfl_array *jo_array_clone(struct cfl_array *array)
{
    size_t i;
    struct cfl_array *out;
    struct cfl_variant *entry;

    out = cfl_array_create(array->entry_count > 0 ? array->entry_count : 1);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < array->entry_count; i++) {
        entry = jo_variant_clone(array->entries[i]);
        if (!entry) {
            cfl_array_destroy(out);
            return NULL;
        }

        if (cfl_array_append(out, entry) != 0) {
            cfl_variant_destroy(entry);
            cfl_array_destroy(out);
            return NULL;
        }
    }

    return out;
}

static struct cfl_kvlist *jo_kvlist_clone(struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_kvlist *out;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *value;

    out = cfl_kvlist_create();
    if (!out) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        value = jo_variant_clone(kvpair->val);
        if (!value) {
            cfl_kvlist_destroy(out);
            return NULL;
        }

        if (cfl_kvlist_insert_s(out, kvpair->key, cfl_sds_len(kvpair->key),
                                value) != 0) {
            cfl_variant_destroy(value);
            cfl_kvlist_destroy(out);
            return NULL;
        }
    }

    return out;
}

/*
 * Deep copy a variant. The values we read still belong to the record body, so
 * anything moved into the attribute or resource lists has to be copied before
 * the body is cleared.
 */
static struct cfl_variant *jo_variant_clone(struct cfl_variant *var)
{
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *out;

    switch (var->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s(var->data.as_string,
                                                cfl_variant_size_get(var),
                                                CFL_FALSE);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes(var->data.as_bytes,
                                             cfl_variant_size_get(var),
                                             CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(var->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(var->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64(var->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(var->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null();
    case CFL_VARIANT_ARRAY:
        array = jo_array_clone(var->data.as_array);
        if (!array) {
            return NULL;
        }
        out = cfl_variant_create_from_array(array);
        if (!out) {
            cfl_array_destroy(array);
        }
        return out;
    case CFL_VARIANT_KVLIST:
        kvlist = jo_kvlist_clone(var->data.as_kvlist);
        if (!kvlist) {
            return NULL;
        }
        out = cfl_variant_create_from_kvlist(kvlist);
        if (!out) {
            cfl_kvlist_destroy(kvlist);
        }
        return out;
    default:
        return NULL;
    }
}

/* jo_insert_mapped(): the value does not fit the semantic convention */
#define JO_INSERT_MISMATCH 1

/*
 * Insert 'var' into 'target' under the semantic convention name of 'field',
 * converting the value to an int64 when the convention asks for a number.
 *
 * A value that does not convert is not stored under the semantic convention
 * name, so that a typed attribute never holds a wrong type. Returns 0 on
 * success, JO_INSERT_MISMATCH when the caller has to keep the original field
 * name and value instead, and -1 on error.
 */
static int jo_insert_mapped(struct cfl_kvlist *target,
                            const struct jo_field *field,
                            struct cfl_variant *var)
{
    int64_t number;
    struct cfl_variant *value;

    /* journald delivers numbers as strings; anything else is already typed */
    if (field->numeric == FLB_TRUE && var->type != CFL_VARIANT_INT &&
        var->type != CFL_VARIANT_UINT) {
        if (var->type != CFL_VARIANT_STRING ||
            jo_parse_int64(var->data.as_string, cfl_variant_size_get(var),
                           &number) != FLB_TRUE) {
            return JO_INSERT_MISMATCH;
        }

        if (cfl_kvlist_insert_int64_s(target, (char *) field->otel,
                                      strlen(field->otel), number) != 0) {
            return -1;
        }

        return 0;
    }

    value = jo_variant_clone(var);
    if (!value) {
        return -1;
    }

    if (cfl_kvlist_insert_s(target, (char *) field->otel, strlen(field->otel),
                            value) != 0) {
        cfl_variant_destroy(value);
        return -1;
    }

    return 0;
}

/* Insert an unmapped journald field, prefixed with "journald." */
static int jo_insert_unmapped(struct cfl_kvlist *target, const char *name,
                              size_t name_len, struct cfl_variant *var)
{
    int ret;
    char *key;
    struct cfl_variant *value;

    key = flb_malloc(JO_UNMAPPED_PREFIX_LEN + name_len + 1);
    if (!key) {
        flb_errno();
        return -1;
    }

    memcpy(key, JO_UNMAPPED_PREFIX, JO_UNMAPPED_PREFIX_LEN);
    memcpy(key + JO_UNMAPPED_PREFIX_LEN, name, name_len);
    key[JO_UNMAPPED_PREFIX_LEN + name_len] = '\0';

    value = jo_variant_clone(var);
    if (!value) {
        flb_free(key);
        return -1;
    }

    ret = cfl_kvlist_insert_s(target, key, JO_UNMAPPED_PREFIX_LEN + name_len,
                              value);
    flb_free(key);

    if (ret != 0) {
        cfl_variant_destroy(value);
        return -1;
    }

    return 0;
}

/*
 * Derive process.executable.name from process.executable.path: it is the base
 * name of the target of /proc/[pid]/exe, which journald reports as _EXE. _COMM
 * is not used for it, since /proc/[pid]/comm does not reliably match the name
 * of the executable.
 */
static int jo_derive_executable_name(struct cfl_kvlist *resource)
{
    size_t i;
    size_t len;
    const char *path;
    const char *base;
    struct cfl_variant *var;

    var = cfl_kvlist_fetch_s(resource, "process.executable.path", 23);
    if (!var || var->type != CFL_VARIANT_STRING) {
        return 0;
    }

    path = var->data.as_string;
    len = cfl_variant_size_get(var);
    base = path;

    for (i = 0; i < len; i++) {
        if (path[i] == '/') {
            base = path + i + 1;
        }
    }

    len -= (size_t) (base - path);
    if (len == 0) {
        return 0;
    }

    if (cfl_kvlist_insert_string_s(resource, "process.executable.name", 23,
                                   (char *) base, len, CFL_FALSE) != 0) {
        return -1;
    }

    return 0;
}

/* Fetch 'key' from 'parent', creating it as an empty kvlist when missing */
static struct cfl_kvlist *jo_get_or_create_kvlist(struct cfl_kvlist *parent,
                                                  const char *key)
{
    struct cfl_kvlist *kvlist;
    struct cfl_variant *var;

    var = cfl_kvlist_fetch_s(parent, (char *) key, strlen(key));
    if (var) {
        if (var->type != CFL_VARIANT_KVLIST) {
            return NULL;
        }
        return var->data.as_kvlist;
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

/* Remove every entry of a kvlist without destroying the list itself */
static void jo_kvlist_clear(struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *kvpair;

    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        cfl_kvpair_destroy(kvpair);
    }
}

/*
 * Build a canonical textual form of the resource attributes so that records
 * sharing a resource can be detected with a plain string comparison. The
 * resource table has a fixed order, so no sorting is needed.
 *
 * The derived process.executable.name is left out on purpose: it is a function
 * of process.executable.path, which the table covers, so it cannot tell two
 * resources apart.
 */
static cfl_sds_t jo_resource_signature(struct cfl_kvlist *resource)
{
    int i;
    cfl_sds_t sig;
    cfl_sds_t tmp;
    struct cfl_variant *var;

    sig = cfl_sds_create_size(128);
    if (!sig) {
        return NULL;
    }

    for (i = 0; jo_resource_attributes[i].journald != NULL; i++) {
        var = cfl_kvlist_fetch_s(resource, (char *) jo_resource_attributes[i].otel,
                                 strlen(jo_resource_attributes[i].otel));
        if (!var) {
            continue;
        }

        tmp = cfl_sds_cat(sig, jo_resource_attributes[i].otel,
                          strlen(jo_resource_attributes[i].otel));
        if (!tmp) {
            cfl_sds_destroy(sig);
            return NULL;
        }
        sig = tmp;

        if (var->type == CFL_VARIANT_STRING) {
            tmp = cfl_sds_cat(sig, var->data.as_string, cfl_variant_size_get(var));
        }
        else if (var->type == CFL_VARIANT_INT) {
            tmp = NULL;
            cfl_sds_printf(&sig, "%" PRId64, var->data.as_int64);
            tmp = sig;
        }
        else {
            /* unexpected type, keep the key alone so records still differ */
            tmp = sig;
        }

        if (!tmp) {
            cfl_sds_destroy(sig);
            return NULL;
        }
        sig = tmp;

        tmp = cfl_sds_cat(sig, (const char[]) {JO_SIG_SEP}, 1);
        if (!tmp) {
            cfl_sds_destroy(sig);
            return NULL;
        }
        sig = tmp;
    }

    return sig;
}

/* -------------------------------------------------------------------------
 * record mapping
 * ------------------------------------------------------------------------- */

/*
 * Map one journald record: MESSAGE becomes the log body, PRIORITY becomes the
 * severity, well-known fields become semantic convention attributes and
 * everything else is kept as a "journald."-prefixed attribute.
 *
 * The resource attributes are returned to the caller instead of being applied
 * directly: in the fluent-bit event model they live on the group that wraps a
 * run of records, so they can only be placed once every record is known.
 */
static int jo_map_record(struct jo_ctx *ctx, struct flb_mp_chunk_record *record,
                         struct cfl_kvlist **out_resource)
{
    int i;
    int ret;
    int severity = -1;
    size_t name_len;
    const char *name;
    const struct jo_field *field;
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *body;
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *otlp;
    struct cfl_kvlist *resource;
    struct cfl_variant *message = NULL;

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

    otlp = jo_get_or_create_kvlist(metadata, "otlp");
    if (!otlp) {
        flb_plg_error(ctx->ins, "could not access the OTLP metadata of a record");
        return -1;
    }

    attributes = jo_get_or_create_kvlist(otlp, "attributes");
    if (!attributes) {
        flb_plg_error(ctx->ins, "could not access the OTLP attributes of a record");
        return -1;
    }

    resource = cfl_kvlist_create();
    if (!resource) {
        flb_errno();
        return -1;
    }

    cfl_list_foreach(head, &body->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        name = kvpair->key;
        name_len = cfl_sds_len(kvpair->key);

        if (jo_key_matches(ctx, "MESSAGE", name, name_len) == FLB_TRUE) {
            message = kvpair->val;
            continue;
        }

        if (jo_key_matches(ctx, "PRIORITY", name, name_len) == FLB_TRUE) {
            if (kvpair->val->type == CFL_VARIANT_STRING &&
                cfl_variant_size_get(kvpair->val) == 1) {
                i = kvpair->val->data.as_string[0] - '0';
                if (i >= 0 && i <= 7) {
                    severity = i;
                    continue;
                }
            }
            /* not a syslog priority, keep it as a plain attribute */
            if (jo_insert_unmapped(attributes, name, name_len,
                                   kvpair->val) != 0) {
                goto failure;
            }
            continue;
        }

        field = jo_field_lookup(ctx, jo_log_attributes, name, name_len);
        if (field) {
            ret = jo_insert_mapped(attributes, field, kvpair->val);
        }
        else {
            field = jo_field_lookup(ctx, jo_resource_attributes, name, name_len);
            if (field) {
                ret = jo_insert_mapped(resource, field, kvpair->val);
            }
            else {
                ret = JO_INSERT_MISMATCH;
            }
        }

        if (ret < 0) {
            goto failure;
        }

        if (ret == 0) {
            continue;
        }

        /*
         * Unmapped field, or a value that does not fit the type required by
         * the semantic convention: keep the original field name and value. A
         * resource field lands in the attributes too, since a resource
         * attribute under a journald name would say nothing about the
         * resource.
         */
        if (jo_insert_unmapped(attributes, name, name_len, kvpair->val) != 0) {
            goto failure;
        }
    }

    if (jo_derive_executable_name(resource) != 0) {
        goto failure;
    }

    /* severity */
    if (severity >= 0) {
        if (cfl_kvlist_insert_int64_s(otlp, "severity_number", 15,
                                      jo_severity[severity].number) != 0) {
            goto failure;
        }

        if (cfl_kvlist_insert_string_s(otlp, "severity_text", 13,
                                       (char *) jo_severity[severity].text,
                                       strlen(jo_severity[severity].text),
                                       CFL_FALSE) != 0) {
            goto failure;
        }
    }

    /* body: keep a copy of MESSAGE before the original record is cleared */
    if (message) {
        message = jo_variant_clone(message);
        if (!message) {
            goto failure;
        }
    }

    jo_kvlist_clear(body);

    if (message) {
        if (cfl_kvlist_insert_s(body, ctx->body_key,
                                flb_sds_len(ctx->body_key), message) != 0) {
            cfl_variant_destroy(message);
            goto failure;
        }
    }

    record->modified = FLB_TRUE;
    *out_resource = resource;

    return 0;

failure:
    flb_plg_error(ctx->ins, "could not map journald record");
    cfl_kvlist_destroy(resource);

    return -1;
}

/* -------------------------------------------------------------------------
 * grouping
 * ------------------------------------------------------------------------- */

/*
 * Create an OTLP group start record carrying 'resource' as its resource
 * attributes and insert it before 'position'. Ownership of 'resource' is
 * transferred to the new record on success.
 */
static struct flb_mp_chunk_record *jo_group_start(struct cfl_list *list,
                                                  struct flb_mp_chunk_record *position,
                                                  struct cfl_kvlist *resource)
{
    struct cfl_kvlist *group = NULL;
    struct cfl_kvlist *meta = NULL;
    struct cfl_kvlist *resource_wrapper = NULL;
    struct cfl_kvlist *scope = NULL;
    struct cfl_object *cobj_meta = NULL;
    struct cfl_object *cobj_record = NULL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_time tm;

    meta = cfl_kvlist_create();
    if (!meta) {
        return NULL;
    }

    if (cfl_kvlist_insert_string(meta, "schema", "otlp") != 0 ||
        cfl_kvlist_insert_int64(meta, "resource_id", 0) != 0 ||
        cfl_kvlist_insert_int64(meta, "scope_id", 0) != 0) {
        goto failure;
    }

    group = cfl_kvlist_create();
    if (!group) {
        goto failure;
    }

    resource_wrapper = cfl_kvlist_create();
    if (!resource_wrapper) {
        goto failure;
    }

    scope = cfl_kvlist_create();
    if (!scope) {
        goto failure;
    }

    if (cfl_kvlist_insert_kvlist_s(resource_wrapper, "attributes", 10,
                                   resource) != 0) {
        goto failure;
    }
    /* 'resource' is owned by resource_wrapper from here on */
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
    if (!cobj_meta) {
        goto failure;
    }

    if (cfl_object_set(cobj_meta, CFL_OBJECT_KVLIST, meta) != 0) {
        goto failure;
    }
    meta = NULL;

    cobj_record = cfl_object_create();
    if (!cobj_record) {
        goto failure;
    }

    if (cfl_object_set(cobj_record, CFL_OBJECT_KVLIST, group) != 0) {
        goto failure;
    }
    group = NULL;

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        goto failure;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    flb_time_copy(&record->event.timestamp, &tm);

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

/* Create an OTLP group end record and insert it after 'position' */
static int jo_group_end(struct cfl_list *list,
                        struct flb_mp_chunk_record *position)
{
    struct flb_mp_chunk_record *record;
    struct flb_time tm;

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        return -1;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    flb_time_copy(&record->event.timestamp, &tm);

    record->modified = FLB_TRUE;
    record->cobj_metadata = NULL;
    record->cobj_record = NULL;

    /*
     * Insert right after 'position'. cfl_list_add_after() is avoided on
     * purpose: it does not update the 'prev' pointer of the following node, so
     * a later insertion before that node would unlink the record again.
     */
    cfl_list_add_before(&record->_head, position->_head.next, list);

    return 0;
}

/*
 * Merge resource attributes into an already existing group start record. Used
 * when another processor (for example 'opentelemetry_envelope') has already
 * wrapped the chunk: in that case the group layout is not ours to decide, so
 * the attributes of every record are folded into the enclosing group.
 */
static int jo_group_merge(struct flb_mp_chunk_record *group,
                          struct cfl_kvlist *resource)
{
    struct cfl_list *head;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *wrapper;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *value;

    if (!group->cobj_record || !group->cobj_record->variant ||
        group->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    wrapper = jo_get_or_create_kvlist(group->cobj_record->variant->data.as_kvlist,
                                      "resource");
    if (!wrapper) {
        return -1;
    }

    attributes = jo_get_or_create_kvlist(wrapper, "attributes");
    if (!attributes) {
        return -1;
    }

    cfl_list_foreach(head, &resource->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        cfl_kvlist_remove(attributes, kvpair->key);

        value = jo_variant_clone(kvpair->val);
        if (!value) {
            return -1;
        }

        if (cfl_kvlist_insert_s(attributes, kvpair->key,
                                cfl_sds_len(kvpair->key), value) != 0) {
            cfl_variant_destroy(value);
            return -1;
        }
    }

    group->modified = FLB_TRUE;

    return 0;
}

static void jo_pending_destroy(struct cfl_list *pending)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct jo_pending *entry;

    cfl_list_foreach_safe(head, tmp, pending) {
        entry = cfl_list_entry(head, struct jo_pending, _head);
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

/*
 * Wrap every run of consecutive records that share the same resource in its own
 * OTLP group. Records are never reordered, so a resource that reappears later
 * in the chunk simply gets a second group; the OpenTelemetry output merges
 * groups with an identical resource again when it builds the payload.
 */
static int jo_build_groups(struct jo_ctx *ctx,
                           struct flb_mp_chunk_cobj *chunk_cobj,
                           struct cfl_list *pending)
{
    struct cfl_list *head;
    struct jo_pending *entry;
    struct jo_pending *run_start = NULL;
    struct jo_pending *previous = NULL;

    cfl_list_foreach(head, pending) {
        entry = cfl_list_entry(head, struct jo_pending, _head);

        if (run_start != NULL &&
            cfl_sds_len(run_start->signature) == cfl_sds_len(entry->signature) &&
            memcmp(run_start->signature, entry->signature,
                   cfl_sds_len(entry->signature)) == 0) {
            /* same resource as the open run, nothing to do */
            previous = entry;
            continue;
        }

        /* close the previous run */
        if (previous != NULL) {
            if (jo_group_end(&chunk_cobj->records, previous->record) != 0) {
                flb_plg_error(ctx->ins, "could not create a group end record");
                return -1;
            }
        }

        if (jo_group_start(&chunk_cobj->records, entry->record,
                           entry->resource) == NULL) {
            flb_plg_error(ctx->ins, "could not create a group start record");
            return -1;
        }
        /* the group start record owns the resource attributes now */
        entry->resource = NULL;

        run_start = entry;
        previous = entry;
    }

    if (previous != NULL) {
        if (jo_group_end(&chunk_cobj->records, previous->record) != 0) {
            flb_plg_error(ctx->ins, "could not create a group end record");
            return -1;
        }
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * callbacks
 * ------------------------------------------------------------------------- */

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    struct jo_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct jo_ctx));
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
    struct jo_ctx *ctx = data;

    if (ctx) {
        flb_free(ctx);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int ret;
    int record_type;
    struct cfl_list pending;
    struct flb_mp_chunk_cobj *chunk_cobj = chunk_data;
    struct flb_mp_chunk_record *group = NULL;
    struct flb_mp_chunk_record *record;
    struct jo_ctx *ctx = ins->context;
    struct jo_pending *entry;
    struct cfl_kvlist *resource;

    cfl_list_init(&pending);

    /*
     * First pass: map every record. This also materializes the whole chunk as
     * cobj records, which is what makes the second pass able to walk the record
     * list directly.
     */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        if (flb_log_event_decoder_get_record_type(&record->event, &record_type) != 0) {
            flb_plg_error(ins, "record has invalid event type");
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group = record;
            continue;
        }
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }

        resource = NULL;
        if (jo_map_record(ctx, record, &resource) != 0) {
            goto failure;
        }
        if (!resource) {
            continue;
        }

        /*
         * When the chunk is already grouped the resource attributes are folded
         * into the enclosing group instead of creating our own envelopes.
         */
        if (group != NULL) {
            ret = jo_group_merge(group, resource);
            cfl_kvlist_destroy(resource);
            if (ret != 0) {
                flb_plg_error(ins, "could not merge resource attributes into "
                              "the existing group");
                goto failure;
            }
            continue;
        }

        entry = flb_calloc(1, sizeof(struct jo_pending));
        if (!entry) {
            flb_errno();
            cfl_kvlist_destroy(resource);
            goto failure;
        }

        entry->record = record;
        entry->resource = resource;
        entry->signature = jo_resource_signature(resource);
        if (!entry->signature) {
            flb_free(entry);
            cfl_kvlist_destroy(resource);
            goto failure;
        }

        cfl_list_add(&entry->_head, &pending);
    }

    /* Second pass: wrap runs of records sharing a resource into groups */
    if (!cfl_list_is_empty(&pending)) {
        if (jo_build_groups(ctx, chunk_cobj, &pending) != 0) {
            goto failure;
        }
    }

    jo_pending_destroy(&pending);

    return FLB_PROCESSOR_SUCCESS;

failure:
    jo_pending_destroy(&pending);

    return FLB_PROCESSOR_FAILURE;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "body_key", "message",
     0, FLB_TRUE, offsetof(struct jo_ctx, body_key),
     "Record key that receives the journald MESSAGE field. The OpenTelemetry "
     "output uses it as the log record body."
    },
    {
     FLB_CONFIG_MAP_BOOL, "strip_underscores", "false",
     0, FLB_TRUE, offsetof(struct jo_ctx, strip_underscores),
     "Must match the 'strip_underscores' setting of the systemd input, so that "
     "trusted journald fields such as _PID are recognized."
    },
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_journald_otel_plugin = {
    .name               = "journald_otel",
    .description        = "map systemd journal fields to their OpenTelemetry "
                          "logs data model equivalents",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
