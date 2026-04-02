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
 * Processor: syslog_to_opentelemetry
 * =========================
 * Transforms syslog (RFC 5424 / RFC 3164) log records into the
 * OpenTelemetry Logs data model.
 *
 * Mapping per OTel spec Appendix A - RFC5424 Syslog:
 *
 *   Syslog Field       -> OTel Field
 *   -------------------------------------------------------
 *   TIMESTAMP          -> Timestamp (preserved)
 *   SEVERITY (from PRI)-> severity_number + severity_text
 *   FACILITY (from PRI)-> Attributes["syslog.facility"]
 *   HOSTNAME           -> Resource["host.name"]
 *   APP-NAME (ident)   -> Resource["service.name"]
 *   PROCID (pid)       -> Attributes["syslog.procid"]
 *   MSGID              -> Attributes["syslog.msgid"]
 *   STRUCTURED-DATA    -> Attributes["syslog.*"]
 *                         origin.ip -> Attributes["client.address"]
 *   MSG                -> Body
 *
 * The processor wraps records in an OTLP envelope (GROUP_START/END)
 * and populates resource, scope, and per-record metadata.
 */

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl.h>

#include <string.h>
#include <stdlib.h>

/* Syslog severity -> OTel severity mapping (Appendix B) */
struct otel_severity {
    int number;
    const char *text;
};

static const struct otel_severity syslog_severity_map[8] = {
    { 21, "FATAL" },  /* 0: Emergency */
    { 21, "FATAL" },  /* 1: Alert     */
    { 18, "ERROR" },  /* 2: Critical  */
    { 17, "ERROR" },  /* 3: Error     */
    { 13, "WARN"  },  /* 4: Warning   */
    { 10, "INFO"  },  /* 5: Notice    */
    {  9, "INFO"  },  /* 6: Informational */
    {  5, "DEBUG" },  /* 7: Debug     */
};

/* Syslog facility code -> name (RFC 5424 Section 6.2.1) */
static const char *syslog_facility_names[] = {
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
    "solaris-cron", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7"
};
#define SYSLOG_FACILITY_COUNT \
    (sizeof(syslog_facility_names) / sizeof(syslog_facility_names[0]))

/*
 * Helper: find a value in a msgpack_object map by string key.
 * Returns pointer to the value msgpack_object, or NULL.
 */
static msgpack_object *mp_map_find(msgpack_object *map,
                                   const char *key, size_t key_len)
{
    size_t i;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i = 0; i < map->via.map.size; i++) {
        msgpack_object_kv *kv = &map->via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR &&
            kv->key.via.str.size == key_len &&
            strncmp(kv->key.via.str.ptr, key, key_len) == 0) {
            return &kv->val;
        }
    }

    return NULL;
}

/*
 * Helper: extract a string from a msgpack map by key.
 * Returns the string pointer and sets *out_len, or NULL.
 */
static const char *mp_map_get_str(msgpack_object *map,
                                  const char *key, size_t key_len,
                                  size_t *out_len)
{
    msgpack_object *val = mp_map_find(map, key, key_len);
    if (val && val->type == MSGPACK_OBJECT_STR) {
        *out_len = val->via.str.size;
        return val->via.str.ptr;
    }
    *out_len = 0;
    return NULL;
}

/*
 * Helper: extract an unsigned integer from a msgpack map by key.
 * Returns 1 on success, 0 on failure.
 */
static int mp_map_get_uint(msgpack_object *map,
                           const char *key, size_t key_len,
                           uint64_t *out_val)
{
    msgpack_object *val = mp_map_find(map, key, key_len);
    if (!val) {
        return 0;
    }
    if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *out_val = val->via.u64;
        return 1;
    }
    if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *out_val = (uint64_t) val->via.i64;
        return 1;
    }
    /* Try parsing from string */
    if (val->type == MSGPACK_OBJECT_STR && val->via.str.size > 0) {
        char buf[32];
        size_t len = val->via.str.size;
        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }
        memcpy(buf, val->via.str.ptr, len);
        buf[len] = '\0';
        *out_val = (uint64_t) strtoull(buf, NULL, 10);
        return 1;
    }
    return 0;
}

/*
 * Helper: check if a msgpack string equals a given C string.
 */
static int mp_str_eq(msgpack_object *obj, const char *str, size_t len)
{
    if (!obj || obj->type != MSGPACK_OBJECT_STR) {
        return 0;
    }
    return obj->via.str.size == len &&
           strncmp(obj->via.str.ptr, str, len) == 0;
}

/*
 * Helper: get or create a nested kvlist inside a kvlist by key.
 */
static struct cfl_kvlist *kvlist_get_or_create(struct cfl_kvlist *parent,
                                               const char *key, size_t key_len)
{
    struct cfl_variant *var;

    var = cfl_kvlist_fetch_s(parent, (char *) key, key_len);
    if (var) {
        if (var->type == CFL_VARIANT_KVLIST) {
            return var->data.as_kvlist;
        }
        return NULL;
    }

    struct cfl_kvlist *child = cfl_kvlist_create();
    if (!child) {
        return NULL;
    }

    if (cfl_kvlist_insert_kvlist_s(parent, (char *) key, key_len, child) != 0) {
        cfl_kvlist_destroy(child);
        return NULL;
    }

    /* Fetch it back to get the kvlist owned by parent */
    var = cfl_kvlist_fetch_s(parent, (char *) key, key_len);
    if (var && var->type == CFL_VARIANT_KVLIST) {
        return var->data.as_kvlist;
    }

    return NULL;
}

/*
 * Parse RFC 5424 structured data and insert into an attributes kvlist.
 *
 * Format: [SD-ID key1="val1" key2="val2"][SD-ID2 ...]
 *
 * Per OTel spec:
 *   - SD-ID "origin", param "ip" -> client.address
 *   - All other -> syslog.<sd-id-base>.<param>
 */
static void parse_structured_data(const char *sd_str, size_t sd_len,
                                  struct cfl_kvlist *attributes)
{
    const char *pos = sd_str;
    const char *end = sd_str + sd_len;
    char attr_key[256];

    while (pos < end) {
        /* Find opening bracket */
        while (pos < end && *pos != '[') {
            pos++;
        }
        if (pos >= end) {
            break;
        }
        pos++; /* skip '[' */

        /* Find SD-ID (first token before space) */
        const char *sd_id_start = pos;
        while (pos < end && *pos != ' ' && *pos != ']') {
            pos++;
        }
        size_t sd_id_len = pos - sd_id_start;

        /* Extract the base prefix (before '@') */
        const char *at = memchr(sd_id_start, '@', sd_id_len);
        size_t sd_base_len = at ? (size_t)(at - sd_id_start) : sd_id_len;

        /* Parse key=value pairs within this SD element */
        while (pos < end && *pos != ']') {
            /* Skip whitespace */
            while (pos < end && *pos == ' ') {
                pos++;
            }
            if (pos >= end || *pos == ']') {
                break;
            }

            /* Parse param name */
            const char *pname_start = pos;
            while (pos < end && *pos != '=' && *pos != ']') {
                pos++;
            }
            size_t pname_len = pos - pname_start;
            if (pos >= end || *pos != '=') {
                break;
            }
            pos++; /* skip '=' */

            /* Expect opening quote */
            if (pos >= end || *pos != '"') {
                break;
            }
            pos++; /* skip '"' */

            /* Parse value, handling escapes */
            char value_buf[1024];
            size_t vlen = 0;
            int in_escape = 0;

            while (pos < end && vlen < sizeof(value_buf) - 1) {
                char c = *pos;
                if (in_escape) {
                    /* Unescape per RFC 5424: \", \\, \] */
                    value_buf[vlen++] = c;
                    in_escape = 0;
                }
                else if (c == '\\') {
                    in_escape = 1;
                }
                else if (c == '"') {
                    pos++; /* skip closing quote */
                    break;
                }
                else {
                    value_buf[vlen++] = c;
                }
                pos++;
            }
            value_buf[vlen] = '\0';

            /* Build attribute key and insert */
            if (sd_base_len == 6 &&
                strncmp(sd_id_start, "origin", 6) == 0 &&
                pname_len == 2 &&
                strncmp(pname_start, "ip", 2) == 0) {
                /* origin.ip -> client.address */
                cfl_kvlist_insert_string_s(attributes,
                                           "client.address", 14,
                                           value_buf, vlen, CFL_FALSE);
            }
            else {
                /* syslog.<sd_base>.<param_name> */
                int key_len = snprintf(attr_key, sizeof(attr_key),
                                       "syslog.%.*s.%.*s",
                                       (int) sd_base_len, sd_id_start,
                                       (int) pname_len, pname_start);
                if (key_len > 0 && (size_t) key_len < sizeof(attr_key)) {
                    cfl_kvlist_insert_string_s(attributes,
                                               attr_key, key_len,
                                               value_buf, vlen, CFL_FALSE);
                }
            }
        }

        /* Skip to closing bracket */
        while (pos < end && *pos != ']') {
            pos++;
        }
        if (pos < end) {
            pos++; /* skip ']' */
        }
    }
}

/*
 * Create an OTLP GROUP_START record with resource/scope populated
 * from syslog fields.
 */
static struct flb_mp_chunk_record *create_group_start(
    struct cfl_list *list,
    struct flb_mp_chunk_record *before_record,
    const char *hostname, size_t hostname_len,
    const char *appname, size_t appname_len)
{
    int ret;
    struct cfl_kvlist *kvlist_meta = NULL;
    struct cfl_kvlist *kvlist_record = NULL;
    struct cfl_kvlist *kvlist_resource = NULL;
    struct cfl_kvlist *kvlist_resource_attr = NULL;
    struct cfl_kvlist *kvlist_scope = NULL;
    struct cfl_object *cobj_meta = NULL;
    struct cfl_object *cobj_record = NULL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_time tm;

    /* Group metadata: {"schema": "otlp", "resource_id": 0, "scope_id": 0} */
    kvlist_meta = cfl_kvlist_create();
    if (!kvlist_meta) {
        return NULL;
    }
    cfl_kvlist_insert_string(kvlist_meta, "schema", "otlp");
    cfl_kvlist_insert_int64(kvlist_meta, "resource_id", 0);
    cfl_kvlist_insert_int64(kvlist_meta, "scope_id", 0);

    /* Group record body: {"resource": {"attributes": {...}}, "scope": {}} */
    kvlist_record = cfl_kvlist_create();
    if (!kvlist_record) {
        goto failure;
    }

    kvlist_resource = cfl_kvlist_create();
    if (!kvlist_resource) {
        goto failure;
    }

    /* Resource attributes per OTel spec */
    kvlist_resource_attr = cfl_kvlist_create();
    if (!kvlist_resource_attr) {
        cfl_kvlist_destroy(kvlist_resource);
        goto failure;
    }

    if (hostname && hostname_len > 0) {
        cfl_kvlist_insert_string_s(kvlist_resource_attr,
                                   "host.name", 9,
                                   (char *) hostname, hostname_len, CFL_FALSE);
    }
    if (appname && appname_len > 0) {
        cfl_kvlist_insert_string_s(kvlist_resource_attr,
                                   "service.name", 12,
                                   (char *) appname, appname_len, CFL_FALSE);
    }

    cfl_kvlist_insert_kvlist(kvlist_resource, "attributes", kvlist_resource_attr);
    cfl_kvlist_insert_kvlist(kvlist_record, "resource", kvlist_resource);

    kvlist_scope = cfl_kvlist_create();
    if (!kvlist_scope) {
        goto failure;
    }
    cfl_kvlist_insert_kvlist(kvlist_record, "scope", kvlist_scope);

    /* Create the record */
    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        goto failure;
    }

    cobj_meta = cfl_object_create();
    if (!cobj_meta) {
        goto failure;
    }
    ret = cfl_object_set(cobj_meta, CFL_OBJECT_KVLIST, kvlist_meta);
    if (ret != 0) {
        goto failure;
    }
    /* kvlist_meta ownership transferred to cobj_meta */
    kvlist_meta = NULL;

    cobj_record = cfl_object_create();
    if (!cobj_record) {
        goto failure;
    }
    ret = cfl_object_set(cobj_record, CFL_OBJECT_KVLIST, kvlist_record);
    if (ret != 0) {
        goto failure;
    }
    /* kvlist_record ownership transferred to cobj_record */
    kvlist_record = NULL;

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    flb_time_copy(&record->event.timestamp, &tm);

    record->modified = FLB_TRUE;
    record->cobj_metadata = cobj_meta;
    record->cobj_record = cobj_record;

    cfl_list_add_before(&record->_head, &before_record->_head, list);
    return record;

failure:
    if (kvlist_meta) {
        cfl_kvlist_destroy(kvlist_meta);
    }
    if (kvlist_record) {
        cfl_kvlist_destroy(kvlist_record);
    }
    if (cobj_meta) {
        cfl_object_destroy(cobj_meta);
    }
    if (cobj_record) {
        cfl_object_destroy(cobj_record);
    }
    if (record) {
        flb_mp_chunk_cobj_record_destroy(NULL, record);
    }
    return NULL;
}

/*
 * Create an OTLP GROUP_END record.
 */
static void create_group_end(struct cfl_list *list,
                             struct flb_mp_chunk_record *after_record)
{
    struct flb_time tm;
    struct flb_mp_chunk_record *record;

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        return;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    flb_time_copy(&record->event.timestamp, &tm);

    record->modified = FLB_TRUE;
    record->cobj_metadata = NULL;
    record->cobj_record = NULL;

    cfl_list_add_after(&record->_head, &after_record->_head, list);
}

/*
 * Set OTLP per-record metadata on a log record's cobj_metadata.
 *
 * Builds: {"otlp": {"severity_number": N, "severity_text": "...",
 *                    "attributes": {...}, "trace_flags": 0}}
 */
static int set_otel_record_metadata(
    struct flb_processor_instance *ins,
    struct flb_mp_chunk_record *record,
    int severity_number, const char *severity_text,
    struct cfl_kvlist *attributes)
{
    struct cfl_kvlist *meta_kvlist;
    struct cfl_kvlist *otlp_kvlist;

    if (!record->cobj_metadata || !record->cobj_metadata->variant ||
        record->cobj_metadata->variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    meta_kvlist = record->cobj_metadata->variant->data.as_kvlist;
    otlp_kvlist = kvlist_get_or_create(meta_kvlist, "otlp", 4);
    if (!otlp_kvlist) {
        return -1;
    }

    cfl_kvlist_insert_int64(otlp_kvlist, "severity_number",
                            (int64_t) severity_number);
    cfl_kvlist_insert_string(otlp_kvlist, "severity_text",
                             (char *) severity_text);
    cfl_kvlist_insert_int64(otlp_kvlist, "trace_flags", 0);

    if (attributes) {
        cfl_kvlist_insert_kvlist(otlp_kvlist, "attributes", attributes);
    }

    return 0;
}

/*
 * Rewrite the record body to contain only the log message.
 * Replaces the body with: {"log": "<message>"}
 */
static int set_record_body(struct flb_mp_chunk_record *record,
                           const char *message, size_t message_len)
{
    struct cfl_kvlist *body_kvlist;
    struct cfl_kvlist *new_body;

    if (!record->cobj_record || !record->cobj_record->variant ||
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    /* Clear existing body and replace with just the log field */
    body_kvlist = record->cobj_record->variant->data.as_kvlist;

    /*
     * We cannot easily clear a kvlist in-place without the CFL API
     * providing a clear function. Instead we create a new body object.
     */
    new_body = cfl_kvlist_create();
    if (!new_body) {
        return -1;
    }

    if (message && message_len > 0) {
        cfl_kvlist_insert_string_s(new_body, "log", 3,
                                   (char *) message, message_len, CFL_FALSE);
    }
    else {
        cfl_kvlist_insert_string(new_body, "log", "");
    }

    /* Replace the body cfl_object content */
    struct cfl_object *new_obj = cfl_object_create();
    if (!new_obj) {
        cfl_kvlist_destroy(new_body);
        return -1;
    }

    if (cfl_object_set(new_obj, CFL_OBJECT_KVLIST, new_body) != 0) {
        cfl_object_destroy(new_obj);
        return -1;
    }

    /* Destroy old body and replace */
    cfl_object_destroy(record->cobj_record);
    record->cobj_record = new_obj;

    return 0;
}

/* Processor initialization */
static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Processor exit */
static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Main logs processing callback */
static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int ret;
    int record_type;
    int grouped = FLB_FALSE;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_record *prev_record = NULL;
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    /* Iterate records */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) ==
           FLB_MP_CHUNK_RECORD_OK) {

        prev_record = record;

        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != 0) {
            flb_plg_error(ins, "record has invalid event type");
            continue;
        }

        /* Pass through existing group markers */
        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            grouped = FLB_TRUE;
            continue;
        }
        if (record_type == FLB_LOG_EVENT_GROUP_END) {
            grouped = FLB_FALSE;
            continue;
        }
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }

        /* Read syslog fields from the record body (msgpack) */
        msgpack_object *body = record->event.body;
        uint64_t pri = 14; /* default: user.info */
        size_t len;
        const char *str;

        mp_map_get_uint(body, "pri", 3, &pri);

        int severity_code = pri % 8;
        int facility_code = pri / 8;
        const struct otel_severity *sev = &syslog_severity_map[severity_code];

        /* Hostname and app-name for resource attributes */
        size_t hostname_len = 0;
        const char *hostname = mp_map_get_str(body, "host", 4, &hostname_len);
        size_t appname_len = 0;
        const char *appname = mp_map_get_str(body, "ident", 5, &appname_len);

        /* Insert OTLP group if not already in one */
        if (!grouped) {
            if (create_group_start(&chunk_cobj->records, record,
                                   hostname, hostname_len,
                                   appname, appname_len)) {
                grouped = FLB_TRUE;
            }
        }

        /* Build per-record OTel log attributes */
        struct cfl_kvlist *attributes = cfl_kvlist_create();
        if (!attributes) {
            flb_plg_error(ins, "failed to allocate attributes kvlist");
            continue;
        }

        /* syslog.facility */
        if ((size_t) facility_code < SYSLOG_FACILITY_COUNT) {
            cfl_kvlist_insert_string(attributes, "syslog.facility",
                                     (char *) syslog_facility_names[facility_code]);
        }
        else {
            char fac_buf[16];
            snprintf(fac_buf, sizeof(fac_buf), "%d", facility_code);
            cfl_kvlist_insert_string(attributes, "syslog.facility", fac_buf);
        }

        /* syslog.procid */
        str = mp_map_get_str(body, "pid", 3, &len);
        if (str && len > 0) {
            cfl_kvlist_insert_string_s(attributes, "syslog.procid", 13,
                                       (char *) str, len, CFL_FALSE);
        }

        /* syslog.msgid */
        str = mp_map_get_str(body, "msgid", 5, &len);
        if (str && len > 0 && !(len == 1 && str[0] == '-')) {
            cfl_kvlist_insert_string_s(attributes, "syslog.msgid", 12,
                                       (char *) str, len, CFL_FALSE);
        }

        /* syslog.version */
        uint64_t version;
        if (mp_map_get_uint(body, "version", 7, &version)) {
            cfl_kvlist_insert_int64(attributes, "syslog.version",
                                    (int64_t) version);
        }

        /* Parse RFC 5424 structured data */
        str = mp_map_get_str(body, "extradata", 9, &len);
        if (str && len > 0 && !(len == 1 && str[0] == '-')) {
            parse_structured_data(str, len, attributes);
        }

        /* Set OTel per-record metadata */
        set_otel_record_metadata(ins, record,
                                 sev->number, sev->text,
                                 attributes);
        /* Note: attributes ownership transferred to otlp_kvlist via insert */

        /* Set record body to just the message */
        size_t msg_len = 0;
        const char *msg = mp_map_get_str(body, "message", 7, &msg_len);
        set_record_body(record, msg, msg_len);
    }

    /* Close any open group */
    if (grouped && prev_record) {
        create_group_end(&chunk_cobj->records, prev_record);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_syslog_to_opentelemetry_plugin = {
    .name               = "syslog_to_opentelemetry",
    .description        = "Transform syslog records to OpenTelemetry log model",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0,
};
