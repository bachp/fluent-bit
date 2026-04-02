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
 * Processor: journald_to_opentelemetry
 * ============================
 * Transforms systemd journald log records into the OpenTelemetry Logs
 * data model.
 *
 * Mapping per OTel spec Appendix A - Journald:
 *
 *   Journal Field         -> OTel Field
 *   -------------------------------------------------------
 *   _HOSTNAME             -> Resource["host.name"]
 *   _MACHINE_ID           -> Resource["host.id"]
 *   _SYSTEMD_UNIT         -> Resource["service.name"] (fallback: SYSLOG_IDENTIFIER)
 *   PRIORITY              -> severity_number + severity_text
 *   MESSAGE               -> Body
 *   _PID                  -> Attributes["process.pid"]
 *   _UID                  -> Attributes["process.user.id"]
 *   _GID                  -> Attributes["process.group.id"]
 *   _COMM                 -> Attributes["process.executable.name"]
 *   _EXE                  -> Attributes["process.executable.path"]
 *   _CMDLINE              -> Attributes["process.command_line"]
 *   _BOOT_ID              -> Attributes["host.boot.id"]
 *   CODE_FILE             -> Attributes["code.filepath"]
 *   CODE_LINE             -> Attributes["code.lineno"]
 *   CODE_FUNC             -> Attributes["code.function"]
 *   SYSLOG_FACILITY       -> Attributes["syslog.facility"]
 *   MESSAGE_ID            -> Attributes["journald.message_id"]
 *   TID                   -> Attributes["thread.id"]
 *   All other fields      -> Attributes["journald.<lowercase_name>"]
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
#include <ctype.h>

/* Syslog priority -> OTel severity mapping (Appendix B) */
struct otel_severity {
    int number;
    const char *text;
};

static const struct otel_severity priority_severity_map[8] = {
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
 * Table of known journald fields that map to well-defined OTel attributes.
 * Fields NOT in this table get mapped to "journald.<lowercase_name>".
 *
 * Resource fields (_HOSTNAME, _MACHINE_ID, _SYSTEMD_UNIT, SYSLOG_IDENTIFIER)
 * and the special fields (PRIORITY, MESSAGE, SYSLOG_FACILITY) are handled
 * explicitly in the processing loop rather than through this table.
 */
struct journal_field_mapping {
    const char *journal_key;
    size_t journal_key_len;
    const char *otel_key;
    size_t otel_key_len;
};

#define JF(jk, ok) { jk, sizeof(jk) - 1, ok, sizeof(ok) - 1 }

static const struct journal_field_mapping known_fields[] = {
    JF("_PID",     "process.pid"),
    JF("_UID",     "process.user.id"),
    JF("_GID",     "process.group.id"),
    JF("_COMM",    "process.executable.name"),
    JF("_EXE",     "process.executable.path"),
    JF("_CMDLINE", "process.command_line"),
    JF("_BOOT_ID", "host.boot.id"),
    JF("CODE_FILE", "code.filepath"),
    JF("CODE_LINE", "code.lineno"),
    JF("CODE_FUNC", "code.function"),
    JF("MESSAGE_ID", "journald.message_id"),
    JF("TID",       "thread.id"),
    { NULL, 0, NULL, 0 }
};

#undef JF

/*
 * Fields to skip (already consumed for resource, severity, body, or facility).
 */
static int is_consumed_field(const char *key, size_t len)
{
    /* Resource fields */
    if (len == 9 && strncmp(key, "_HOSTNAME", 9) == 0) {
        return 1;
    }
    if (len == 11 && strncmp(key, "_MACHINE_ID", 11) == 0) {
        return 1;
    }
    if (len == 14 && strncmp(key, "_SYSTEMD_UNIT", 14) == 0) {
        return 1;
    }
    /* Special fields handled explicitly */
    if (len == 8 && strncmp(key, "PRIORITY", 8) == 0) {
        return 1;
    }
    if (len == 7 && strncmp(key, "MESSAGE", 7) == 0) {
        return 1;
    }
    if (len == 16 && strncmp(key, "SYSLOG_FACILITY", 16) == 0) {
        return 1;
    }
    /*
     * SYSLOG_IDENTIFIER is consumed only when it was used as the
     * service.name fallback (i.e. _SYSTEMD_UNIT was absent).
     * We skip it here unconditionally to avoid duplication; users
     * rarely need both the resource attribute and a journald.* copy.
     */
    if (len == 17 && strncmp(key, "SYSLOG_IDENTIFIER", 17) == 0) {
        return 1;
    }
    return 0;
}

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
 * Insert a msgpack string value into a CFL kvlist as a string attribute.
 */
static void insert_mp_str_attr(struct cfl_kvlist *attrs,
                                const char *key, size_t key_len,
                                msgpack_object *val)
{
    if (val->type == MSGPACK_OBJECT_STR && val->via.str.size > 0) {
        cfl_kvlist_insert_string_s(attrs, (char *) key, key_len,
                                   (char *) val->via.str.ptr,
                                   val->via.str.size, CFL_FALSE);
    }
    else if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%" PRIu64, val->via.u64);
        if (len > 0) {
            cfl_kvlist_insert_string_s(attrs, (char *) key, key_len,
                                       buf, len, CFL_FALSE);
        }
    }
    else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%" PRId64, val->via.i64);
        if (len > 0) {
            cfl_kvlist_insert_string_s(attrs, (char *) key, key_len,
                                       buf, len, CFL_FALSE);
        }
    }
}

/*
 * Create an OTLP GROUP_START record with resource/scope populated
 * from journald fields.
 */
static struct flb_mp_chunk_record *create_group_start(
    struct cfl_list *list,
    struct flb_mp_chunk_record *before_record,
    const char *hostname, size_t hostname_len,
    const char *machine_id, size_t machine_id_len,
    const char *service_name, size_t service_name_len)
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
    if (machine_id && machine_id_len > 0) {
        cfl_kvlist_insert_string_s(kvlist_resource_attr,
                                   "host.id", 7,
                                   (char *) machine_id, machine_id_len,
                                   CFL_FALSE);
    }
    if (service_name && service_name_len > 0) {
        cfl_kvlist_insert_string_s(kvlist_resource_attr,
                                   "service.name", 12,
                                   (char *) service_name, service_name_len,
                                   CFL_FALSE);
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
    struct cfl_kvlist *new_body;
    struct cfl_object *new_obj;

    if (!record->cobj_record || !record->cobj_record->variant ||
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

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

    new_obj = cfl_object_create();
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
    size_t i;
    size_t j;
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

        /* Read journald fields from the record body (msgpack) */
        msgpack_object *body = record->event.body;
        if (!body || body->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Extract resource fields */
        size_t hostname_len = 0;
        const char *hostname = mp_map_get_str(body, "_HOSTNAME", 9,
                                              &hostname_len);
        size_t machine_id_len = 0;
        const char *machine_id = mp_map_get_str(body, "_MACHINE_ID", 11,
                                                &machine_id_len);

        /* service.name: prefer _SYSTEMD_UNIT, fallback to SYSLOG_IDENTIFIER */
        size_t svc_len = 0;
        const char *svc_name = mp_map_get_str(body, "_SYSTEMD_UNIT", 14,
                                              &svc_len);
        if (!svc_name || svc_len == 0) {
            svc_name = mp_map_get_str(body, "SYSLOG_IDENTIFIER", 17, &svc_len);
        }

        /* Severity from PRIORITY field */
        uint64_t priority = 6; /* default: Informational */
        mp_map_get_uint(body, "PRIORITY", 8, &priority);
        if (priority > 7) {
            priority = 7;
        }
        const struct otel_severity *sev = &priority_severity_map[priority];

        /* Insert OTLP group if not already in one */
        if (!grouped) {
            if (create_group_start(&chunk_cobj->records, record,
                                   hostname, hostname_len,
                                   machine_id, machine_id_len,
                                   svc_name, svc_len)) {
                grouped = FLB_TRUE;
            }
        }

        /* Build per-record OTel log attributes */
        struct cfl_kvlist *attributes = cfl_kvlist_create();
        if (!attributes) {
            flb_plg_error(ins, "failed to allocate attributes kvlist");
            continue;
        }

        /* syslog.facility from SYSLOG_FACILITY */
        uint64_t facility;
        if (mp_map_get_uint(body, "SYSLOG_FACILITY", 16, &facility)) {
            if (facility < SYSLOG_FACILITY_COUNT) {
                cfl_kvlist_insert_string(
                    attributes, "syslog.facility",
                    (char *) syslog_facility_names[facility]);
            }
            else {
                char fac_buf[16];
                snprintf(fac_buf, sizeof(fac_buf), "%" PRIu64, facility);
                cfl_kvlist_insert_string(attributes, "syslog.facility",
                                         fac_buf);
            }
        }

        /*
         * Iterate all fields in the record body.
         * - Known fields are mapped to their OTel attribute names.
         * - Consumed fields (resource, severity, body, facility) are skipped.
         * - Unknown fields become journald.<lowercase_name>.
         */
        for (i = 0; i < body->via.map.size; i++) {
            msgpack_object_kv *kv = &body->via.map.ptr[i];
            const char *key;
            size_t key_len;
            int found;

            if (kv->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            key = kv->key.via.str.ptr;
            key_len = kv->key.via.str.size;

            /* Skip consumed fields */
            if (is_consumed_field(key, key_len)) {
                continue;
            }

            /* Check known field mappings */
            found = 0;
            for (j = 0; known_fields[j].journal_key != NULL; j++) {
                if (key_len == known_fields[j].journal_key_len &&
                    strncmp(key, known_fields[j].journal_key, key_len) == 0) {
                    insert_mp_str_attr(attributes,
                                       known_fields[j].otel_key,
                                       known_fields[j].otel_key_len,
                                       &kv->val);
                    found = 1;
                    break;
                }
            }

            if (!found) {
                /*
                 * Unknown field: map to journald.<lowercase_name>.
                 * Strip leading underscore if present.
                 */
                char attr_key[256];
                const char *name_start = key;
                size_t name_len = key_len;
                size_t k;
                int attr_key_len;

                if (name_len > 0 && name_start[0] == '_') {
                    name_start++;
                    name_len--;
                }

                attr_key_len = snprintf(attr_key, sizeof(attr_key),
                                        "journald.");
                if (name_len > 0 &&
                    (size_t) attr_key_len + name_len < sizeof(attr_key)) {
                    for (k = 0; k < name_len; k++) {
                        attr_key[attr_key_len + k] = tolower(
                            (unsigned char) name_start[k]);
                    }
                    attr_key_len += name_len;
                    attr_key[attr_key_len] = '\0';

                    insert_mp_str_attr(attributes,
                                       attr_key, attr_key_len,
                                       &kv->val);
                }
            }
        }

        /* Set OTel per-record metadata */
        set_otel_record_metadata(ins, record,
                                 sev->number, sev->text,
                                 attributes);
        /* Note: attributes ownership transferred to otlp_kvlist via insert */

        /* Set record body to just the message */
        size_t msg_len = 0;
        const char *msg = mp_map_get_str(body, "MESSAGE", 7, &msg_len);
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

struct flb_processor_plugin processor_journald_to_opentelemetry_plugin = {
    .name               = "journald_to_opentelemetry",
    .description        = "Transform journald records to OpenTelemetry log model",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0,
};
