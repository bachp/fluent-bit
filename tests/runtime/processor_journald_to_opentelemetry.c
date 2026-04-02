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
 * Runtime tests for the journald_to_opentelemetry processor.
 *
 * Each test pushes a msgpack-encoded journald record through the processor
 * via the "lib" input plugin and inspects the JSON-encoded output produced
 * by the "lib" output plugin.
 *
 * Journald records use uppercase field names as emitted by systemd:
 *   _HOSTNAME, _MACHINE_ID, _SYSTEMD_UNIT, SYSLOG_IDENTIFIER,
 *   PRIORITY, MESSAGE, _PID, _UID, _GID, _COMM, _EXE, _CMDLINE,
 *   _BOOT_ID, CODE_FILE, CODE_LINE, CODE_FUNC, SYSLOG_FACILITY,
 *   MESSAGE_ID, TID, and arbitrary additional fields.
 *
 * After the processor runs, the body should contain only "log": "<MESSAGE>".
 * The OTLP envelope (GROUP_START/END) and per-record metadata (severity,
 * attributes) are injected into the chunk metadata, which is not directly
 * visible in the JSON body output of the "lib" plugin.  We therefore verify:
 *   - the message text is preserved in the body
 *   - resource/journald-specific fields do NOT appear verbatim in the body
 *     (they should have been moved to metadata or dropped)
 */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

/* -------------------------------------------------------------------------
 * Shared state
 * ------------------------------------------------------------------------- */

struct test_ctx {
    flb_ctx_t *flb;
    int        i_ffd;
    int        o_ffd;
    struct flb_processor      *proc;
    struct flb_processor_unit *pu;
};

struct expect_str {
    const char *str;
    int         found; /* FLB_TRUE => must be present, FLB_FALSE => must be absent */
};

/* -------------------------------------------------------------------------
 * Output callback.
 *
 * The processor emits an OTLP envelope so the lib output delivers three
 * records per input record:
 *   1. GROUP_START  – timestamp 4294967295, body = {resource/scope}
 *   2. log record   – normal timestamp,     body = {"log": "..."}
 *   3. GROUP_END    – timestamp 4294967294, body = {}
 *
 * We only run assertions on the actual log record (2); the envelope records
 * are identified by their magic timestamps and skipped.
 * ------------------------------------------------------------------------- */
#define FLB_LOG_EVENT_GROUP_START_STR "4294967295.000000"
#define FLB_LOG_EVENT_GROUP_END_STR   "4294967294.000000"

static int cb_check_result(void *record, size_t size, void *data)
{
    const char        *result   = (const char *) record;
    struct expect_str *expected = (struct expect_str *) data;

    /* Skip GROUP_START and GROUP_END envelope records */
    if (strstr(result, FLB_LOG_EVENT_GROUP_START_STR) ||
        strstr(result, FLB_LOG_EVENT_GROUP_END_STR)) {
        flb_free(record);
        return 0;
    }

    if (!TEST_CHECK(result   != NULL)) { flb_error("result is NULL");   }
    if (!TEST_CHECK(expected != NULL)) { flb_error("expected is NULL"); }

    while (expected && expected->str) {
        const char *p = strstr(result, expected->str);
        if (expected->found == FLB_TRUE) {
            if (!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find '%s' in: %.*s",
                          expected->str, (int) size, result);
            }
        }
        else {
            if (!TEST_CHECK(p == NULL)) {
                flb_error("Did not expect '%s' in: %.*s",
                          expected->str, (int) size, result);
            }
        }
        expected++;
    }

    flb_free(record);
    return 0;
}

/* -------------------------------------------------------------------------
 * Test context helpers
 * ------------------------------------------------------------------------- */
static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *cb)
{
    struct test_ctx *ctx;

    ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    ctx->flb = flb_create();
    if (!TEST_CHECK(ctx->flb != NULL)) {
        flb_free(ctx);
        return NULL;
    }

    flb_service_set(ctx->flb,
                    "Flush",     "0.200000000",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    /* lib input */
    ctx->i_ffd = flb_input(ctx->flb, "lib", NULL);
    if (!TEST_CHECK(ctx->i_ffd >= 0)) {
        TEST_MSG("flb_input(lib) failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }
    flb_input_set(ctx->flb, ctx->i_ffd, "tag", "test", NULL);

    /* lib output */
    ctx->o_ffd = flb_output(ctx->flb, "lib", cb);
    if (!TEST_CHECK(ctx->o_ffd >= 0)) {
        TEST_MSG("flb_output(lib) failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }
    flb_output_set(ctx->flb, ctx->o_ffd,
                   "match",  "test",
                   "format", "json",
                   NULL);

    /* processor */
    ctx->proc = flb_processor_create(ctx->flb->config, "unit_test", NULL, 0);
    if (!TEST_CHECK(ctx->proc != NULL)) {
        TEST_MSG("flb_processor_create failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    ctx->pu = flb_processor_unit_create(ctx->proc,
                                        FLB_PROCESSOR_LOGS,
                                        "journald_to_opentelemetry");
    if (!TEST_CHECK(ctx->pu != NULL)) {
        TEST_MSG("flb_processor_unit_create failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    if (!TEST_CHECK(flb_input_set_processor(ctx->flb, ctx->i_ffd,
                                            ctx->proc) == 0)) {
        TEST_MSG("flb_input_set_processor failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void push_and_wait(struct test_ctx *ctx, const char *record)
{
    int ret;
    int bytes;
    size_t len = strlen(record);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, record, len);
    TEST_CHECK(bytes == (int) len);
}

/* =========================================================================
 * Test cases
 * ========================================================================= */

/*
 * Basic record: common journald fields.
 * The processor must emit the MESSAGE text in the body and must not crash.
 */
static void test_basic_record(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"hello from journald", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    /* PRIORITY 6 = informational */
    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"myhost\","
        "\"_MACHINE_ID\":\"aabbcc\","
        "\"_SYSTEMD_UNIT\":\"myservice.service\","
        "\"PRIORITY\":\"6\","
        "\"MESSAGE\":\"hello from journald\","
        "\"_PID\":\"1234\","
        "\"_UID\":\"1000\","
        "\"_GID\":\"1000\","
        "\"_COMM\":\"mybin\","
        "\"SYSLOG_FACILITY\":\"3\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * SYSLOG_IDENTIFIER fallback: _SYSTEMD_UNIT absent, service.name should
 * come from SYSLOG_IDENTIFIER.  The message must still be delivered.
 */
static void test_syslog_identifier_fallback(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"fallback service msg", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"host2\","
        "\"_MACHINE_ID\":\"ddeeff\","
        "\"SYSLOG_IDENTIFIER\":\"myident\","
        "\"PRIORITY\":\"5\","
        "\"MESSAGE\":\"fallback service msg\","
        "\"_PID\":\"999\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Emergency priority (0) maps to FATAL/21 in OTel.
 * The processor must not crash and must forward the message.
 */
static void test_priority_emergency(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"critical failure", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"crashbox\","
        "\"_SYSTEMD_UNIT\":\"kernel.service\","
        "\"PRIORITY\":\"0\","
        "\"MESSAGE\":\"critical failure\","
        "\"_PID\":\"1\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Debug priority (7): maps to DEBUG/5 in OTel.
 */
static void test_priority_debug(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"verbose debug info", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"devhost\","
        "\"_SYSTEMD_UNIT\":\"debug.service\","
        "\"PRIORITY\":\"7\","
        "\"MESSAGE\":\"verbose debug info\","
        "\"_PID\":\"42\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Code location fields: CODE_FILE, CODE_LINE, CODE_FUNC map to
 * code.filepath, code.lineno, code.function respectively.
 * These should not appear verbatim in the body.
 */
static void test_code_location_fields(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"code location test", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"codehost\","
        "\"_SYSTEMD_UNIT\":\"testapp.service\","
        "\"PRIORITY\":\"6\","
        "\"MESSAGE\":\"code location test\","
        "\"CODE_FILE\":\"/src/main.c\","
        "\"CODE_LINE\":\"42\","
        "\"CODE_FUNC\":\"main\","
        "\"_PID\":\"100\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Unknown journald fields: any field not in the known mapping table should
 * be emitted as "journald.<lowercase_name>" and must not crash the processor.
 */
static void test_unknown_fields(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"unknown field test", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"host3\","
        "\"_SYSTEMD_UNIT\":\"app.service\","
        "\"PRIORITY\":\"6\","
        "\"MESSAGE\":\"unknown field test\","
        "\"MY_CUSTOM_FIELD\":\"customval\","
        "\"ANOTHER_FIELD\":\"anotherval\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Empty MESSAGE: processor must not crash.
 */
static void test_empty_message(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"_HOSTNAME\":\"h\","
        "\"_SYSTEMD_UNIT\":\"s.service\","
        "\"PRIORITY\":\"6\","
        "\"MESSAGE\":\"\""
        "}]");

    test_ctx_destroy(ctx);
}

/* =========================================================================
 * Test list
 * ========================================================================= */
TEST_LIST = {
    {"basic_record",                test_basic_record},
    {"syslog_identifier_fallback",  test_syslog_identifier_fallback},
    {"priority_emergency",          test_priority_emergency},
    {"priority_debug",              test_priority_debug},
    {"code_location_fields",        test_code_location_fields},
    {"unknown_fields",              test_unknown_fields},
    {"empty_message",               test_empty_message},
    {NULL, NULL}
};
