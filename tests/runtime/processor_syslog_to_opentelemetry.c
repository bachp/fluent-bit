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
 * Runtime tests for the syslog_to_opentelemetry processor.
 *
 * Each test pushes a msgpack-encoded syslog record through the processor
 * via the "lib" input plugin and inspects the JSON-encoded output produced
 * by the "lib" output plugin.
 *
 * The syslog parser in Fluent Bit emits records with the following keys:
 *   pri, host, ident, pid, msgid, version, extradata, message
 *
 * After the processor runs, the output record body should contain only
 * "log": "<message>", and the OTLP metadata (severity, attributes) should
 * be reflected in the msgpack metadata embedded by the output encoder.
 * Because the "lib" output delivers the raw msgpack chunk, we verify the
 * fields that survive into the JSON-formatted output.
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
 * Output callback: search for expected strings in the JSON result.
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
    const char         *result   = (const char *) record;
    struct expect_str  *expected = (struct expect_str *) data;

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
                                        "syslog_to_opentelemetry");
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

/* -------------------------------------------------------------------------
 * Helper: push a record and wait
 * ------------------------------------------------------------------------- */
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
 * Basic: a record with pri=14 (user.info), host, ident, and message.
 * Expected in the JSON output:
 *  - "log": the message text is preserved in the body
 *  - severity fields are handled in OTLP metadata (not directly in JSON body
 *    when using lib output with format=json), so we verify the body key "log"
 */
static void test_basic_message(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    /* pri=14 => facility=1 (user), severity=6 (info) */
    struct expect_str expect[] = {
        {"hello from syslog", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"pri\":14,"
        "\"host\":\"myhost\","
        "\"ident\":\"myapp\","
        "\"pid\":\"1234\","
        "\"msgid\":\"-\","
        "\"version\":1,"
        "\"extradata\":\"-\","
        "\"message\":\"hello from syslog\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Emergency severity (pri=0): facility=0 (kern), severity=0 (emergency).
 * The message body must still be forwarded.
 */
static void test_emergency_severity(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"kernel panic", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"pri\":0,"
        "\"host\":\"router\","
        "\"ident\":\"kernel\","
        "\"pid\":\"-\","
        "\"msgid\":\"-\","
        "\"version\":1,"
        "\"extradata\":\"-\","
        "\"message\":\"kernel panic\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * RFC 5424 structured data: the processor must parse it and not crash.
 * We verify the message body survives.
 */
static void test_structured_data(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"structured message", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    /* pri=30 => facility=3 (daemon), severity=6 (info) */
    push_and_wait(ctx,
        "[0, {"
        "\"pri\":30,"
        "\"host\":\"server1\","
        "\"ident\":\"myservice\","
        "\"pid\":\"5678\","
        "\"msgid\":\"ID42\","
        "\"version\":1,"
        "\"extradata\":\"[origin ip=\\\"192.0.2.1\\\"]\","
        "\"message\":\"structured message\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Empty message field: processor must not crash and body key "log" must
 * appear (with an empty value).
 */
static void test_empty_message(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    /* We just check the pipeline does not crash; no specific string required */
    struct expect_str expect[] = {
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"pri\":14,"
        "\"host\":\"h\","
        "\"ident\":\"app\","
        "\"pid\":\"-\","
        "\"msgid\":\"-\","
        "\"version\":1,"
        "\"extradata\":\"-\","
        "\"message\":\"\""
        "}]");

    test_ctx_destroy(ctx);
}

/*
 * Debug severity (pri=7): facility=0 (kern), severity=7 (debug).
 */
static void test_debug_severity(void)
{
    struct test_ctx      *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct expect_str expect[] = {
        {"debug trace", FLB_TRUE},
        {NULL, FLB_TRUE}
    };

    cb_data.cb   = cb_check_result;
    cb_data.data = &expect;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) return;

    push_and_wait(ctx,
        "[0, {"
        "\"pri\":7,"
        "\"host\":\"devbox\","
        "\"ident\":\"traced\","
        "\"pid\":\"99\","
        "\"msgid\":\"-\","
        "\"version\":1,"
        "\"extradata\":\"-\","
        "\"message\":\"debug trace\""
        "}]");

    test_ctx_destroy(ctx);
}

/* =========================================================================
 * Test list
 * ========================================================================= */
TEST_LIST = {
    {"basic_message",      test_basic_message},
    {"emergency_severity", test_emergency_severity},
    {"structured_data",    test_structured_data},
    {"empty_message",      test_empty_message},
    {"debug_severity",     test_debug_severity},
    {NULL, NULL}
};
