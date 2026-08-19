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

#include <fluent-bit.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "flb_tests_runtime.h"

/*
 * The out_lib callback runs on the engine thread, so the rendered output is
 * collected under a mutex and inspected once the flush is known to be done.
 */
static pthread_mutex_t jo_result_mutex = PTHREAD_MUTEX_INITIALIZER;
static flb_sds_t jo_output = NULL;

struct jo_test {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
};

static void jo_output_clear(void)
{
    pthread_mutex_lock(&jo_result_mutex);
    if (jo_output) {
        flb_sds_destroy(jo_output);
        jo_output = NULL;
    }
    pthread_mutex_unlock(&jo_result_mutex);
}

static flb_sds_t jo_output_take(void)
{
    flb_sds_t out;

    pthread_mutex_lock(&jo_result_mutex);
    out = jo_output;
    jo_output = NULL;
    pthread_mutex_unlock(&jo_result_mutex);

    return out;
}

static void jo_append(const char *label, msgpack_object *obj)
{
    char *json;

    if (!obj) {
        return;
    }

    json = flb_msgpack_to_json_str(1024, obj, FLB_FALSE);
    if (!json) {
        return;
    }

    if (!jo_output) {
        jo_output = flb_sds_create_size(1024);
    }

    flb_sds_cat_safe(&jo_output, label, strlen(label));
    flb_sds_cat_safe(&jo_output, json, strlen(json));
    flb_sds_cat_safe(&jo_output, "\n", 1);

    flb_free(json);
}

/*
 * Render every record of the flush -- group records included -- as labelled
 * JSON lines so the assertions below can be simple substring checks.
 */
static int cb_collect(void *record, size_t size, void *data)
{
    int ret;
    int32_t record_type;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    ret = flb_log_event_decoder_init(&decoder, (char *) record, size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_free(record);
        return -1;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    pthread_mutex_lock(&jo_result_mutex);

    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        if (flb_log_event_decoder_get_record_type(&event, &record_type) != 0) {
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            jo_append("group=", event.body);
        }
        else if (record_type == FLB_LOG_EVENT_NORMAL) {
            jo_append("meta=", event.metadata);
            jo_append("body=", event.body);
        }
    }

    pthread_mutex_unlock(&jo_result_mutex);

    flb_log_event_decoder_destroy(&decoder);
    flb_free(record);

    return 0;
}

static struct jo_test *jo_test_create(struct flb_lib_out_cb *cb_data)
{
    int ret;
    struct jo_test *ctx;

    ctx = flb_calloc(1, sizeof(struct jo_test));
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    ctx->flb = flb_create();
    if (!TEST_CHECK(ctx->flb != NULL)) {
        flb_free(ctx);
        return NULL;
    }

    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->proc = flb_processor_create(ctx->flb->config, "unit_test", NULL, 0);
    if (!TEST_CHECK(ctx->proc != NULL)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    ctx->i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    if (!TEST_CHECK(ctx->i_ffd >= 0)) {
        goto failure;
    }
    flb_input_set(ctx->flb, ctx->i_ffd, "tag", "test", NULL);

    ctx->o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) cb_data);
    if (!TEST_CHECK(ctx->o_ffd >= 0)) {
        goto failure;
    }
    flb_output_set(ctx->flb, ctx->o_ffd, "match", "test", NULL);

    ctx->pu = flb_processor_unit_create(ctx->proc, FLB_PROCESSOR_LOGS,
                                        "journald_otel");
    if (!TEST_CHECK(ctx->pu != NULL)) {
        goto failure;
    }

    ret = flb_input_set_processor(ctx->flb, ctx->i_ffd, ctx->proc);
    if (!TEST_CHECK(ret == 0)) {
        goto failure;
    }

    return ctx;

failure:
    flb_destroy(ctx->flb);
    flb_free(ctx);

    return NULL;
}

static void jo_test_destroy(struct jo_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

/* Push a set of JSON records through the processor and return the rendering */
static flb_sds_t jo_run(const char **records, int count)
{
    int i;
    int ret;
    flb_sds_t out;
    struct jo_test *ctx;
    struct flb_lib_out_cb cb_data = {0};

    jo_output_clear();

    cb_data.cb = cb_collect;
    cb_data.data = NULL;

    ctx = jo_test_create(&cb_data);
    if (!ctx) {
        return NULL;
    }

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        jo_test_destroy(ctx);
        return NULL;
    }

    for (i = 0; i < count; i++) {
        flb_lib_push(ctx->flb, ctx->i_ffd, (char *) records[i],
                     strlen(records[i]));
    }

    /* let the engine flush */
    sleep(2);

    jo_test_destroy(ctx);

    out = jo_output_take();
    if (!TEST_CHECK(out != NULL)) {
        TEST_MSG("processor produced no output");
    }

    return out;
}

static void jo_expect(flb_sds_t out, const char *needle)
{
    if (!out) {
        return;
    }

    if (!TEST_CHECK(strstr(out, needle) != NULL)) {
        TEST_MSG("expected to find '%s' in:\n%s", needle, out);
    }
}

static void jo_expect_absent(flb_sds_t out, const char *needle)
{
    if (!out) {
        return;
    }

    if (!TEST_CHECK(strstr(out, needle) == NULL)) {
        TEST_MSG("did not expect to find '%s' in:\n%s", needle, out);
    }
}

/* count non-overlapping occurrences of 'needle' */
static int jo_count(flb_sds_t out, const char *needle)
{
    int count = 0;
    const char *p = out;
    size_t len = strlen(needle);

    if (!out) {
        return 0;
    }

    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += len;
    }

    return count;
}

/* A single fully populated journal entry, as in_systemd would deliver it */
#define JO_FULL_RECORD                                                     \
    "[0, {\"MESSAGE\": \"unit started\","                                  \
    " \"PRIORITY\": \"3\","                                                \
    " \"CODE_FILE\": \"../src/core/unit.c\","                              \
    " \"CODE_FUNC\": \"unit_log_success\","                                \
    " \"CODE_LINE\": \"5487\","                                            \
    " \"SYSLOG_FACILITY\": \"3\","                                         \
    " \"SYSLOG_IDENTIFIER\": \"systemd\","                                 \
    " \"SYSLOG_PID\": \"1234\","                                           \
    " \"SYSLOG_TIMESTAMP\": \"Apr 16 15:17:06\","                          \
    " \"_HOSTNAME\": \"myhost\","                                          \
    " \"_PID\": \"13894\","                                                \
    " \"_COMM\": \"systemd\","                                             \
    " \"_EXE\": \"/usr/lib/systemd/systemd\","                             \
    " \"_CMDLINE\": \"/lib/systemd/systemd --user\","                      \
    " \"_BOOT_ID\": \"c4fa36de\","                                         \
    " \"_TRANSPORT\": \"journal\","                                        \
    " \"TID\": \"777\"}]"

static void test_body_and_severity(void)
{
    const char *records[] = {JO_FULL_RECORD};
    flb_sds_t out = jo_run(records, 1);

    /* MESSAGE becomes the log body under the default 'message' key */
    jo_expect(out, "body={\"message\":\"unit started\"}");

    /* PRIORITY 3 (err) maps to SeverityNumber 17 */
    jo_expect(out, "\"severity_number\":17");
    jo_expect(out, "\"severity_text\":\"err\"");

    /* the consumed fields must not survive anywhere */
    jo_expect_absent(out, "\"MESSAGE\"");
    jo_expect_absent(out, "\"PRIORITY\"");
    jo_expect_absent(out, "journald.MESSAGE");
    jo_expect_absent(out, "journald.PRIORITY");

    if (out) {
        flb_sds_destroy(out);
    }
}

static void test_log_attributes(void)
{
    const char *records[] = {JO_FULL_RECORD};
    flb_sds_t out = jo_run(records, 1);

    jo_expect(out, "\"code.file.path\":\"../src/core/unit.c\"");
    jo_expect(out, "\"code.function.name\":\"unit_log_success\"");
    jo_expect(out, "\"syslog.identifier\":\"systemd\"");
    jo_expect(out, "\"syslog.timestamp\":\"Apr 16 15:17:06\"");

    /* numeric conventions are converted from their journald string form */
    jo_expect(out, "\"code.line.number\":5487");
    jo_expect(out, "\"syslog.facility.code\":3");
    jo_expect(out, "\"syslog.pid\":1234");

    /* original names are gone */
    jo_expect_absent(out, "\"CODE_FILE\"");
    jo_expect_absent(out, "\"SYSLOG_IDENTIFIER\"");
    jo_expect_absent(out, "\"SYSLOG_TIMESTAMP\"");

    if (out) {
        flb_sds_destroy(out);
    }
}

static void test_unmapped_fields(void)
{
    const char *records[] = {JO_FULL_RECORD};
    flb_sds_t out = jo_run(records, 1);

    /*
     * Fields without a semantic convention mapping keep their journald name
     * under the "journald." prefix and their original string type. TID has no
     * mapping in the data model, so it is not promoted to thread.id.
     */
    jo_expect(out, "\"journald._BOOT_ID\":\"c4fa36de\"");
    jo_expect(out, "\"journald._TRANSPORT\":\"journal\"");
    jo_expect(out, "\"journald.TID\":\"777\"");
    jo_expect_absent(out, "thread.id");

    if (out) {
        flb_sds_destroy(out);
    }
}

static void test_resource_attributes(void)
{
    const char *records[] = {JO_FULL_RECORD};
    flb_sds_t out = jo_run(records, 1);

    /* host and process fields live on the group, not on the record */
    jo_expect(out, "group=");
    jo_expect(out, "\"host.name\":\"myhost\"");
    jo_expect(out, "\"process.pid\":13894");
    jo_expect(out, "\"process.executable.name\":\"systemd\"");
    jo_expect(out, "\"process.executable.path\":\"/usr/lib/systemd/systemd\"");
    jo_expect(out, "\"process.command_line\":\"/lib/systemd/systemd --user\"");

    jo_expect_absent(out, "\"_HOSTNAME\"");
    jo_expect_absent(out, "\"_CMDLINE\"");
    jo_expect_absent(out, "journald._PID");

    if (out) {
        flb_sds_destroy(out);
    }
}

/* every syslog priority maps to the SeverityNumber of appendix B */
static void test_severity_mapping(void)
{
    int i;
    char buf[256];
    const char *records[8];
    const char *expected[8] = {
        "\"severity_number\":21", "\"severity_number\":19",
        "\"severity_number\":18", "\"severity_number\":17",
        "\"severity_number\":13", "\"severity_number\":10",
        "\"severity_number\":9",  "\"severity_number\":5"
    };
    const char *texts[8] = {
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
    };
    flb_sds_t out;

    for (i = 0; i < 8; i++) {
        snprintf(buf, sizeof(buf),
                 "[0, {\"MESSAGE\": \"m\", \"PRIORITY\": \"%d\","
                 " \"_HOSTNAME\": \"h\"}]", i);
        records[i] = flb_strdup(buf);
    }

    out = jo_run(records, 8);

    for (i = 0; i < 8; i++) {
        jo_expect(out, expected[i]);

        snprintf(buf, sizeof(buf), "\"severity_text\":\"%s\"", texts[i]);
        jo_expect(out, buf);

        flb_free((void *) records[i]);
    }

    if (out) {
        flb_sds_destroy(out);
    }
}

/* a PRIORITY that is not a syslog level is kept as a plain attribute */
static void test_invalid_priority(void)
{
    const char *records[] = {
        "[0, {\"MESSAGE\": \"m\", \"PRIORITY\": \"9\", \"_HOSTNAME\": \"h\"}]"
    };
    flb_sds_t out = jo_run(records, 1);

    jo_expect(out, "\"journald.PRIORITY\":\"9\"");
    jo_expect_absent(out, "severity_number");

    if (out) {
        flb_sds_destroy(out);
    }
}

/* a numeric convention whose value is not a number keeps the original string */
static void test_non_numeric_value(void)
{
    const char *records[] = {
        "[0, {\"MESSAGE\": \"m\", \"CODE_LINE\": \"not-a-number\","
        " \"_HOSTNAME\": \"h\"}]"
    };
    flb_sds_t out = jo_run(records, 1);

    jo_expect(out, "\"code.line.number\":\"not-a-number\"");

    if (out) {
        flb_sds_destroy(out);
    }
}

/*
 * Records that share a resource end up in one group; a different resource
 * opens a new one. Records are never reordered, so the run of two 'a' records
 * followed by a 'b' record produces exactly two groups.
 */
static void test_grouping(void)
{
    const char *records[] = {
        "[0, {\"MESSAGE\": \"one\", \"_HOSTNAME\": \"h\", \"_PID\": \"1\"}]",
        "[0, {\"MESSAGE\": \"two\", \"_HOSTNAME\": \"h\", \"_PID\": \"1\"}]",
        "[0, {\"MESSAGE\": \"three\", \"_HOSTNAME\": \"h\", \"_PID\": \"2\"}]"
    };
    flb_sds_t out = jo_run(records, 3);

    if (!TEST_CHECK(jo_count(out, "group=") == 2)) {
        TEST_MSG("expected 2 groups, got %d in:\n%s", jo_count(out, "group="),
                 out ? out : "(null)");
    }

    jo_expect(out, "\"process.pid\":1");
    jo_expect(out, "\"process.pid\":2");

    if (out) {
        flb_sds_destroy(out);
    }
}

/* a record without any trusted field still gets a group, with no attributes */
static void test_no_resource_fields(void)
{
    const char *records[] = {
        "[0, {\"MESSAGE\": \"orphan\", \"PRIORITY\": \"6\"}]"
    };
    flb_sds_t out = jo_run(records, 1);

    jo_expect(out, "body={\"message\":\"orphan\"}");
    jo_expect(out, "\"attributes\":{}");
    jo_expect(out, "\"severity_number\":9");

    if (out) {
        flb_sds_destroy(out);
    }
}

/* a record with no MESSAGE produces an empty body rather than being dropped */
static void test_missing_message(void)
{
    const char *records[] = {
        "[0, {\"PRIORITY\": \"4\", \"_HOSTNAME\": \"h\","
        " \"_TRANSPORT\": \"kernel\"}]"
    };
    flb_sds_t out = jo_run(records, 1);

    jo_expect(out, "body={}");
    jo_expect(out, "\"severity_number\":13");
    jo_expect(out, "\"journald._TRANSPORT\":\"kernel\"");

    if (out) {
        flb_sds_destroy(out);
    }
}

TEST_LIST = {
    {"body_and_severity",    test_body_and_severity},
    {"log_attributes",       test_log_attributes},
    {"unmapped_fields",      test_unmapped_fields},
    {"resource_attributes",  test_resource_attributes},
    {"severity_mapping",     test_severity_mapping},
    {"invalid_priority",     test_invalid_priority},
    {"non_numeric_value",    test_non_numeric_value},
    {"grouping",             test_grouping},
    {"no_resource_fields",   test_no_resource_fields},
    {"missing_message",      test_missing_message},
    {NULL, NULL}
};
