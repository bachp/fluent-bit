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

#include <msgpack.h>

#include "flb_tests_runtime.h"

static pthread_mutex_t so_result_mutex = PTHREAD_MUTEX_INITIALIZER;
static flb_sds_t so_output = NULL;

struct so_test {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
};

static void so_output_clear(void)
{
    pthread_mutex_lock(&so_result_mutex);
    if (so_output) {
        flb_sds_destroy(so_output);
        so_output = NULL;
    }
    pthread_mutex_unlock(&so_result_mutex);
}

static void so_append(const char *label, msgpack_object *object)
{
    char *json;

    if (!object) {
        return;
    }

    json = flb_msgpack_to_json_str(2048, object, FLB_FALSE);
    if (!json) {
        return;
    }

    if (!so_output) {
        so_output = flb_sds_create_size(2048);
    }

    flb_sds_cat_safe(&so_output, label, strlen(label));
    flb_sds_cat_safe(&so_output, json, strlen(json));
    flb_sds_cat_safe(&so_output, "\n", 1);
    flb_free(json);
}

static int cb_collect(void *record, size_t size, void *data)
{
    int result;
    int32_t record_type;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    result = flb_log_event_decoder_init(&decoder, (char *) record, size);
    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_free(record);
        return -1;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    pthread_mutex_lock(&so_result_mutex);

    while (flb_log_event_decoder_next(&decoder, &event) ==
           FLB_EVENT_DECODER_SUCCESS) {
        if (flb_log_event_decoder_get_record_type(&event, &record_type) != 0) {
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            so_append("group=", event.body);
        }
        else if (record_type == FLB_LOG_EVENT_NORMAL) {
            so_append("meta=", event.metadata);
            so_append("body=", event.body);
        }
    }

    pthread_mutex_unlock(&so_result_mutex);
    flb_log_event_decoder_destroy(&decoder);
    flb_free(record);

    return 0;
}

static struct so_test *so_test_create(struct flb_lib_out_cb *cb_data)
{
    int result;
    struct so_test *ctx;

    ctx = flb_calloc(1, sizeof(struct so_test));
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
        goto failure;
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
                                        "syslog_otel");
    if (!TEST_CHECK(ctx->pu != NULL)) {
        goto failure;
    }

    result = flb_input_set_processor(ctx->flb, ctx->i_ffd, ctx->proc);
    if (!TEST_CHECK(result == 0)) {
        goto failure;
    }

    return ctx;

failure:
    flb_destroy(ctx->flb);
    flb_free(ctx);
    return NULL;
}

static flb_sds_t so_run(const char **records, int count)
{
    int index;
    int result;
    flb_sds_t output;
    struct so_test *ctx;
    struct flb_lib_out_cb cb_data = {0};

    so_output_clear();
    cb_data.cb = cb_collect;
    ctx = so_test_create(&cb_data);
    if (!ctx) {
        return NULL;
    }

    result = flb_start(ctx->flb);
    if (!TEST_CHECK(result == 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    for (index = 0; index < count; index++) {
        flb_lib_push(ctx->flb, ctx->i_ffd, (char *) records[index],
                     strlen(records[index]));
    }

    sleep(2);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    pthread_mutex_lock(&so_result_mutex);
    output = so_output;
    so_output = NULL;
    pthread_mutex_unlock(&so_result_mutex);

    if (!TEST_CHECK(output != NULL)) {
        TEST_MSG("processor produced no output");
    }

    return output;
}

static void so_expect(flb_sds_t output, const char *needle)
{
    if (output && !TEST_CHECK(strstr(output, needle) != NULL)) {
        TEST_MSG("expected to find '%s' in:\n%s", needle, output);
    }
}

static void so_expect_absent(flb_sds_t output, const char *needle)
{
    if (output && !TEST_CHECK(strstr(output, needle) == NULL)) {
        TEST_MSG("did not expect to find '%s' in:\n%s", needle, output);
    }
}

static int so_count(flb_sds_t output, const char *needle)
{
    int count;
    size_t len;
    const char *position;

    if (!output) {
        return 0;
    }

    count = 0;
    len = strlen(needle);
    position = output;
    while ((position = strstr(position, needle)) != NULL) {
        count++;
        position += len;
    }

    return count;
}

#define SO_FULL_RECORD                                                     \
    "[0, {\"pri\":\"34\","                                                 \
    "\"time\":\"2003-10-11T22:14:15.003Z\","                              \
    "\"host\":\"mymachine.example.com\","                                  \
    "\"ident\":\"su\",\"pid\":\"-\",\"msgid\":\"ID47\","                   \
    "\"extradata\":\"-\","                                                 \
    "\"message\":\"'su root' failed for lonvick on /dev/pts/8\"}]"

static void test_header_body_and_severity(void)
{
    const char *records[] = {SO_FULL_RECORD};
    flb_sds_t output;

    output = so_run(records, 1);
    so_expect(output, "body={\"message\":\"'su root' failed for lonvick");
    so_expect(output, "\"syslog.version\":1");
    so_expect(output, "\"syslog.facility.code\":4");
    so_expect(output, "\"severity_number\":18");
    so_expect(output, "\"severity_text\":\"crit\"");
    so_expect(output, "\"syslog.identifier\":\"su\"");
    so_expect(output, "\"syslog.msg.id\":\"ID47\"");
    so_expect(output, "\"host.name\":\"mymachine.example.com\"");
    so_expect_absent(output, "\"syslog.procid\"");
    so_expect_absent(output, "\"pri\"");
    so_expect_absent(output, "\"time\"");

    if (output) {
        flb_sds_destroy(output);
    }
}

static void test_structured_data(void)
{
    const char *records[] = {
        "[0,{\"pri\":\"165\",\"time\":\"2003-10-11T22:14:15Z\","
        "\"host\":\"h\",\"ident\":\"app\",\"pid\":\"42\",\"msgid\":\"m\","
        "\"extradata\":\"[origin swVersion=\\\"1.2.3\\\" "
        "ip=\\\"192.0.2.1\\\"][meta@32473 key=\\\"a\\\\]b\\\" "
        "key=\\\"two\\\" Key=\\\"case-sensitive\\\"]\","
        "\"message\":\"ok\"}]"
    };
    flb_sds_t output;

    output = so_run(records, 1);
    so_expect(output, "\"service.version\":\"1.2.3\"");
    so_expect(output, "\"client.address\":\"192.0.2.1\"");
    so_expect(output, "\"syslog.meta@32473.key\":[\"a]b\",\"two\"]");
    so_expect(output, "\"syslog.meta@32473.Key\":\"case-sensitive\"");
    so_expect(output, "\"syslog.procid\":\"42\"");
    so_expect(output, "\"syslog.facility.code\":20");
    so_expect(output, "\"severity_number\":10");

    if (output) {
        flb_sds_destroy(output);
    }
}

static void test_invalid_values_are_preserved(void)
{
    const char *records[] = {
        "[0,{\"pri\":\"034\",\"time\":\"-\",\"host\":\"-\",\"ident\":\"-\","
        "\"pid\":\"-\",\"msgid\":\"-\","
        "\"extradata\":\"[partial key=\\\"value\\\"][broken\","
        "\"message\":\"bad\",\"source_host\":\"udp://192.0.2.2:514\"}]"
    };
    flb_sds_t output;

    output = so_run(records, 1);
    so_expect(output, "\"syslog.priority\":\"034\"");
    so_expect(output, "\"syslog.structured_data\":"
                      "\"[partial key=\\\"value\\\"][broken\"");
    so_expect(output, "\"source_host\":\"udp://192.0.2.2:514\"");
    so_expect_absent(output, "\"severity_number\"");
    so_expect_absent(output, "\"host.name\"");
    so_expect_absent(output, "\"syslog.identifier\"");
    so_expect_absent(output, "\"syslog.partial.key\"");

    if (output) {
        flb_sds_destroy(output);
    }
}

static void test_resource_grouping(void)
{
    const char *records[] = {
        "[0,{\"pri\":\"14\",\"time\":\"-\",\"host\":\"a\",\"ident\":\"x\","
        "\"pid\":\"-\",\"msgid\":\"-\",\"extradata\":\"-\","
        "\"message\":\"one\"}]",
        "[0,{\"pri\":\"14\",\"time\":\"-\",\"host\":\"a\",\"ident\":\"x\","
        "\"pid\":\"-\",\"msgid\":\"-\",\"extradata\":\"-\","
        "\"message\":\"two\"}]",
        "[0,{\"pri\":\"14\",\"time\":\"-\",\"host\":\"b\",\"ident\":\"x\","
        "\"pid\":\"-\",\"msgid\":\"-\",\"extradata\":\"-\","
        "\"message\":\"three\"}]"
    };
    flb_sds_t output;

    output = so_run(records, 3);
    if (!TEST_CHECK(so_count(output, "group=") == 2)) {
        TEST_MSG("expected 2 groups, got %d in:\n%s",
                 so_count(output, "group="), output ? output : "(null)");
    }

    if (output) {
        flb_sds_destroy(output);
    }
}

TEST_LIST = {
    {"header_body_and_severity",       test_header_body_and_severity},
    {"structured_data",                test_structured_data},
    {"invalid_values_are_preserved",   test_invalid_values_are_preserved},
    {"resource_grouping",              test_resource_grouping},
    {NULL, NULL}
};
