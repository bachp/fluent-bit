set(src
    syslog_to_opentelemetry.c)

FLB_PLUGIN(processor_syslog_to_opentelemetry "${src}" "")
