set(src
    journald_to_opentelemetry.c)

FLB_PLUGIN(processor_journald_to_opentelemetry "${src}" "")
