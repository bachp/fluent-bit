# processor_syslog_otel

Maps RFC 5424 fields produced by Fluent Bit's built-in
`syslog-rfc5424` parser onto the OpenTelemetry logs data model: log body,
severity, log record attributes, and resource attributes.

The full mapping is documented in [`MAPPING.md`](./MAPPING.md).

## Usage

```yaml
pipeline:
  inputs:
    - name: syslog
      mode: udp
      parser: syslog-rfc5424
      processors:
        logs:
          - name: syslog_otel

  outputs:
    - name: opentelemetry
      match: '*'
      host: otel-collector
      port: 4318
```

### Configuration parameters

| Key | Description | Default |
| --- | --- | --- |
| `body_key` | Record key that receives the RFC 5424 `MSG` field. `out_opentelemetry` uses it as the log record body. | `message` |

## Input contract

The processor consumes the keys emitted by the built-in
`syslog-rfc5424` parser: `pri`, `time`, `host`, `ident`, `pid`, `msgid`,
`extradata`, and `message`. The parser has already converted `time` to the
Fluent Bit event timestamp, so the processor removes that duplicate field and
does not change the event timestamp.

Use this processor with RFC 5424 records. The RFC 3164 parser does not provide
the protocol version, message ID, or structured data required by this mapping.

## Behavior details

- RFC 5424 NILVALUE (`-`) header fields are omitted.
- Invalid priorities are preserved as `syslog.priority` and do not set
  severity or facility.
- Structured-data parameters are flattened as
  `syslog.<SD-ID>.<PARAM-NAME>`.
- Repeated structured-data parameters are preserved as arrays.
- Malformed structured data is preserved unchanged as
  `syslog.structured_data`.
- Fields added by the syslog input or an earlier processor are retained as log
  attributes under their existing names.
- Records are grouped by `host.name` and `service.version` without reordering,
  using the same resource grouping model as `journald_otel`.
