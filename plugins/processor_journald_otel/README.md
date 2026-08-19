# processor_journald_otel

Maps the raw systemd journal fields produced by the `in_systemd` input plugin
onto the OpenTelemetry logs data model: log body, severity, log record
attributes and resource attributes.

The full mapping is documented in [`MAPPING.md`](./MAPPING.md).

## Usage

```yaml
pipeline:
  inputs:
    - name: systemd
      tag: journal
      processors:
        logs:
          - name: journald_otel

  outputs:
    - name: opentelemetry
      match: '*'
      host: otel-collector
      port: 4318
```

### Configuration parameters

| Key                 | Description                                                                                                                                        | Default   |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| `body_key`          | Record key that receives the journald `MESSAGE` field. `out_opentelemetry` uses it as the log record body (its `logs_body_key` default is `$log`, `$message`). | `message` |
| `strip_underscores` | Must match the `strip_underscores` setting of the `systemd` input, so that trusted fields such as `_PID` are still recognized.                       | `false`   |

## How resource attributes are represented

Fluent Bit carries resource attributes on the group records that wrap a run of
log records, not per record. A journal, however, interleaves entries from
different processes, so consecutive entries rarely share a resource.

The processor therefore wraps every run of consecutive records that share the
same resource in its own group. Records are **never reordered**: a resource
that reappears later in the chunk simply gets a second group.
`out_opentelemetry` merges groups with an identical resource again when it
builds the OTLP payload, so the wire format ends up with one
`resource_logs` entry per distinct resource.

If another processor has already wrapped the chunk in a group — for example
`opentelemetry_envelope` running before this one — the group layout is not
ours to decide, and the resource attributes of every record are folded into
that enclosing group instead.

## Behaviour details

- Fields with no mapping keep their journald name under a `journald.` prefix
  and their original value, so nothing from the journal is lost.
- Repeated journal fields, which `in_systemd` delivers as an array, are
  preserved as an array.
- A record without `MESSAGE` is kept with an empty body rather than dropped.
- The processor expects raw journal records. It is meant to run once, directly
  on the `systemd` input; applying it to already-mapped records would move the
  body key into the attributes.
