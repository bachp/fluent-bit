# OpenTelemetry log mapping test stack

This Compose stack manually tests both log mapping processors end to end:

1. `in_systemd` -> `journald_otel` -> `out_opentelemetry`
2. `in_syslog` -> `syslog_otel` -> `out_opentelemetry`
3. OpenTelemetry Collector Contrib receives both streams over OTLP/HTTP and
   prints the decoded payload with the detailed `debug` exporter.

The Collector output shows resource attributes, log record attributes,
severity number and text, and the body. Compare it with the processor mapping
documents:

- [`journald_otel` mapping](../../plugins/processor_journald_otel/MAPPING.md)
- [`syslog_otel` mapping](../../plugins/processor_syslog_otel/MAPPING.md)

## Run the stack

```sh
docker compose up --build
```

You can also use Podman:

```sh
podman-compose up --build
```

## Test the journald mapping

Write an entry to the host journal:

```sh
echo "hello from journald" | systemd-cat -t demo -p err
```

The example reads only entries whose `SYSLOG_IDENTIFIER` is `demo`. This
prevents the Collector's detailed debug output from being read from journald
and sent back to the Collector.

The Collector output should include a plain string body, `SeverityText: err`,
`SeverityNumber: Error2(17)`, `host.name` and `process.*` resource attributes,
and unmapped fields under `journald.*`.

## Test the RFC 5424 syslog mapping

The stack exposes the Fluent Bit UDP syslog listener on host port 5514.

The preferred test client is `logger` from util-linux. Its RFC 5424 mode
constructs the header and structured data instead of requiring a hand-written
wire-format message:

```sh
logger \
  --server 127.0.0.1 \
  --port 5514 \
  --udp \
  --rfc5424 \
  --priority auth.crit \
  --tag demo \
  --id=123 \
  --msgid ID47 \
  --sd-id origin \
  --sd-param 'swVersion="1.2.3"' \
  --sd-param 'ip="192.0.2.1"' \
  --sd-id meta@32473 \
  --sd-param 'key="value"' \
  "hello from syslog"
```

This command uses the local hostname for the RFC 5424 `HOSTNAME` field.
Depending on the util-linux version and clock state, `logger` can also add a
`timeQuality` structured-data element.

To test an exact wire-format packet, use `printf` and netcat instead:

```sh
timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
header="<34>1 $timestamp mymachine.example.com demo 123 ID47"
structured_data='[origin swVersion="1.2.3" ip="192.0.2.1"][meta@32473 key="value"]'
printf '%s %s %s\n' "$header" "$structured_data" "hello from syslog" \
  | nc -u -w1 127.0.0.1 5514
```

The Collector output should include:

```text
Resource attributes:
     -> host.name: Str(mymachine.example.com)
     -> service.version: Str(1.2.3)
SeverityText: crit
SeverityNumber: Error2(18)
Body: Str(hello from syslog)
Attributes:
     -> syslog.version: Int(1)
     -> syslog.facility.code: Int(4)
     -> syslog.identifier: Str(demo)
     -> syslog.procid: Str(123)
     -> syslog.msg.id: Str(ID47)
     -> client.address: Str(192.0.2.1)
     -> syslog.meta@32473.key: Str(value)
```

Follow only the Collector output with:

```sh
docker compose logs -f otel-collector
```

## Podman and journald notes

- **SELinux:** The Compose file relabels only the two configuration files and
  disables SELinux separation for the Fluent Bit container. This lets the
  Collector read its configuration without changing the labels on the host
  journal directories.
- **Config permissions:** The diagnostic Collector runs as root so it can read
  bind-mounted configuration files from checkouts with a restrictive umask.
- **Journal permissions:** Rootless Podman normally cannot read the journal.
  Run the stack with `sudo podman-compose`, or add yourself to the
  `systemd-journal` group and use `--group-add keep-groups`.
- **Volatile journal:** If `/var/log/journal` does not exist, remove that bind
  mount. `/run/log/journal` is sufficient for a volatile journal.
