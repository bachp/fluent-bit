### Description

This directory has a compose file (and its configuration) for manually testing
the `journald_otel` processor end to end:

1) Fluent Bit, built from the local repo source, running `in_systemd` ->
   `journald_otel` processor -> `out_opentelemetry` (logs only), reading the
   host journal read-only.
2) An OpenTelemetry Collector (contrib), receiving the logs over OTLP/HTTP and
   printing the decoded payload with the `debug` exporter at `detailed`
   verbosity.

The point of the `debug` exporter is that it prints the record exactly as the
collector understands it — resource attributes, log record attributes,
severity number/text and body — so the mapping can be checked field by field
against [`MAPPING.md`](../../plugins/processor_journald_otel/MAPPING.md).

### Running it

```
$ podman-compose up --build
```

Then, from the host, write something into the journal:

```
$ echo "hello from the host" | systemd-cat -t demo -p err
```

and watch the collector output. A mapped entry looks like this:

```
Resource SchemaURL:
Resource attributes:
     -> host.name: Str(myhost)
     -> process.pid: Int(13894)
     -> process.executable.name: Str(demo)
     -> process.executable.path: Str(/usr/bin/echo)
     -> process.command_line: Str(echo hello from the host)
ScopeLogs #0
LogRecord #0
ObservedTimestamp: 2026-08-19 12:00:00.123456789 +0000 UTC
Timestamp: 2026-08-19 12:00:00.123456 +0000 UTC
SeverityText: err
SeverityNumber: Error2(17)
Body: Str(hello from the host)
Attributes:
     -> syslog.identifier: Str(demo)
     -> syslog.facility.code: Int(3)
     -> journald._BOOT_ID: Str(...)
     -> journald._TRANSPORT: Str(journal)
```

Things worth checking in that output:

- the body is the plain `MESSAGE` string, not a map;
- `SeverityNumber` matches the `PRIORITY` of the entry (`-p err` above gives
  `Error2(17)`);
- `host.name` and the `process.*` attributes are on the **resource**, not on
  the log record;
- every field the data model does not name shows up under `journald.`, none
  are silently dropped.

### Notes for podman

- **SELinux.** On a system with SELinux in enforcing mode the bind mounts need
  a relabel or an exemption. The simplest thing for a throwaway test stack is
  to add `,z` to the config mounts; the journal directories should *not* be
  relabelled (they belong to the host's systemd), so run the Fluent Bit
  container with `--security-opt label=disable` instead, or use
  `podman-compose --podman-run-args="--security-opt label=disable" up`.

- **Journal permissions.** `/var/log/journal` is readable by root and by the
  `systemd-journal` group. Under rootless podman the container's root maps to
  your unprivileged user, which normally cannot read it — run the stack with
  `sudo podman-compose`, or add yourself to `systemd-journal` and pass the
  group through with `--group-add keep-groups`.

- If the host uses a volatile journal only, `/var/log/journal` does not exist
  and just `/run/log/journal` is needed; the missing bind mount can be removed
  from the compose file.

### Comparing against the collector's own journald receiver

The same mapping is implemented by the `journaldreceiver` of
opentelemetry-collector-contrib. To compare the two implementations on the
same journal, add a `journald` receiver to `config/otel-collector.yaml` and
attach it to the same `logs` pipeline — both sources then print through the
same `debug` exporter and the records can be diffed directly. Note that the
collector image must be able to read the host journal too, so it needs the
same mounts as the Fluent Bit service.
