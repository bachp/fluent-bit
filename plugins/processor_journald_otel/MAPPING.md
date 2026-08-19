# systemd journal to OpenTelemetry logs mapping

This is the mapping the processor implements. It follows the "Appendix A"
systemd-journald example of the OpenTelemetry logs data model
([`specification/logs/data-model-appendix.md`][spec]) and the severity mapping
of its Appendix B.

[spec]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model-appendix.md

## Fields

| journald field           | OpenTelemetry destination                     | Type    |
| ------------------------ | --------------------------------------------- | ------- |
| `__REALTIME_TIMESTAMP`   | `Timestamp`                                    | —       |
| `MESSAGE`                | `Body`                                         | string  |
| `PRIORITY`               | `SeverityNumber` / `SeverityText`              | —       |
| `CODE_FILE`              | `Attributes["code.file.path"]`                 | string  |
| `CODE_FUNC`              | `Attributes["code.function.name"]`             | string  |
| `CODE_LINE`              | `Attributes["code.line.number"]`               | int     |
| `SYSLOG_FACILITY`        | `Attributes["syslog.facility.code"]`           | int     |
| `SYSLOG_IDENTIFIER`      | `Attributes["syslog.identifier"]`              | string  |
| `SYSLOG_PID`             | `Attributes["syslog.pid"]`                     | int     |
| `SYSLOG_TIMESTAMP`       | `Attributes["syslog.timestamp"]`               | string  |
| `_HOSTNAME`              | `Resource["host.name"]`                        | string  |
| `_PID`                   | `Resource["process.pid"]`                      | int     |
| `_COMM`                  | `Resource["process.executable.name"]`          | string  |
| `_EXE`                   | `Resource["process.executable.path"]`          | string  |
| `_CMDLINE`               | `Resource["process.command_line"]`             | string  |
| *anything else*          | `Attributes["journald.<FIELD>"]`               | as-is   |

`__REALTIME_TIMESTAMP` needs no handling here: `in_systemd` already takes the
event timestamp from the journal realtime clock and does not surface the field
in the record.

Fields listed as `int` are converted from their journald string form. A value
that does not parse as an integer is kept as the original string rather than
being dropped, so no data is lost on a malformed entry.

## Severity

`PRIORITY` carries a syslog severity level (RFC 5424 section 6.2.1). It is
mapped per Appendix B of the data model:

| `PRIORITY` | syslog name | `SeverityNumber`  | `SeverityText` |
| ---------- | ----------- | ----------------- | -------------- |
| 0          | emerg       | 21 (`FATAL2`)     | `emerg`        |
| 1          | alert       | 19 (`ERROR4`)     | `alert`        |
| 2          | crit        | 18 (`ERROR3`)     | `crit`         |
| 3          | err         | 17 (`ERROR2`)     | `err`          |
| 4          | warning     | 13 (`WARN`)       | `warning`      |
| 5          | notice      | 10 (`INFO2`)      | `notice`       |
| 6          | info        | 9 (`INFO`)        | `info`         |
| 7          | debug       | 5 (`DEBUG`)       | `debug`        |

A `PRIORITY` outside `0..7` is not a syslog level; it is kept as
`Attributes["journald.PRIORITY"]` and no severity is set.

## Notes on two entries

`SYSLOG_IDENTIFIER` is documented by systemd as the equivalent of the RFC 5424
`APP-NAME`, which the data model maps to `syslog.identifier` — not to
`Resource["service.name"]`. A journal is a host-level stream that mixes many
programs; deriving a service identity from it would be wrong.

`SYSLOG_PID` maps to `syslog.pid` and not to the RFC 5424 `syslog.procid`:
journald defines it as the numeric PID of the client, whereas RFC 5424
`PROCID` is an implementation-defined string that need not be a process ID.
