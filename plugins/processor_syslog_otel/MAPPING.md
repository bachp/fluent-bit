# RFC 5424 syslog to OpenTelemetry logs mapping

This processor implements the RFC 5424 example in the OpenTelemetry Logs Data
Model appendix. The appendix is an example rather than a normative
specification.

- [OpenTelemetry Logs Data Model appendix](https://opentelemetry.io/docs/specs/otel/logs/data-model-appendix/#rfc5424-syslog)
- [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html)

## Fields

| RFC 5424 field | Parser key | OpenTelemetry destination | Type |
| --- | --- | --- | --- |
| `TIMESTAMP` | `time` | `Timestamp` | timestamp |
| severity from `PRI` | `pri` | `SeverityNumber` / `SeverityText` | — |
| facility from `PRI` | `pri` | `Attributes["syslog.facility.code"]` | int |
| `VERSION` | implicit | `Attributes["syslog.version"]` | int |
| `HOSTNAME` | `host` | `Resource["host.name"]` | string |
| `APP-NAME` | `ident` | `Attributes["syslog.identifier"]` | string |
| `PROCID` | `pid` | `Attributes["syslog.procid"]` | string |
| `MSGID` | `msgid` | `Attributes["syslog.msg.id"]` | string |
| `origin.swVersion` | `extradata` | `Resource["service.version"]` | string |
| `origin.ip` | `extradata` | `Attributes["client.address"]` | string or array |
| other structured data | `extradata` | `Attributes["syslog.<SD-ID>.<PARAM-NAME>"]` | string or array |
| `MSG` | `message` | `Body` | string |

The built-in parser is specifically an RFC 5424 version 1 parser and does not
emit the version as a record key. The processor therefore sets
`syslog.version` to `1`.

The parser sets the Fluent Bit event timestamp from `time`. The processor
consumes the duplicate string but leaves the event timestamp unchanged.

## Priority and severity

RFC 5424 combines facility and severity in `PRI`:

```text
facility = PRI / 8
severity = PRI % 8
```

| Syslog severity | Name | `SeverityNumber` |
| --- | --- | --- |
| 0 | `emerg` | 21 |
| 1 | `alert` | 19 |
| 2 | `crit` | 18 |
| 3 | `err` | 17 |
| 4 | `warning` | 13 |
| 5 | `notice` | 10 |
| 6 | `info` | 9 |
| 7 | `debug` | 5 |

`PRI` must be a decimal integer from 0 through 191 without a leading zero.
Invalid values are preserved as `syslog.priority`.

## Structured data

The OpenTelemetry example does not define how to encode arbitrary SD-IDs and
parameter names into attribute keys. This processor uses the deterministic
form `syslog.<SD-ID>.<PARAM-NAME>`. RFC 5424 escapes `"`, `\`, and `]` in
parameter values; the processor removes those escapes. Repeated parameters are
represented as an array to avoid data loss.

If structured data is malformed, the processor keeps the original value as
`syslog.structured_data` instead of partially interpreting or dropping it.
