# Security policy

## Supported versions

This library is pre-1.0. Security fixes are released against the latest published
minor version. Until 1.0, only the most recent release line receives fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue for
a security problem.

- Preferred: use GitHub's private vulnerability reporting on this repository
  (the "Report a vulnerability" button under the Security tab).
- Include a description, affected versions, reproduction steps or a proof of
  concept, and the impact you expect.

## Response timeline

- Acknowledgement of a report: within 5 business days.
- Initial assessment and severity triage: within 10 business days.
- Fix and coordinated disclosure: targeted within 90 days, sooner for
  high-severity issues. We will keep you informed of progress and coordinate a
  disclosure date with you.

## Scope notes

This library speaks the SMTP submission protocol over a TLS socket. It always
performs certificate chain and hostname validation and does not expose any
option to disable validation. Reports about the on-device native TLS behavior of
the transport dependency (`react-native-tcp-socket`) should also be raised with
that project, but we want to hear about them so we can react (pin, document, or
work around).
