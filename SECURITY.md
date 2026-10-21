# Security policy

## Supported versions

Until the first stable release, only the latest tagged version and the current
default branch receive security fixes.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could expose
credentials, bypass artifact validation, forge receipts, or cause unsafe
provider actions. Use
[GitHub private vulnerability reporting](https://github.com/patcGM/closurectl/security/advisories/new)
and include:

- affected version or commit;
- impact and threat scenario;
- minimal reproduction;
- whether credential material may have been exposed;
- suggested remediation, if known.

The project will acknowledge a complete report within seven days and
coordinate disclosure based on impact and fix availability.

## High-priority areas

- receipt forgery or signature confusion;
- canonicalization inconsistencies;
- plaintext credential persistence;
- command injection in provider adapters;
- destructive behavior in a read-only command;
- minimum-cut errors that incorrectly report `CLOSED`;
- key overwrite or unsafe private-key handling;
- provider responses being interpreted as stronger evidence than they are.

## Safe testing

Use only accounts, organizations, packages, and infrastructure you own or have
explicit authorization to test. Do not include real credentials or personal
incident data in reports. A local demonstration can be generated with:

```bash
closurectl demo --dir closurectl-demo
```

## Security posture

Version 0.1 has no live mutation adapters. GitHub and npm adapters are
read-only and persist allow-listed metadata only. This significantly limits
impact but does not make the software suitable for unattended production
incident response.
