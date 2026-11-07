# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities **privately**, through GitHub's private
advisory form:

<https://github.com/ibraimfarag/MIF/security/advisories/new>

That channel is end-to-end private between you and the maintainer. If you cannot use
it, open an issue that says only that you have a report and how to reach you — never
the details.

What to include: the version or commit, what you did, what happened, and what you
expected. A proof of concept helps; a working exploit is not required and should not be
sent for anything that could harm a third party.

## What to expect

This is a volunteer, single-maintainer project with no budget, so there is no formal
response time — but a security report is the one kind of message that gets read first.
Fixes are committed in the open, with the reasoning, because the whole threat model is
public (`docs/THREAT-MODEL.md`) and a silent fix would contradict it.

## Our Commitment

- No telemetry.
- No accounts.
- Full transparency (local SQLite storage).
- No kernel drivers (usermode protection only).
- Every privileged operation is written to `%PROGRAMDATA%\MICS\logs\priv.log`
  **before** it runs (`docs/PRIVILEGED-OPS.md`).
