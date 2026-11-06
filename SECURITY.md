# Security policy

## What this plugin can do

- read Windows security descriptors (owner, DACL, SACL integrity label);
- compute effective `WRITE_DAC` / `WRITE_OWNER` for the current user;
- run `powershell.exe` as the current user, without elevation, for each probe;
- append JSONL records under `$DSH_HOME/acl-guard`.

## What it cannot do

- write, reset, or repair a security descriptor;
- change an owner, remove a deny entry, or edit inheritance;
- elevate (no UAC, no `runas`);
- access the network;
- replace, wrap, or disable any DSH service.

## Threat model

The plugin is a diagnostic. It is **not** a security boundary and does not make the sandbox
safer. A malicious actor who can already write to the plugin directory can replace the probe
script; treat the checkout and the installed package with the same trust as any other local
plugin.

The journal is plain text and contains paths, owner SIDs, and SDDL. It is stored under the
user's profile (`$DSH_HOME`) and is never uploaded. Redact SIDs and paths before sharing it.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer listed in
`package.json`. Please include the plugin version, the DSH version, and a minimal reproduction.
Do not include personal paths or SIDs.
