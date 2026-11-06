# Changelog

## 0.1.0 — 2026-11-06

First public release. Read-only by design.

- `acl-probe.ps1`: reads owner, DACL, SACL label, protection flag and effective
  `WRITE_DAC`/`WRITE_OWNER`; never writes a security descriptor.
- `detect.js`: parses SDDL, recognizes the current and legacy DSH signatures, classifies
  directory roles into risk levels.
- `journal.js`: local JSONL baseline and change journal under `$DSH_HOME/acl-guard`.
- Tools: `acl_status`, `acl_scan`, `acl_journal`.
- One-line system-prompt warning when the session workspace root is risky.
- Bilingual output (`zh` / `en`), no network, no native dependencies.
