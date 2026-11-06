# dsh-workspace-acl-guard

A read-only DSH plugin that makes the Windows sandbox's **workspace ACL side effects** visible.

> DSH's Windows sandbox needs the restricted child to write the workspace, so it permanently
> rewrites the workspace root's security descriptor: a capability SID allow ACE, an
> `Everyone` delete deny, and a Low integrity label. The change survives the session.
> On a Desktop or an application directory that can break things that look unrelated to DSH.
> See [docs/REPORT.en.md](docs/REPORT.en.md) (中文: [docs/REPORT.zh.md](docs/REPORT.zh.md)).

This plugin **does not fix or prevent** that rewrite. It answers three questions, safely:

1. **Is this workspace root risky?** — before the first command runs.
2. **Has it already been touched?** — with the exact ACEs and label that prove it.
3. **When did it change?** — a local journal of security-descriptor baselines and diffs.

## What it does

- reads owner, DACL, SACL integrity label, protection flag and effective `WRITE_DAC`/`WRITE_OWNER`;
- recognizes the current DSH signature (capability SID + delete-child deny + Low label) and the
  legacy one (protected DACL + `Delete` deny + Medium label);
- classifies the directory's role (Desktop, application directory, repository, plain directory…)
  and turns it into a risk level;
- records a baseline the first time it sees a path, and every later change, into
  `$DSH_HOME/acl-guard/YYYY-MM.jsonl`;
- contributes **one warning line** to the system prompt when the current workspace root is risky;
- exposes `acl_status`, `acl_scan` and `acl_journal` tools.

## What it never does

- **writes no ACL** — no `SetNamedSecurityInfo`, no owner change, no deny removal;
- wraps or replaces no DSH service, and never disables the sandbox;
- never throws out of `apply()`: a failure disables this plugin only;
- sends nothing over the network and records nothing outside `$DSH_HOME/acl-guard`.

## Install

### From npm (recommended)

```sh
dsh plugin --profile <profile> add dsh-workspace-acl-guard
```

or install it from the Web **Plugins** page.

### From a local checkout

```sh
git clone https://github.com/<you>/dsh-workspace-acl-guard
dsh plugin --profile <profile> add "<absolute path to the checkout>"
```

### Standalone, without DSH

The probe and detector also run as a plain CLI:

```sh
node scripts/selftest.mjs "C:\Users\me\Desktop" "C:\work" --known
```

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `locale` | `zh` | Output language: `zh` or `en`. |
| `watch` | `true` | Background watcher over the session workspace and known folders. |
| `intervalMs` | `15000` | Watcher period (5s–10min). |
| `scanKnownFolders` | `true` | Include the Windows known folders in every tick. |

Example:

```yaml
- insert:
    - id: workspace-acl-guard
      name: 'dsh-workspace-acl-guard'
      config:
        locale: en
        watch: true
        intervalMs: 15000
```

## Tools

### `acl_status`

Inspect one directory (defaults to the session workspace root). Returns the verdict
(`ok` / `polluted` / `will-fail` / `risky-root` / `unknown`), the role, rights, label,
signature, evidence and the recommended next step.

### `acl_scan`

Scan the Windows known folders plus any extra paths. Prints a count and every non-ok entry.

### `acl_journal`

Read the local journal. Each line records `ts`, `event` (`baseline` / `change`), path,
signature, `writeDac`, `writeOwner`, the full SDDL and the previous SDDL.

## How detection works

`probe → analyze`:

1. `assets/acl-probe.ps1` reads the descriptor with `GetNamedSecurityInfoW(OWNER|DACL|SACL)`
   and evaluates effective rights against the current token (user + groups).
2. `lib/detect.js` parses the SDDL into ACEs and looks for:
   - an allow ACE whose trustee is `S-1-4-*` (DSH's derived capability SID);
   - an `Everyone` deny of `FILE_DELETE_CHILD (0x40)` or `DELETE (0x10000)`;
   - a `Low` mandatory label (`LW`);
   - a protected DACL (`D:P…`).
3. The directory role comes from the Windows known-folder list and simple markers
   (`.git`, an `.exe`/`.dll` in the root).

## Risk model

| Role | Level |
|---|---|
| Desktop, Documents, Downloads, OneDrive, Start Menu, Startup, profile root, drive root, Windows, Program Files, `DSH_HOME` | critical |
| Application directory (an `.exe`/`.dll` at the root) | high |
| Repository (`.git`) | medium |
| Plain directory | low |

A recognized DSH signature raises the level to at least `high`; on a critical role it becomes
`critical`. A directory without `WRITE_DAC`/`WRITE_OWNER` is reported as `will-fail`: DSH's
first grant fails with Win32 error 5 and every command asks for approval again.

## Limitations

- **Read-only by design.** It reports and warns; it does not clean ACEs. The report contains
  the exact `icacls` commands, and you run them yourself.
- **Signature coverage is best effort.** At least two DSH generations write different ACEs;
  unknown mutations are reported as evidence, not as a verdict.
- **Windows only.** On other platforms the plugin registers nothing.
- **PowerShell 5.1 is required** (present on every supported Windows). The interpreter can be
  overridden with `DSH_ACL_GUARD_POWERSHELL`.
- The exact shell-parsing mechanism behind the icon/localized-name failure is still unproven;
  see the report's “Unconfirmed” section.

## Privacy

The journal contains paths, owner SIDs and SDDL. It stays local, is never uploaded, and can be
deleted at any time. Tool output may contain SIDs; redact before pasting into an issue.

## Development

```sh
npm test
node scripts/selftest.mjs "C:\work"
```

## License

MIT
