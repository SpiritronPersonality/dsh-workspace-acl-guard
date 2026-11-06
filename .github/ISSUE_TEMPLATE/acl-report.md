---
name: ACL report
about: Report a directory whose ACL was changed by DSH, or a false verdict
labels: [acl]
---

**Environment**

- DSH version:
- Windows version:
- Plugin version (`dsh plugin list` or `package.json`):

**What you saw**

<!-- White icons, unknown publisher, update failures, "cannot delete", etc. -->

**Redacted report**

Paste the output of `acl_status` (or `acl_scan`) here. **Remove user names, SIDs and
paths you do not want public** — replace them with `<user-sid>`, `<path>`.

```
```

**Journal entries**

If the change happened while the plugin was running, paste the matching line from
`$DSH_HOME/acl-guard/YYYY-MM.jsonl` (both `sddl` and `previousSddl`).

**Did removing the ACEs and restoring inheritance fix it?**

<!-- yes / no / not tried -->
