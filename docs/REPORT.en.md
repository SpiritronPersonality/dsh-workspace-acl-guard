# Defect report: the DSH sandbox writes a persistent security descriptor onto the workspace root

**Product**: DeepSeek Harness (Windows desktop client)
**Platform**: Windows 11, Simplified Chinese (single-user workstation)
**Affected versions**: 0.2.x (this report follows the 0.2.2-rc.1 code path and field samples; earlier builds used a different signature, see §5)
**Severity**: High — the symptoms have nothing to do with DSH, so users blame Windows; it already caused two OS reinstalls
**Status**: Mechanism located, machine repaired; upstream fix recommended

> Public version: user SIDs, account names and some paths are replaced with placeholders.

---

## 1. Summary

When DSH runs its first confined command in `workspace-write` mode on Windows, it performs a **persistent** security-descriptor rewrite on the **session workspace root**. One `SetNamedSecurityInfoW` call writes three things at once:

1. an allow ACE for a capability SID (`S-1-4-*`) deterministically derived from the workspace path;
2. a `Everyone` deny of `FILE_DELETE_CHILD` ("delete subfolders and files");
3. a Low integrity label (`no-write-up`, inheritable).

The rewrite is **not rolled back when the session ends** — the source comments call it resident, cached, never revoked. When the workspace is a real directory such as the Desktop, Documents, or an application folder, the directory leaves the Windows inheritance chain and its default policy. The resulting failures look unrelated to DSH: every desktop shortcut turns into a generic white icon, the localized folder name falls back to `Desktop`, and double-clicking reports an unknown publisher. On application directories and code repositories the failures are harder to attribute: "cannot save", "update failed", "cannot delete", "build broke".

This report contains two field samples, code-level evidence, a minimal reproduction, and a read-only detection tool published with this repository.

---

## 2. Symptoms

### 2.1 Desktop (most visible)

- Every `.lnk` icon on the Desktop becomes the generic shortcut icon; folder icons stay normal; double-click still opens.
- The Desktop folder's display name falls back from the localized name to `Desktop`; sibling folders keep their localized names.
- Double-clicking a shortcut reports "unknown publisher".
- All of this appears **only after the icon cache is rebuilt** (installing software, restarting Explorer, cleanup tools), so it looks like "fine yesterday, broken today".

### 2.2 Any workspace (silent)

The same rewrite happens on any directory used as a workspace. The second field sample is a subdirectory inside a project (`<PROJECT>\XIANGLING`); its DACL is still protected and still carries a capability SID and an `Everyone` deny:

```
D:PAI(D;CI;DT;;;WD)(A;OICI;0x110156;;;S-1-4-<CAP>)(A;;FA;;;BA)...
S:AI(ML;OICI;NW;;;ME)
```

There are no icons to break there, so nobody notices — but the directory has left its inheritance chain, and any tool that relies on Windows defaults (installers, updaters, backup/sync, restricted-token processes) can misbehave.

**This is not a Desktop problem. It is a workspace-root problem; the Desktop is merely the most observable sample.**

---

## 3. Field evidence

### 3.1 Sample A: Desktop

`icacls` shows two **explicit (non-inherited)** entries:

| Trustee | Type | Rights | Inheritance |
|---|---|---|---|
| `Everyone` | Deny | Delete subfolders and files | explicit |
| `S-1-4-<CAP>` | Allow | Delete subfolders and files / Write / Delete | explicit |

On the same machine, `Documents` has only three **inherited** entries (SYSTEM / Administrators / the user) and no explicit entry.

Evidence for attribution:

1. the entries appear only after DSH has used that directory as a workspace;
2. they return after two OS reinstalls — as soon as DSH uses the directory again;
3. `S-1-4-*` is NT NON UNIQUE AUTHORITY, not a principal Windows assigns to ordinary users or groups.

### 3.2 Sample B: a project directory

See §2.2. Its label is `ME` (Medium) and its deny is `DT` (Delete), unlike the 0.2.2 shape (`0x40` deny + Low label). At least two generations of the write signature exist — which is exactly why signature matching alone is not enough.

### 3.3 Repair works

After removing both entries, restoring inheritance, and rebuilding the icon cache: icons are colored again, the localized name returns, double-click no longer warns.

**Verified: removing the ACEs clears the symptoms.**
**Not verified: why these entries break shell parsing (see §7).**

---

## 4. Code-level evidence (0.2.2-rc.1)

In `@deepseek-ai/dsh-sandbox-windows-acl`:

- reads the current descriptor with `GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL|LABEL)`;
- merges three entries and writes them in **one** `SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL|LABEL, ...)`;
- the capability SID is **deterministically derived** from the normalized workspace path;
- the deny is `Everyone` + `FILE_DELETE_CHILD (0x40)`, container-inherited only;
- the label is a `SYSTEM_MANDATORY_LABEL_ACE` pointing at Low (`S-1-16-4096`), `no-write-up`, inheritable;
- the workspace grant is **resident**: it survives the session and instance disposal; only temporary grants are revoked.

Precondition (relevant to the second failure mode):

- the granted directory must be owned by the caller or explicitly grant `WRITE_OWNER` (the label lives in the SACL, and the merged write needs it);
- when the directory is owned by **another account** and the current user only has inherited Modify (typical after a reinstall over an old data disk), the grant fails with Win32 error 5;
- the command then cannot run inside the sandbox. In the field this looked like **an approval prompt on every single command** — the user reads it as "the sandbox is broken".

The field `acl-report` from 2026-11-05 records: owner is an old account SID, `writeDac=false`, classification `PRECONDITION`, repair refused. A one-off administrator grant of `FullControl` fixed it.

---

## 5. Why it is hard to attribute

1. **The symptoms are outside DSH**: white icons, an English folder name, an unknown-publisher warning — users blame Windows, antivirus, or themselves.
2. **Delayed appearance**: the rewrite happens on the first command, but the failure waits for an icon-cache rebuild.
3. **No logs**: the rewrite is silent; DSH shows nothing, and Windows event logs have no matching entry.
4. **Repairs "succeed" and do nothing**: `sfc`, `DISM`, cumulative-update reinstall, in-place reinstall, icon-cache rebuild — all succeed, none help.
5. **Two reinstalls**: the ACL state is preserved across reinstalls, so reinstalling does not help but does destroy the development environment and some desktop files.

---

## 6. Minimal reproduction

> Use a disposable test machine or VM; do not try this on a production Desktop.

1. Clean Windows 11 (Simplified Chinese); place three shortcuts to different `exe` files on the Desktop.
2. Record the baseline: `icacls "%USERPROFILE%\Desktop"`; confirm colored icons and the localized name.
3. Set the DSH workspace to `%USERPROFILE%\Desktop`; run one write/rename.
4. Run `icacls` again: the two explicit entries from §3.1 should appear.
5. Record the integrity label (`icacls` cannot show it; read the SACL). Expected shape: `...S:AI(ML;OICI;NW;;;ME)`; `ME` = Medium (normal), `LW` = Low (newer DSH builds write this).
6. Close the DSH session — the entries **remain**.
7. Rebuild the icon cache / restart Explorer / reboot.
8. Observe: every `.lnk` turns white, `Desktop` replaces the localized name, double-click warns about an unknown publisher.
9. Clean up and restore inheritance:

```bat
icacls "%USERPROFILE%\Desktop" /remove:d Everyone
icacls "%USERPROFILE%\Desktop" /remove:g *S-1-4-<CAP>
icacls "%USERPROFILE%\Desktop" /inheritance:e
```

10. Rebuild the cache and observe.

`docs/REPRODUCE.ps1` in this repository automates steps 2, 4 and 5: it captures both the DACL and the label and prints a before/after table.

---

## 7. Verified vs unverified

**Verified**

- the rewrite is real, explicit and repeatable;
- it survives session end;
- removing it clears the symptoms (at least one case, Desktop).

**Unverified (hypotheses)**

- why the two entries break shell icon and localized-name parsing. The captured deny only covers "delete subfolders and files", which should not block reads. The actual cause may be:
  - the Low integrity label (`no-write-up`) being rejected on the shell's restricted-token / AppContainer path;
  - the protected DACL severing inheritance so shell processes lose an expected right;
  - an unresolvable trustee SID making some parser fall back.
- An HRESULT trace on the shell parsing path is needed to settle it.

**Ruled out**

- missing localization resources: `desktop.ini`, `FolderDescriptions`, `shell32.dll.mui` are all correct;
- icon-cache residue: copying a colored shortcut elsewhere still yields a white icon;
- language/registry corruption: `shell:Desktop` still resolves to the localized name.

---

## 8. Impact

| Area | Consequence |
|---|---|
| Experience | White desktop icons, English folder name, unknown-publisher prompt on every open |
| Data & environment | Two reinstalls destroyed the C: development environment (Python/Node/Git/venv) and some desktop files |
| Trust | The symptoms look unrelated to DSH, so users blame Windows first |
| Silence | The same rewrite on application/code directories is nearly impossible to attribute |

---

## 9. Recommendations

### Product (must)

1. **Never grant on a known-folder root**: refuse when the workspace is Desktop / Documents / Downloads / OneDrive / Start Menu / the profile root / a drive root, or force a `.dsh\workspace` subdirectory.
2. **Append-only grants**: no explicit `Deny Everyone`, no non-standard trustee SIDs, no breaking the inheritance chain.

### Product (should)

3. Snapshot the DACL/SACL at session start and roll back on exit or crash.
4. Startup self-check for historical pollution (`Everyone Deny` / `S-1-4-*` / Low label) with one-click cleanup.
5. Icon fallback: if every `.lnk` icon fails to resolve, surface a hint and a repair entry point.

### Product (optional)

6. Document and warn in the UI: do not put the workspace on the Desktop or other system folders.

### User-side mitigation

- Move the workspace off the Desktop and off every application directory (e.g. `C:\dsh-work`).
- Clean historical ACEs per §6 step 9.
- Acceptance after a reinstall: colored icons / localized "Desktop" / no unknown-publisher prompt.
- Periodically compare against a baseline using the read-only tool in this repository.

---

## 10. Unconfirmed

1. The exact ACL → icon/name failure mechanism (§7).
2. A **component version mismatch** was present on the same machine (`explorer.exe` / `shell32.dll` / component store on three different versions). It may be a contributing factor or an unrelated problem; it disappeared after reinstalling Windows.
3. The cost of the two reinstalls should be stated separately from the technical root cause; do not fold unverified causality into the conclusion.
4. The version boundary between the earlier signature (protected DACL + `Delete` deny + Medium label) and the 0.2.2 signature (`FILE_DELETE_CHILD` deny + Low label) has not been confirmed build by build.

---

## 11. Appendix: detection tool

`dsh-workspace-acl-guard`, published with this repository, is read-only:

- reads owner, DACL, SACL label, protection flag, effective `WRITE_DAC/WRITE_OWNER`;
- recognizes both known DSH signatures;
- classifies the directory's role (system folder / application directory / repository / plain) into a risk level;
- records a baseline so a later diff shows *when* and *which ACE* changed;
- **writes no ACL**.

See the repository README for usage.
