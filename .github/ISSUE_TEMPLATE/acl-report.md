---
name: ACL 报告
about: 报告被 DSH 改动过 ACL 的目录，或判定不准的情况
labels: [acl]
---

**环境**

- DSH 版本：
- Windows 版本：
- 插件版本（`dsh plugin list` 或 `package.json`）：

**你看到了什么**

<!-- 白图标、未知发布者、更新失败、“无法删除”等 -->

**脱敏后的报告**

粘贴 `acl_status`（或 `acl_scan`）的输出。**请先删除用户名、SID 和不想公开的路径**，
用 `<user-sid>`、`<path>` 代替。

```
```

**日志记录**

如果变化发生在插件运行期间，请附上 `$DSH_HOME/acl-guard/YYYY-MM.jsonl` 中对应的一行
（含 `sddl` 与 `previousSddl`）。

**删除 ACE 并恢复继承后，问题是否消失？**

<!-- 是 / 否 / 未尝试 -->
