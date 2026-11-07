# 更新日志

## 0.1.0 — 2026-11-06

首个公开版本，设计上只读。

- `acl-probe.ps1`：读取所有者、DACL、SACL 标签、保护态与有效 `WRITE_DAC` / `WRITE_OWNER`；不写任何安全描述符。
- `detect.js`：解析 SDDL，识别当前与旧版 DSH 签名，按目录角色折算风险等级。
- `journal.js`：本地 JSONL 基线与变化日志，位于 `$DSH_HOME/acl-guard`。
- 工具：`acl_status`、`acl_scan`、`acl_journal`。
- 当前会话工作区根有风险时，向系统提示词贡献一行中文预警。
- 中英文输出（默认中文）、无网络、无原生依赖。

## 0.1.1 — 2026-11-08

- 工具描述、参数说明与错误信息全部中文化（`locale: en` 可切回英文）。
- 仓库默认 README 改为中文，英文版移至 `README.en.md`。
- 探测失败按错误码本地化（超时、退出码、非法 JSON、无法启动 PowerShell）。
