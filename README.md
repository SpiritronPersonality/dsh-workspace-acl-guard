# dsh-workspace-acl-guard

[English](README.en.md) | 简体中文

一个**只读**的 DSH 插件，把 Windows 沙箱对工作区根写入的 **ACL 副作用**变得可见。

> DSH 的 Windows 沙箱为了让受限子进程能写工作区，会永久改写工作区根的安全描述符：
> 一个能力 SID 允许项、一条 `Everyone` 删除拒绝、一个 Low 完整性标签；会话结束也不回收。
> 当工作区是桌面或应用目录时，这会引发看起来与 DSH 毫无关系的故障。
> 详见 [docs/REPORT.zh.md](docs/REPORT.zh.md)（English: [docs/REPORT.en.md](docs/REPORT.en.md)）。

这个插件**不修复、也不阻止**这次改写。它只回答三个问题，而且不碰任何 ACL：

1. **这个工作区根有风险吗？**——在第一条命令跑之前；
2. **它已经被写过了吗？**——给出具体是哪几条 ACE、什么标签；
3. **什么时候变的？**——本地记录安全描述符基线，并对比出变化。

## 它做什么

- 读取所有者、DACL、SACL 完整性标签、保护态、有效 `WRITE_DAC`/`WRITE_OWNER`；
- 识别当前 DSH 签名（能力 SID + 删除子项拒绝 + Low 标签）与旧版签名（保护态 DACL + Delete 拒绝 + Medium 标签）；
- 判断目录角色（桌面、应用目录、仓库、普通目录……）并折算风险等级；
- 第一次见到某个路径时记录基线，之后每次变化都写入 `$DSH_HOME/acl-guard/YYYY-MM.jsonl`；
- 当前工作区根有风险时，向系统提示词贡献**一行**警告；
- 提供 `acl_status`、`acl_scan`、`acl_journal` 三个工具。

## 它绝不做什么

- **不写任何 ACL**：没有 `SetNamedSecurityInfo`、不改所有者、不删拒绝项；
- 不包装、不替换、不关闭任何 DSH 服务，也不动沙箱；
- `apply()` 绝不向外抛异常：失败只禁用自己；
- 不联网，除了 `$DSH_HOME/acl-guard` 不写任何地方。

## 安装

### 从 npm（推荐）

```sh
dsh plugin --profile <profile> add dsh-workspace-acl-guard
```

或在 Web 的「插件」页安装。

### 本地目录

```sh
git clone https://github.com/SpiritronPersonality/dsh-workspace-acl-guard
dsh plugin --profile <profile> add "<本地目录的绝对路径>"
```

### 不装 DSH 也能用

探针和检测逻辑可以当普通 CLI 跑：

```sh
node scripts/selftest.mjs "C:\Users\me\Desktop" "C:\work" --known
```

## 配置

| 字段 | 默认 | 含义 |
|---|---|---|
| `locale` | `zh` | 输出语言：`zh` / `en` |
| `watch` | `true` | 后台观察会话工作区与已知文件夹 |
| `intervalMs` | `60000` | 观察周期（5 秒–10 分钟） |
| `scanKnownFolders` | `true` | 每轮是否包含 Windows 已知文件夹 |

## 工具

- `acl_status`：检查一个目录（默认当前会话工作区），返回判定（`ok` / `polluted` / `will-fail` / `risky-root` / `unknown`）、角色、权限、标签、签名、证据与建议。
- `acl_scan`：扫描 Windows 已知文件夹与额外路径，输出计数与所有异常项。
- `acl_journal`：读取本地记录，每行含时间、事件（baseline/change）、路径、签名、权限、完整 SDDL 与上一次 SDDL。

## 检测原理

`probe → analyze`：

1. `assets/acl-probe.ps1` 用 `GetNamedSecurityInfoW(OWNER|DACL|SACL)` 读描述符，并按当前令牌（用户 + 组）计算有效权限；
2. `lib/detect.js` 把 SDDL 解析成 ACE，查找：
   - 受托者为 `S-1-4-*` 的允许项（DSH 按路径派生的能力 SID）；
   - `Everyone` 对 `FILE_DELETE_CHILD (0x40)` 或 `DELETE (0x10000)` 的拒绝；
   - `Low` 完整性标签（`LW`）；
   - 保护态 DACL（`D:P…`）。
3. 目录角色来自 Windows 已知文件夹列表与简单标记（`.git`、根下 `.exe`/`.dll`）。

## 风险模型

| 角色 | 等级 |
|---|---|
| 桌面、文档、下载、OneDrive、开始菜单、启动、用户目录根、盘根、Windows、Program Files、`DSH_HOME` | 严重 |
| 应用目录（根下有 `.exe`/`.dll`） | 高 |
| 仓库（`.git`） | 中 |
| 普通目录 | 低 |

识别到 DSH 签名时至少升到「高」；角色为「严重」时升到「严重」。缺 `WRITE_DAC`/`WRITE_OWNER`
的目录判为 `will-fail`：DSH 首次授权会报 Win32 错误 5，之后每条命令都会再次要授权。

## 限制

- **只读是设计选择**：它只报告、只警告，不清理 ACE。清理命令写在报告里，由你自己执行。
- **签名覆盖是尽力而为**：至少两代 DSH 写法不同；未知改动按证据记录，不硬下结论。
- **仅 Windows**：其他平台不注册任何东西。
- **需要 PowerShell 5.1**（所有受支持的 Windows 都有）；可用 `DSH_ACL_GUARD_POWERSHELL` 指定解释器。
- 图标/本地化名失效的精确机理仍未证实，见报告「未确认项」。

## 隐私

记录包含路径、所有者 SID 与 SDDL，仅保存在本机，不上传，可随时删除。工具输出可能含 SID，
贴到 issue 前请脱敏。

## 开发

```sh
npm test
node scripts/selftest.mjs "C:\work"
```

## 许可证

MIT
