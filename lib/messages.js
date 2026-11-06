/**
 * Bilingual messages and text rendering for tool output and the prompt warning.
 * Locale is a plugin config field; there is no dependency on the client locale.
 */

const ZH = {
  'verdict.ok': '正常',
  'verdict.polluted': '已检测到 DSH 写入的 ACL（污染）',
  'verdict.will-fail': '沙箱授权会失败（Win32 错误 5）',
  'verdict.risky-root': '高风险工作区根',
  'verdict.unknown': '无法判定',
  'signature.clean': '无 DSH 足迹',
  'level.low': '低',
  'level.medium': '中',
  'level.high': '高',
  'level.critical': '严重',
  'level.unknown': '未知',
  'signature.current': 'DSH 新版写入：能力 SID + 删除拒绝 + Low 标签',
  'signature.legacy': 'DSH 旧版写入：保护态 DACL + Delete 拒绝',
  'signature.capability': '仅有能力 SID',
  'signature.lowLabel': '仅有 Low 完整性标签',
  'evidence.capability-allow': '能力 SID 允许项',
  'evidence.world-deny-delete-child': 'Everyone 拒绝删除子目录和文件',
  'evidence.world-deny-delete': 'Everyone 拒绝删除',
  'evidence.protected-dacl': 'DACL 处于保护态（继承被切断）',
  'evidence.low-integrity-label': 'Low 完整性标签',
  'evidence.owner-mismatch': '所有者为其他账户',
  'evidence.no-write-dac': '缺少「修改权限」',
  'evidence.no-write-owner': '缺少「取得所有权」',
  'role.desktop': '桌面',
  'role.documents': '文档',
  'role.downloads': '下载',
  'role.pictures': '图片',
  'role.music': '音乐',
  'role.videos': '视频',
  'role.start-menu': '开始菜单',
  'role.startup': '启动文件夹',
  'role.onedrive': 'OneDrive',
  'role.profile-root': '用户目录根',
  'role.windows': 'Windows 目录',
  'role.program-files': 'Program Files',
  'role.program-files-x86': 'Program Files (x86)',
  'role.dsh-home': 'DSH_HOME',
  'role.application': '应用目录',
  'role.repository': '代码仓库',
  'role.directory': '普通目录',
  'role.drive-root': '磁盘根目录',
  'hint.ok': '无需处理。',
  'hint.polluted': '建议清理：先备份 SDDL，再移除能力 SID 与 Everyone 拒绝、恢复继承；不要把这个目录继续当工作区。',
  'hint.will-fail': '该目录缺少「修改权限」：DSH 首次授权会报错误 5，命令会反复要授权。需要管理员一次性授予完全控制，或改用专用工作区。',
  'hint.risky-root': '这是系统/应用目录，作为工作区会被写入常驻 ACL。请改用专用目录，例如在该目录下新建 .dsh\\workspace。',
  'warn.title': '【acl-guard】当前工作区根 {path} 有风险：{verdict}。',
  'warn.hint': '建议改用专用目录；运行 acl_status 查看详情。',
  'status.title': 'acl_status: {path}',
  'status.verdict': '判定：{verdict}（风险等级 {level}）',
  'status.role': '角色：{role}',
  'status.rights': '权限：WRITE_DAC={dac} WRITE_OWNER={owner}；标签={label}；保护态={protected}',
  'status.owner': '所有者：{owner}（{self}）',
  'status.signature': '签名：{signature}',
  'status.evidence': '证据：{evidence}',
  'status.hint': '建议：{hint}',
  'scan.title': 'acl_scan：共 {total} 个目录，需注意 {bad} 个',
  'scan.counts': '正常 {ok} / 污染 {polluted} / 会失败 {willFail} / 高风险 {risky} / 未知 {unknown}',
  'scan.line': '- [{level}] {path} — {verdict}',
  'journal.title': 'acl_journal：{count} 条记录（{dir}）',
  'journal.line': '- {ts} {event} {path} — {signature}',
  'yes': '是',
  'no': '否',
  'unknown': '未知',
};

const EN = {
  'verdict.ok': 'ok',
  'verdict.polluted': 'polluted by DSH sandbox ACLs',
  'verdict.will-fail': 'sandbox provisioning will fail (Win32 error 5)',
  'verdict.risky-root': 'risky workspace root',
  'verdict.unknown': 'unknown',
  'signature.clean': 'no DSH footprint',
  'level.low': 'low',
  'level.medium': 'medium',
  'level.high': 'high',
  'level.critical': 'critical',
  'level.unknown': 'unknown',
  'signature.current': 'current DSH write: capability SID + delete deny + Low label',
  'signature.legacy': 'legacy DSH write: protected DACL + Delete deny',
  'signature.capability': 'capability SID only',
  'signature.lowLabel': 'Low integrity label only',
  'evidence.capability-allow': 'capability SID allow ACE',
  'evidence.world-deny-delete-child': 'Everyone deny delete-child',
  'evidence.world-deny-delete': 'Everyone deny delete',
  'evidence.protected-dacl': 'protected DACL (inheritance severed)',
  'evidence.low-integrity-label': 'Low integrity label',
  'evidence.owner-mismatch': 'owner is another account',
  'evidence.no-write-dac': 'no WRITE_DAC',
  'evidence.no-write-owner': 'no WRITE_OWNER',
  'role.desktop': 'Desktop',
  'role.documents': 'Documents',
  'role.downloads': 'Downloads',
  'role.pictures': 'Pictures',
  'role.music': 'Music',
  'role.videos': 'Videos',
  'role.start-menu': 'Start Menu',
  'role.startup': 'Startup',
  'role.onedrive': 'OneDrive',
  'role.profile-root': 'profile root',
  'role.windows': 'Windows directory',
  'role.program-files': 'Program Files',
  'role.program-files-x86': 'Program Files (x86)',
  'role.dsh-home': 'DSH_HOME',
  'role.application': 'application directory',
  'role.repository': 'repository',
  'role.directory': 'directory',
  'role.drive-root': 'drive root',
  'hint.ok': 'Nothing to do.',
  'hint.polluted': 'Back up the SDDL, then remove the capability SID and the Everyone deny and restore inheritance; do not keep using this directory as a workspace.',
  'hint.will-fail': 'This directory denies WRITE_DAC: the first sandbox grant fails with error 5 and every command asks again. Grant full control once as administrator, or move to a dedicated workspace.',
  'hint.risky-root': 'This is a system or application directory. Using it as a workspace writes a resident ACL. Use a dedicated directory such as .dsh\\workspace inside it.',
  'warn.title': '[acl-guard] The workspace root {path} is risky: {verdict}.',
  'warn.hint': 'Use a dedicated workspace directory; run acl_status for details.',
  'status.title': 'acl_status: {path}',
  'status.verdict': 'verdict: {verdict} (level {level})',
  'status.role': 'role: {role}',
  'status.rights': 'rights: WRITE_DAC={dac} WRITE_OWNER={owner}; label={label}; protected={protected}',
  'status.owner': 'owner: {owner} (self={self})',
  'status.signature': 'signature: {signature}',
  'status.evidence': 'evidence: {evidence}',
  'status.hint': 'hint: {hint}',
  'scan.title': 'acl_scan: {total} directories, {bad} need attention',
  'scan.counts': 'ok {ok} / polluted {polluted} / will-fail {willFail} / risky {risky} / unknown {unknown}',
  'scan.line': '- [{level}] {path} — {verdict}',
  'journal.title': 'acl_journal: {count} entries ({dir})',
  'journal.line': '- {ts} {event} {path} — {signature}',
  'yes': 'yes',
  'no': 'no',
  'unknown': 'unknown',
};

const TABLES = { zh: ZH, en: EN };

const HINT_KEY = {
  ok: 'hint.ok',
  polluted: 'hint.polluted',
  'will-fail': 'hint.will-fail',
  'risky-root': 'hint.risky-root',
  unknown: 'hint.ok',
};

export function translate(locale, key, vars = {}) {
  const table = TABLES[locale] ?? ZH;
  const template = table[key] ?? ZH[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name) => (name in vars ? String(vars[name]) : `{${name}}`));
}

export function verdictText(locale, verdict) {
  return translate(locale, `verdict.${verdict}`);
}

export function hintText(locale, verdict) {
  return translate(locale, HINT_KEY[verdict] ?? 'hint.ok');
}

const SIGNATURE_KEY = {
  clean: 'signature.clean',
  'dsh-current': 'signature.current',
  'dsh-legacy': 'signature.legacy',
  'dsh-capability-only': 'signature.capability',
  'low-label-only': 'signature.lowLabel',
};

function boolText(locale, value) {
  if (value === true) return translate(locale, 'yes');
  if (value === false) return translate(locale, 'no');
  return translate(locale, 'unknown');
}

/** Render one analyzed record as plain text. */
export function formatStatus(locale, analysis) {
  const lines = [];
  lines.push(translate(locale, 'status.title', { path: analysis.path }));
  lines.push(translate(locale, 'status.verdict', {
    verdict: verdictText(locale, analysis.verdict),
    level: translate(locale, `level.${analysis.level}`),
  }));
  lines.push(translate(locale, 'status.role', { role: translate(locale, `role.${analysis.role}`) }));
  lines.push(translate(locale, 'status.rights', {
    dac: boolText(locale, analysis.writeDac),
    owner: boolText(locale, analysis.writeOwner),
    label: analysis.label ?? '-',
    protected: boolText(locale, analysis.protected),
  }));
  if (analysis.owner) {
    lines.push(translate(locale, 'status.owner', {
      owner: analysis.owner,
      self: boolText(locale, analysis.ownerIsSelf),
    }));
  }
  lines.push(translate(locale, 'status.signature', {
    signature: translate(locale, SIGNATURE_KEY[analysis.signature] ?? 'signature.clean'),
  }));
  if (analysis.evidence.length > 0) {
    lines.push(translate(locale, 'status.evidence', {
      evidence: analysis.evidence.map((key) => translate(locale, `evidence.${key}`)).join('、'),
    }));
  }
  lines.push(translate(locale, 'status.hint', { hint: hintText(locale, analysis.verdict) }));
  return lines.join('\n');
}

/** Render a scan result. */
export function formatScan(locale, result) {
  const lines = [];
  lines.push(translate(locale, 'scan.title', { total: result.total, bad: result.bad }));
  lines.push(translate(locale, 'scan.counts', result.counts));
  for (const item of result.items) {
    if (item.verdict === 'ok') continue;
    lines.push(translate(locale, 'scan.line', {
      level: translate(locale, `level.${item.level}`),
      path: item.path,
      verdict: verdictText(locale, item.verdict),
    }));
  }
  return lines.join('\n');
}

/** Render journal entries. */
export function formatJournal(locale, entries, dir) {
  const lines = [translate(locale, 'journal.title', { count: entries.length, dir })];
  for (const entry of entries) {
    lines.push(translate(locale, 'journal.line', {
      ts: entry.ts,
      event: entry.event,
      path: entry.path,
      signature: entry.signature,
    }));
  }
  return lines.join('\n');
}

/** One-line warning contributed to the system prompt. */
export function formatWarning(locale, analysis) {
  return translate(locale, 'warn.title', {
    path: analysis.path,
    verdict: verdictText(locale, analysis.verdict),
  }) + ' ' + translate(locale, 'warn.hint');
}
