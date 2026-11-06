/**
 * SDDL parsing and signature detection.
 *
 * The detector is deliberately conservative: it recognizes what DSH writes
 * today (capability SID + Everyone delete-child deny + Low label) and what
 * earlier builds wrote (protected DACL + Everyone delete deny + Medium label),
 * and reports anything else as an unknown mutation instead of guessing.
 */

const SHORT_RIGHTS = {
  RC: 0x00020000, // READ_CONTROL
  SD: 0x00010000, // DELETE
  WD: 0x00040000, // WRITE_DAC
  WO: 0x00080000, // WRITE_OWNER
  GA: 0x10000000, // GENERIC_ALL
  GR: 0x80000000, // GENERIC_READ
  GW: 0x40000000, // GENERIC_WRITE
  GE: 0x20000000, // GENERIC_EXECUTE
  FA: 0x001f01ff, // FILE_ALL_ACCESS
  FR: 0x00120089, // FILE_GENERIC_READ
  FW: 0x00120116, // FILE_GENERIC_WRITE
  FX: 0x001200a0, // FILE_GENERIC_EXECUTE
  GX: 0x20000000, // GENERIC_EXECUTE
  DT: 0x00010000, // DELETE (alias seen in older SDDL)
  DC: 0x00000040, // FILE_DELETE_CHILD (alias seen in some SDDL)
};

const CAPABILITY_SID = /^S-1-4-\d+-\d+$/i;
const ACE_PATTERN = /\(([A-Za-z]{1,2});([^;]*);([^;]*);([^;]*);([^;]*);([^)]+)\)/g;

/** Parse a rights token (`FA`, `0x1301bf`, `SDGXGWGR`) into a mask, or null. */
export function parseRights(token) {
  const text = String(token ?? '').trim();
  if (text === '') return 0;
  if (/^0x[0-9a-f]+$/i.test(text)) {
    const value = Number.parseInt(text.slice(2), 16);
    return Number.isFinite(value) ? value >>> 0 : null;
  }
  if (text.length % 2 !== 0) return null;
  let mask = 0;
  for (let index = 0; index < text.length; index += 2) {
    const code = text.slice(index, index + 2).toUpperCase();
    if (!(code in SHORT_RIGHTS)) return null;
    mask |= SHORT_RIGHTS[code];
  }
  return mask >>> 0;
}

/** Parse an ACE-flags token (`OICIID`) into a set of two-letter flags. */
export function parseFlags(token) {
  const text = String(token ?? '').trim().toUpperCase();
  const flags = new Set();
  for (let index = 0; index + 2 <= text.length; index += 2) flags.add(text.slice(index, index + 2));
  return flags;
}

function aceKind(type) {
  const code = String(type ?? '').toUpperCase();
  if (code === 'ML' || code === 'RA' || code === 'SP' || code === 'TL') return 'label';
  if (code === 'AU' || code === 'AL') return 'audit';
  if (code.startsWith('D')) return 'deny';
  if (code.startsWith('A')) return 'allow';
  return 'other';
}

/**
 * Parse a full SDDL string into sections, ACEs and the integrity label.
 *
 * @param {string} sddl
 * @returns {{owner: string|null, daclFlags: string, protected: boolean, label: string|null, aces: object[]}}
 */
export function parseSddl(sddl) {
  const text = String(sddl ?? '');
  const ownerMatch = /^O:(S-\d+(?:-\d+)+)/i.exec(text);
  const daclMatch = /D:([A-Z]*)/.exec(text);
  const daclFlags = daclMatch ? daclMatch[1] : '';

  const aces = [];
  let label = null;
  ACE_PATTERN.lastIndex = 0;
  let match;
  while ((match = ACE_PATTERN.exec(text)) !== null) {
    const [, type, flags, rights, , , sid] = match;
    const kind = aceKind(type);
    const ace = {
      type: kind,
      rawType: type,
      flags: parseFlags(flags),
      inherited: parseFlags(flags).has('ID'),
      inheritOnly: parseFlags(flags).has('IO'),
      mask: parseRights(rights),
      rights,
      sid,
    };
    if (kind === 'label') {
      label = sid.toUpperCase();
    }
    aces.push(ace);
  }

  return {
    owner: ownerMatch ? ownerMatch[1] : null,
    daclFlags,
    protected: daclFlags.includes('P'),
    label,
    aces,
  };
}

const ROLE_LEVEL = {
  desktop: 'critical',
  documents: 'critical',
  downloads: 'critical',
  onedrive: 'critical',
  'start-menu': 'critical',
  startup: 'critical',
  'profile-root': 'critical',
  'drive-root': 'critical',
  windows: 'critical',
  'program-files': 'critical',
  'program-files-x86': 'critical',
  'dsh-home': 'high',
  application: 'high',
  repository: 'medium',
  directory: 'low',
};

const LEVEL_ORDER = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function maxLevel(a, b) {
  return (LEVEL_ORDER[a] ?? 0) >= (LEVEL_ORDER[b] ?? 0) ? a : b;
}

/**
 * Analyze one probe record.
 *
 * @param {object} record - a record from `probe()`.
 * @returns {{
 *   path: string, role: string, signature: string, verdict: string,
 *   level: string, evidence: string[], capabilitySids: string[],
 *   label: string|null, protected: boolean, writeDac: boolean|null,
 *   writeOwner: boolean|null, owner: string|null, ownerIsSelf: boolean|null,
 *   error: string|null
 * }}
 */
export function analyze(record) {
  const parsed = parseSddl(record?.sddl ?? '');
  const label = (record?.label ?? parsed.label ?? '').toUpperCase() || null;

  const capabilitySids = [...new Set(
    parsed.aces
      .filter((ace) => ace.type === 'allow' && CAPABILITY_SID.test(ace.sid))
      .map((ace) => ace.sid.toUpperCase()),
  )];

  const worldDeny = parsed.aces.filter(
    (ace) => ace.type === 'deny' && (ace.sid === 'WD' || ace.sid === 'S-1-1-0'),
  );
  const deleteChildDeny = worldDeny.filter((ace) => ace.mask !== null && (ace.mask & 0x40) !== 0);
  const deleteDeny = worldDeny.filter((ace) => ace.mask !== null && (ace.mask & 0x10000) !== 0);

  const lowLabel = label === 'LW';
  const role = record?.role ?? 'unknown';
  const error = record?.error ?? null;
  const writeDac = record?.writeDac === true ? true : record?.writeDac === false ? false : null;
  const writeOwner = record?.writeOwner === true ? true : record?.writeOwner === false ? false : null;
  const ownerIsSelf = record?.ownerIsSelf === true ? true : record?.ownerIsSelf === false ? false : null;

  let signature = 'clean';
  if (capabilitySids.length > 0) {
    if (lowLabel || deleteChildDeny.length > 0) signature = 'dsh-current';
    else if (deleteDeny.length > 0 || parsed.protected) signature = 'dsh-legacy';
    else signature = 'dsh-capability-only';
  } else if (lowLabel) {
    signature = 'low-label-only';
  }

  const evidence = [];
  if (capabilitySids.length > 0) evidence.push('capability-allow');
  if (deleteChildDeny.length > 0) evidence.push('world-deny-delete-child');
  if (deleteDeny.length > 0) evidence.push('world-deny-delete');
  if (parsed.protected) evidence.push('protected-dacl');
  if (lowLabel) evidence.push('low-integrity-label');
  if (ownerIsSelf === false) evidence.push('owner-mismatch');
  if (writeDac === false) evidence.push('no-write-dac');
  if (writeOwner === false) evidence.push('no-write-owner');

  let verdict = 'ok';
  if (error) verdict = 'unknown';
  else if (signature !== 'clean') verdict = 'polluted';
  else if (ROLE_LEVEL[role] === 'critical') verdict = 'risky-root';
  else if (writeDac === false || writeOwner === false) verdict = 'will-fail';

  let level = ROLE_LEVEL[role] ?? 'unknown';
  if (verdict === 'polluted') level = maxLevel(level, 'high');
  if (verdict === 'polluted' && (ROLE_LEVEL[role] === 'critical' || ROLE_LEVEL[role] === 'high')) level = 'critical';
  if (verdict === 'will-fail') level = maxLevel(level, 'high');
  if (verdict === 'risky-root') level = 'critical';

  return {
    path: record?.path ?? '',
    role,
    signature,
    verdict,
    level,
    evidence,
    capabilitySids,
    label,
    protected: parsed.protected,
    writeDac,
    writeOwner,
    owner: record?.owner ?? null,
    ownerIsSelf,
    error,
  };
}

/** Short human reason for a signature, used by both locales. */
export function signatureKey(signature) {
  switch (signature) {
    case 'dsh-current': return 'signature.current';
    case 'dsh-legacy': return 'signature.legacy';
    case 'dsh-capability-only': return 'signature.capability';
    case 'low-label-only': return 'signature.lowLabel';
    default: return 'signature.clean';
  }
}
