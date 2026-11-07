#!/usr/bin/env node
/**
 * 命令行自检：探测路径并输出分析后的状态。
 * 不加载 DSH，不写任何 ACL。
 *
 *   node scripts/selftest.mjs "F:\work" "C:\Users\me\Desktop" --known
 */
import { probe } from '../lib/probe.js';
import { analyze } from '../lib/detect.js';
import { formatStatus } from '../lib/messages.js';

const args = process.argv.slice(2);
const includeKnown = args.includes('--known');
const paths = args.filter((value) => value !== '--known');
const locale = process.env.DSH_ACL_GUARD_LOCALE === 'en' ? 'en' : 'zh';

if (process.platform !== 'win32') {
  console.error('自检：仅支持 Windows');
  process.exit(2);
}

const targets = paths.length > 0 ? paths : [process.cwd()];
const records = await probe(targets, { includeKnown });
if (records.length === 0) {
  console.error('自检：探针没有返回记录');
  process.exit(1);
}

for (const record of records) {
  console.log(formatStatus(locale, analyze(record)));
  console.log('');
}
