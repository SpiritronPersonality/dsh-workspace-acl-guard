#!/usr/bin/env node
/**
 * Command-line self test: probe paths and print the analyzed status.
 * Does not load DSH and does not write any ACL.
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
  console.error('selftest: Windows only');
  process.exit(2);
}

const targets = paths.length > 0 ? paths : [process.cwd()];
const records = await probe(targets, { includeKnown });
if (records.length === 0) {
  console.error('selftest: probe returned no records');
  process.exit(1);
}

for (const record of records) {
  console.log(formatStatus(locale, analyze(record)));
  console.log('');
}
