import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function execJson(cmd, args) {
  const out = execFileSync(cmd, args, { encoding: 'utf8' });
  return JSON.parse(out);
}

function execWranglerJson(args) {
  // In cloudflare/wrangler-action, Wrangler is often invoked via `pnpm exec wrangler ...`
  // and the `wrangler` binary may not be on PATH during preCommands.
  const candidates = [
    { cmd: 'wrangler', args },
    { cmd: 'pnpm', args: ['exec', 'wrangler', ...args] },
  ];

  let lastErr;
  for (const c of candidates) {
    try {
      return execJson(c.cmd, c.args);
    } catch (e) {
      // Only fall back on ENOENT (command not found). For other errors, surface them.
      if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
        lastErr = e;
        continue;
      }
      throw e;
    }
  }

  console.error("Wrangler command not found. Tried: 'wrangler' and 'pnpm exec wrangler'.");
  throw lastErr ?? new Error('Wrangler not found');
}

function asArray(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.result)) return data.result;
  if (data && Array.isArray(data.databases)) return data.databases;
  return [];
}

function getD1Id(item) {
  return (item?.uuid ?? item?.id ?? item?.database_id ?? '').toString().trim();
}

const d1IdFromEnv = (process.env.D1_DATABASE_ID || '').trim();
const d1Name = (process.env.D1_DATABASE_NAME || 'beaconauth').trim();
const baseUrl = (process.env.BASE_URL || '').trim();

let d1Id = d1IdFromEnv;

if (!d1Id) {
  let list;
  try {
    list = execWranglerJson(['d1', 'list', '--json']);
  } catch (e) {
    console.error("Failed to run 'wrangler d1 list --json'. Is Wrangler authenticated and available?");
    throw e;
  }

  for (const it of asArray(list)) {
    if (it?.name === d1Name) {
      d1Id = getD1Id(it);
      break;
    }
  }

  if (!d1Id) {
    console.log(`D1 database '${d1Name}' not found; creating it...`);
    try {
      execFileSync('wrangler', ['d1', 'create', d1Name], { stdio: 'inherit' });
    } catch (e) {
      if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
        execFileSync('pnpm', ['exec', 'wrangler', 'd1', 'create', d1Name], { stdio: 'inherit' });
      } else {
        throw e;
      }
    }

    const list2 = execWranglerJson(['d1', 'list', '--json']);
    for (const it of asArray(list2)) {
      if (it?.name === d1Name) {
        d1Id = getD1Id(it);
        break;
      }
    }
  }
}

if (!d1Id) {
  console.error(
    "Unable to resolve a D1 database id. Provide secrets.CLOUDFLARE_WORKER_D1_DATABASE_ID or set vars.CLOUDFLARE_WORKER_D1_DATABASE_NAME (defaults to 'beaconauth').",
  );
  process.exit(1);
}

const srcPath = resolve('wrangler.toml');
let text = readFileSync(srcPath, 'utf8');

// Replace placeholder if present.
if (text.includes('REPLACE_WITH_D1_DATABASE_ID')) {
  text = text.replaceAll('REPLACE_WITH_D1_DATABASE_ID', d1Id);
} else {
  const re = /^database_id\s*=\s*"[^"]*"\s*$/gm;
  if (!re.test(text)) {
    console.error('Could not find D1 database_id entry in wrangler.toml');
    process.exit(1);
  }
  text = text.replace(re, `database_id = "${d1Id}"`);
}

// Keep the configured schema binding name but align the database_name in CI config to what we resolved.
text = text.replace(/^database_name\s*=\s*"[^"]*"\s*$/gm, `database_name = "${d1Name}"`);

// Keep repo defaults unless a BASE_URL value is provided.
if (baseUrl) {
  text = text.replace('BASE_URL = "https://example.com"', `BASE_URL = "${baseUrl}"`);
}

const outPath = resolve('wrangler.ci.toml');
writeFileSync(outPath, text, 'utf8');
console.log(`Wrote ${outPath} (D1 name=${d1Name}, id=${d1Id})`);
