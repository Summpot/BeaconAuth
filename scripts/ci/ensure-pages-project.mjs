import { execFileSync } from 'node:child_process';

function execJson(cmd, args) {
  const out = execFileSync(cmd, args, { encoding: 'utf8' });
  return JSON.parse(out);
}

function execWranglerJson(args) {
  const candidates = [
    { cmd: 'wrangler', args },
    { cmd: 'pnpm', args: ['exec', 'wrangler', ...args] },
  ];

  let lastErr;
  for (const c of candidates) {
    try {
      return execJson(c.cmd, c.args);
    } catch (e) {
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

function asProjectArray(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.result)) return data.result;
  if (data && Array.isArray(data.projects)) return data.projects;
  return [];
}

const projectName = (process.env.PAGES_PROJECT_NAME || 'beaconauth').trim();
if (!projectName) {
  console.error('PAGES_PROJECT_NAME is not set');
  process.exit(2);
}

let projects;
try {
  projects = asProjectArray(execWranglerJson(['pages', 'project', 'list', '--json']));
} catch (e) {
  console.error('Failed to list Pages projects via Wrangler. Is Wrangler authenticated and available?');
  throw e;
}

const exists = projects.some((p) => p && p.name === projectName);
if (!exists) {
  console.log(`Creating Pages project '${projectName}' (production branch: main)...`);
  try {
    execFileSync('wrangler', ['pages', 'project', 'create', projectName, '--production-branch', 'main'], {
      stdio: 'inherit',
    });
  } catch (e) {
    if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
      execFileSync(
        'pnpm',
        ['exec', 'wrangler', 'pages', 'project', 'create', projectName, '--production-branch', 'main'],
        { stdio: 'inherit' },
      );
    } else {
      throw e;
    }
  }
} else {
  console.log(`Pages project '${projectName}' already exists.`);
}
