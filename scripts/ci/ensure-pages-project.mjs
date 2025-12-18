import { execFileSync } from 'node:child_process';

function runJson(cmd, args) {
  const out = execFileSync(cmd, args, { encoding: 'utf8' });
  return JSON.parse(out);
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
  projects = asProjectArray(runJson('wrangler', ['pages', 'project', 'list', '--json']));
} catch (e) {
  console.error('Failed to list Pages projects via Wrangler. Is Wrangler authenticated and available?');
  throw e;
}

const exists = projects.some((p) => p && p.name === projectName);
if (!exists) {
  console.log(`Creating Pages project '${projectName}' (production branch: main)...`);
  execFileSync('wrangler', ['pages', 'project', 'create', projectName, '--production-branch', 'main'], {
    stdio: 'inherit',
  });
} else {
  console.log(`Pages project '${projectName}' already exists.`);
}
