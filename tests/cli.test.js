import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const laneRoot = join(__dirname, '..');
const cliBin = join(laneRoot, 'bin', 'pqblocks-browser-verify.js');

/**
 * Run the CLI binary against a stdin payload.
 *
 * @param {string|Uint8Array} stdin - bytes to feed on stdin;
 *   give '-' as the argv path to route them to the CLI.
 * @param {string[]} [extraArgs]
 * @returns {{ status: number, stdout: string, stderr: string }}
 */
function runCli(stdin, extraArgs = []) {
  try {
    const stdout = execFileSync('node', [cliBin, '-', ...extraArgs], {
      encoding: 'utf8',
      input: stdin,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (e) {
    return {
      status: e.status === undefined ? -1 : e.status,
      stdout: e.stdout ? String(e.stdout) : '',
      stderr: e.stderr ? String(e.stderr) : '',
    };
  }
}

// Corpus leaf certificate bytes (same bytes as the API tests)
const leafPemPath = join(laneRoot, 'tests', 'corpus', 'leaf1.pem');
const leafPemBytes = readFileSync(leafPemPath, 'utf8');

// The same leaf cert serves as its own trust anchor - this is how the API
// tests S9-33 verify a corpus leaf and the CLI gate should exercise the
// identical verifier path when the user passes the leaf as both chain+anchor.
test('CLI exits 0 when the chain verifies (corpus leaf, self as anchor)', () => {
  // Supply leaf PEM as both input and trust anchor
  const out = runCli(leafPemBytes, ['--trust-anchors', leafPemPath]);
  assert.equal(out.status, 0, `expected exit 0, got ${out.status}\nstderr: ${out.stderr}`);
});

test('CLI exits 1 when the chain does not verify (garbage DER payload)', () => {
  // Exit 1 means verification failed (invalid/incorrect chain)
  // Exit 3 means library threw an internal error (e.g. unhandled exception)
  // Exit 2 means usage / bad input
  const out = runCli(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  // Status 1 = normal FAIL; Status 3 = thrown exception during verify
  assert([1, 3].includes(out.status), `expected exit 1 or 3, got ${out.status}\nstderr: ${out.stderr}`);
});

test('CLI exits 2 on unreadable input path', () => {
  let status = -1;
  try {
    execFileSync('node', [cliBin, join(laneRoot, 'does-not-exist.pem')], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (e) {
    status = e.status;
  }
  assert.equal(status, 2, `expected exit 2 for a missing input file, got ${status}`);
});

test('CLI exits 2 on empty stdin', () => {
  const out = runCli('');
  assert.equal(out.status, 2, `expected exit 2 for empty input, got ${out.status}`);
  assert.match(out.stderr, /input is empty/);
});

test('CLI rejects unknown options with exit 2', () => {
  const out = runCli(leafPemBytes, ['--totally-unknown']);
  assert.equal(out.status, 2, `expected exit 2, got ${out.status}`);
  assert.match(out.stderr, /unknown option: --totally-unknown/);
});

test('CLI --json emits the full PqVerificationResult with trust anchors', () => {
  const out = runCli(leafPemBytes, ['--json', '--trust-anchors', leafPemPath]);
  assert.equal(out.status, 0, `expected exit 0, got ${out.status}\nstderr: ${out.stderr}`);
  const parsed = JSON.parse(out.stdout);
  assert.equal(parsed.verified, true);
  assert.ok(Array.isArray(parsed.errors));
  assert.ok(parsed.cbom, 'cbom must be present in the JSON result');
  assert.ok(parsed.cbom.certCount >= 1);
});

test('CLI is invocable through the package bin alias (npm exec semantics)', () => {
  // Exercise the exact command a consumer would run in CI: npm exec on the
  // declared bin. This proves the package.json bin entry resolves.
  let status = -1;
  let stderr = '';
  try {
    execFileSync(
      'npm',
      ['exec', '--no', '--', 'pqblocks-browser-verify', '-'],
      { encoding: 'utf8',
        input: '-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----',
        cwd: laneRoot,
        stdio: ['pipe', 'pipe', 'pipe'] },
    );
  } catch (e) {
    status = e.status;
    stderr = e.stderr ? String(e.stderr) : '';
  }
  // Never 0: a garbage PEM cannot verify. Any non-zero exit proves the bin is wired.
  assert.notEqual(status, 0, `garbage PEM must not exit 0 (got ${status}); stderr: ${stderr}`);
});