#!/usr/bin/env node
/**
 * PQ chain verification CLI gate.
 *
 * Exit codes
 *   0  chain verified successfully
 *   1  chain invalid or verification failed
 *   2  usage / input parse error (file unreadable, bad arguments)
 *   3  runtime / library failure (tasked verification could not complete)
 *
 * Options
 *   --trust-anchors <file>   PEM or DER file with trusted root certificate(s)
 *   --json                   emit the full verification result as JSON on stdout
 *   --max-depth <n>          override the maximum chain length (default 5)
 *
 * Input
 *   A positional argument naming a file containing a PEM bundle or DER-encoded
 *   certificate chain. Input may also be read from stdin when the path is '-'.
 *
 * @module pqblocks-browser-verify
 */
import { verifyPqChain, loadTrustAnchorsFromPem, loadTrustAnchorsFromDer } from '../src/index.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** @typedef {{code:number,message:string,stage:'input'|'verify'|'system'}} CliFailure */

/**
 * Parse the CLI argument vector into a structured options object.
 *
 * @param {string[]} argv process arguments (argv)
 * @returns {{
 *   inputPath: string | null,
 *   trustAnchorPath: string | null,
 *   json: boolean,
 *   maxDepth: number | null,
 *   errors: string[]
 * }}
 */
export function parseArgs(argv) {
  const out = {
    inputPath: null,
    trustAnchorPath: null,
    json: false,
    maxDepth: null,
    errors: [],
  };
  const positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--trust-anchors':
        out.trustAnchorPath = argv[++i] ?? null;
        if (out.trustAnchorPath === null) out.errors.push('--trust-anchors requires a file path');
        break;
      case '--json':
        out.json = true;
        break;
      case '--max-depth':
        out.maxDepth = Number(argv[++i]);
        if (!Number.isInteger(out.maxDepth) || out.maxDepth < 1) {
          out.errors.push('--max-depth requires a positive integer');
        }
        break;
      case '-h':
      case '--help':
        out.help = true;
        return out;
      default:
        if (a.startsWith('--') && a.length > 2) {
          out.errors.push(`unknown option: ${a}`);
        } else if (a === '-' || !a.startsWith('-')) {
          positionals.push(a);
        } else {
          out.errors.push(`unknown option: ${a}`);
        }
        break;
    }
  }
  if (positionals.length > 1) {
    out.errors.push('only one input file may be given');
  }
  if (positionals.length === 1) out.inputPath = positionals[0];
  return out;
}

/**
 * Read the input bytes, resolving '-' to stdin.
 *
 * @param {string} inputPath
 * @returns {string} raw bytes decoded as UTF-8 (PEM-friendly) for string form
 */
function readInput(inputPath) {
  if (inputPath === '-') {
    return readFileSync(0, 'utf8');
  }
  return readFileSync(inputPath, 'utf8');
}

/**
 * Load trust anchors from a file, honouring PEM and DER encodings.
 *
 * @param {string} p
 * @returns {Array<object>}
 */
function loadAnchors(p) {
  const raw = readFileSync(p);
  const text = raw.toString('utf8');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    return loadTrustAnchorsFromPem(text);
  }
  return loadTrustAnchorsFromDer(new Uint8Array(raw));
}

/**
 * Pretty-print a verification result to a human-readable form.
 *
 * @param {object} result PqVerificationResult
 */
function printHuman(result) {
  if (result.verified) {
    console.log('Chain verification: PASS');
    console.log(`Chain length: ${result.chain.length}`);
    if (result.cbom) {
      console.log(`CBOM schema: ${result.cbom.schema}`);
      console.log(`CBOM algorithms: ${result.cbom.algorithms.join(', ')}`);
      console.log(`CBOM certCount: ${result.cbom.certCount}`);
    }
  } else {
    console.log('Chain verification: FAIL');
    for (const e of result.errors) console.error(`  ${e}`);
    if (result.cbom) {
      console.log(`CBOM certCount: ${result.cbom.certCount}`);
    }
  }
}

/**
 * CLI entry point. Resolves with an exit code and never throws.
 *
 * @param {string[]} argv process arguments (argv)
 * @returns {Promise<number>} exit code
 */
export async function main(argv = process.argv.filter((_, i) => i >= 2)) {
  const opts = parseArgs(argv);

  if (opts.help) {
    console.log('Usage: pqblocks-browser-verify <chain.pem|chain.der|-> [options]');
    console.log('  --trust-anchors <file>  PEM or DER trust anchor certificate(s)');
    console.log('  --json                  emit the full result as JSON');
    console.log('  --max-depth <n>         maximum chain length (default 5)');
    return 0;
  }

  if (opts.errors.length > 0 || !opts.inputPath) {
    for (const e of opts.errors) console.error(e);
    if (!opts.inputPath) console.error('missing input file');
    console.error('Usage: pqblocks-browser-verify <chain.pem|chain.der|-> [options]');
    return 2;
  }

  let input;
  try {
    input = readInput(opts.inputPath);
  } catch (e) {
    console.error(`cannot read input ${opts.inputPath}: ${e.message}`);
    return 2;
  }

  if (input.trim().length === 0) {
    console.error('input is empty');
    return 2;
  }

  let trustAnchors = [];
  if (opts.trustAnchorPath) {
    try {
      trustAnchors = loadAnchors(opts.trustAnchorPath);
    } catch (e) {
      console.error(`cannot read trust anchors ${opts.trustAnchorPath}: ${e.message}`);
      return 2;
    }
  }

  const verifyOpts = { trustAnchors };
  if (opts.maxDepth !== null) verifyOpts.maxDepth = opts.maxDepth;

  let result;
  try {
    result = await verifyPqChain(input, verifyOpts);
  } catch (e) {
    if (e instanceof TypeError) {
      console.error(`invalid input: ${e.message}`);
      return 2;
    }
    console.error(`verification failed: ${e.message}`);
    return 3;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, replacer, 2));
  } else {
    printHuman(result);
  }
  return result.verified ? 0 : 1;
}

/**
 * JSON.stringify replacer exposing Uint8Arrays as hex rather than an
 * enormous object of numeric keys.
 *
 * @param {string} key
 * @param {any} value
 */
function replacer(key, value) {
  if (value instanceof Uint8Array) {
    return `0x${Buffer.from(value).toString('hex')}`;
  }
  return value;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`fatal: ${e && e.message ? e.message : String(e)}`);
    process.exit(3);
  },
);
