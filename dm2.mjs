#!/usr/bin/env node
// Wrapper that uses alternate data directory for second identity
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

// Set environment variable for alternate data dir
const child = spawn('node', [join(__dirname, 'dm.mjs'), ...args], {
  env: { ...process.env, QUORUM_DATA_DIR: process.env.HOME + '/.quorum-client-2' },
  stdio: 'inherit'
});
child.on('exit', code => process.exit(code));
