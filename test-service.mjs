import { basename, join } from 'path';
import { homedir } from 'os';

const dataDir = process.env.QUORUM_DATA_DIR || join(homedir(), '.quorum-client');
console.log('Data dir:', dataDir);
console.log('Service name:', basename(dataDir));
