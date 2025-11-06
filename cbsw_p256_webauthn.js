// file: prepare-sign-and-build-userop.mjs
// node >=18, ESM
import { createPublicClient, encodeAbiParameters, encodeFunctionData, decodeAbiParameters, http, keccak256, toHex } from 'viem';
import { baseSepolia } from 'viem/chains';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------- Config (edit if needed) ----------
const CHAIN = baseSepolia; // change if you like
const ENTRY_POINT = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789'; // EP v0.6
const RPC_URL = process.env.RPC_URL || CHAIN.rpcUrls.default.http[0];
// Optional: set BUNDLER_URL to estimate gas or send (eth_*UserOperation*)
const BUNDLER_URL = process.env.BUNDLER_URL || null;
// WebAuthn envelope (Android-style): indices on keys; authenticatorData = 33 bytes (rpIdHash + flags)
const WEBAUTHN_INDEX_MODE = 'key';
const WEBAUTHN_AUTHDATA_SIGNCOUNT = false;
// --------------------------------------------

// ---------- External signer integration (optional) ----------
const __dirname = dirname(fileURLToPath(import.meta.url));
const LTUTIL_BIN = process.env.LTUTIL_BIN || join(__dirname, 'libtropic-util', 'build', 'lt-util');
const LTUTIL_DEVICE = process.env.LTUTIL_DEVICE || '/dev/ttyACM0';
const LTUTIL_SLOT = process.env.LTUTIL_SLOT || '1';
const LTUTIL_USE_SUDO = (process.env.LTUTIL_USE_SUDO || '0') === '1';
const AUTO_SEND = (process.env.SEND || process.env.AUTO_SEND || '0') === '1';
const USEROP_OUT = process.env.USEROP_OUT || '';

function execFilePromise(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout, stderr) => {
      if (err) {
        err.message += `\nSTDERR: ${stderr}`;
        return reject(err);
      }
      resolve({ stdout, stderr });
    });
  });
}

async function autoSignWithLtUtil(messageHashHex) {
  const tmp = mkdtempSync(join(tmpdir(), 'lt-sign-'));
  const out = join(tmp, 'sig_rs.bin');
  const args = [LTUTIL_DEVICE, '-e', '-S', String(LTUTIL_SLOT), messageHashHex, out];
  try {
    if (LTUTIL_USE_SUDO) {
      await execFilePromise('/usr/bin/sudo', [LTUTIL_BIN, ...args]);
    } else {
      await execFilePromise(LTUTIL_BIN, args);
    }
    const sig = readFileSync(out);
    const hex = '0x' + Buffer.from(sig).toString('hex');
    return hex;
  } catch (e) {
    throw new Error(`lt-util signing failed: ${e.message}`);
  }
}

// Minimal ABIs
const entryPointAbi = [
  {
    type: 'function',
    name: 'getNonce',
    stateMutability: 'view',
    inputs: [
      { name: 'sender', type: 'address' },
      { name: 'key', type: 'uint192' },
    ],
    outputs: [{ name: 'nonce', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'getUserOpHash',
    stateMutability: 'view',
    inputs: [
      {
        name: 'op',
        type: 'tuple',
        components: [
          { name: 'sender', type: 'address' },
          { name: 'nonce', type: 'uint256' },
          { name: 'initCode', type: 'bytes' },
          { name: 'callData', type: 'bytes' },
          { name: 'callGasLimit', type: 'uint256' },
          { name: 'verificationGasLimit', type: 'uint256' },
          { name: 'preVerificationGas', type: 'uint256' },
          { name: 'maxFeePerGas', type: 'uint256' },
          { name: 'maxPriorityFeePerGas', type: 'uint256' },
          { name: 'paymasterAndData', type: 'bytes' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [{ name: 'hash', type: 'bytes32' }],
  },
];

const cbswAbi = [
  // Coinbase Smart Wallet `execute(address target,uint256 value,bytes data)`
  { type: 'function', name: 'execute', stateMutability: 'payable',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
    ],
    outputs: []
  },
];

// DER helpers for P-256
function parseDerSig(derHex) {
  const b = Buffer.from(derHex.replace(/^0x/, ''), 'hex');
  if (b[0] !== 0x30) throw new Error('Bad DER: no SEQUENCE');
  let i = 2; // skip 0x30, len
  if (b[1] & 0x80) i = 2 + (b[1] & 0x7f); // long-form len not expected but handle
  if (b[i++] !== 0x02) throw new Error('Bad DER: expected INTEGER(r)');
  const rLen = b[i++]; const r = b.slice(i, i += rLen);
  if (b[i++] !== 0x02) throw new Error('Bad DER: expected INTEGER(s)');
  const sLen = b[i++]; const s = b.slice(i, i += sLen);
  const r32 = r.length > 32 ? r.slice(r.length - 32) : r;
  const s32 = s.length > 32 ? s.slice(s.length - 32) : s;
  return {
    r: '0x' + r32.toString('hex').padStart(64, '0'),
    s: '0x' + s32.toString('hex').padStart(64, '0'),
  };
}
function splitRsHex(rsHex) {
  const h = rsHex.replace(/^0x/, '');
  if (h.length !== 128) throw new Error('Expected 64-byte r||s');
  return { r: '0x' + h.slice(0, 64), s: '0x' + h.slice(64) };
}

// base64url
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// WebAuthn message hash: sha256(authenticatorData || sha256(clientDataJSON))
function webauthnMessageHash(authenticatorDataBytes, clientDataJSONString) {
  const cHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSONString, 'utf8')).digest();
  const msg = Buffer.concat([authenticatorDataBytes, cHash]);
  return '0x' + crypto.createHash('sha256').update(msg).digest('hex');
}

// Low-S check (Secp256r1)
const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const P256_N_DIV_2 = P256_N >> 1n;
function ensureLowS(sHex) {
  const s = BigInt(sHex);
  if (s > P256_N_DIV_2) throw new Error('Signature has high-S. Re-sign with canonical low-S.');
}

// Simple JSON-RPC
async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(`${method} error: ${j.error.message}`);
  return j.result;
}

(async () => {
  const rl = readline.createInterface({ input, output });

  const sender = (await rl.question('Coinbase Smart Wallet address (sender): ')).trim();
  const pubXY = (await rl.question('Owner[0] P-256 pubkey (X||Y, 130 chars incl 0x): ')).trim();
  if (!/^0x[0-9a-fA-F]{128}$/.test(pubXY)) throw new Error('Bad pubkey format, expected 0x + 128 hex chars.');

  const client = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });

  // Build minimal callData: execute(self, 0, 0x) – a no-op call that succeeds. (ABI: 0xb61d27f6)  :contentReference[oaicite:1]{index=1}
  const callData = encodeFunctionData({
    abi: cbswAbi,
    functionName: 'execute',
    args: [sender, 0n, '0x'],
  });

  // Nonce from EntryPoint v0.6: getNonce(sender, key=0)
  const nonce = await client.readContract({
    address: ENTRY_POINT,
    abi: entryPointAbi,
    functionName: 'getNonce',
    args: [sender, 0n],
  }); // :contentReference[oaicite:2]{index=2}

  // Skeleton UserOperation (gas fields can be estimated later; fill sane placeholders)
  let userOp = {
    sender,
    nonce,
    initCode: '0x',
    callData,
    callGasLimit: 100000n,
    verificationGasLimit: 350000n, // WebAuthn verify cost; adjust if needed
    preVerificationGas: 50000n,
    maxFeePerGas: 1_000_000_000n,         // 1 gwei
    maxPriorityFeePerGas: 1_000_000_000n, // 1 gwei
    paymasterAndData: '0x',
    signature: '0x', // placeholder for hashing
  };

  // If a bundler is available, ask it to estimate the three gas fields
  if (BUNDLER_URL) {
    const est = await rpc(BUNDLER_URL, 'eth_estimateUserOperationGas', [userOp, ENTRY_POINT]);
    userOp = {
      ...userOp,
      preVerificationGas: BigInt(est.preVerificationGas),
      verificationGasLimit: BigInt(est.verificationGasLimit),
      callGasLimit: BigInt(est.callGasLimit),
    };
  }

  // Compute userOpHash via EntryPoint.getUserOpHash (exact on-chain hash)  :contentReference[oaicite:3]{index=3}
  const userOpHash = await client.readContract({
    address: ENTRY_POINT,
    abi: entryPointAbi,
    functionName: 'getUserOpHash',
    args: [userOp],
  });

  // Debug: show the exact UserOperation hash computed by EntryPoint
  console.log('\n=== EntryPoint.getUserOpHash (bytes32) ===');
  console.log(userOpHash);

  // ---- Build WebAuthn envelope that the wallet expects onchain ----
  // clientDataJSON must contain `"type":"webauthn.get"` and the base64url of abi.encode(userOpHash).  :contentReference[oaicite:4]{index=4}
  const challengeBytes = Buffer.from(userOpHash.replace(/^0x/, ''), 'hex'); // abi.encode(bytes32) -> 32 bytes (same bytes)
  const challengeB64Url = b64url(challengeBytes);
  // Minimal JSON to match Android reference implementation
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challengeB64Url}"}`;

  // Indices: configurable to point to JSON keys (Android-style) or values (common Solidity libs)
  let typeIndex, challengeIndex;
  if (WEBAUTHN_INDEX_MODE === 'value') {
    const typeKeyVal = '"type":"';
    const challengeKeyVal = '"challenge":"';
    typeIndex = clientDataJSON.indexOf(typeKeyVal) + typeKeyVal.length;
    challengeIndex = clientDataJSON.indexOf(challengeKeyVal) + challengeKeyVal.length;
  } else {
    const typeKey = '"type"';
    const challengeKey = '"challenge"';
    typeIndex = clientDataJSON.indexOf(typeKey);
    challengeIndex = clientDataJSON.indexOf(challengeKey);
  }
  if (typeIndex < 0 || challengeIndex < 0) throw new Error('Internal error computing indices.');

  // authenticatorData: 32-byte rpIdHash || 1-byte flags (UP set) || optional 4-byte signCount
  // rpIdHash is NOT validated onchain by CBSW’s verifier. We set zeros.
  const authenticatorData = WEBAUTHN_AUTHDATA_SIGNCOUNT
    ? Buffer.concat([Buffer.alloc(32, 0x00), Buffer.from([0x01]), Buffer.alloc(4, 0x00)])
    : Buffer.concat([Buffer.alloc(32, 0x00), Buffer.from([0x01])]);

  // Debug: show envelope knobs
  console.log(`\n=== WebAuthn envelope ===`);
  console.log(`clientDataJSON: ${clientDataJSON}`);
  console.log(`indexMode=${WEBAUTHN_INDEX_MODE}  typeIndex=${typeIndex}  challengeIndex=${challengeIndex}`);
  console.log(`authenticatorData.length=${authenticatorData.length} bytes (includeSignCount=${WEBAUTHN_AUTHDATA_SIGNCOUNT})`);

  // This is the EXACT digest you must sign with P-256 ECDSA over SHA-256:
  const messageHash = webauthnMessageHash(authenticatorData, clientDataJSON);

  console.log('\n=== Sign this hash with P-256 / ECDSA / SHA-256 ===');
  console.log(messageHash);
  console.log('(Accepts signature as 0x{r}{s} or DER)\n');

  let sigHex;
  // Try hardware signer if configured
  if (process.env.LTUTIL_AUTOSIGN === '1') {
    try {
      console.log('Attempting lt-util auto-sign...');
      sigHex = await autoSignWithLtUtil(messageHash);
      console.log('lt-util signature:', sigHex);
    } catch (e) {
      console.log('Auto-sign failed, falling back to manual paste:', e.message);
      sigHex = (await rl.question('Paste signature: ')).trim();
    }
  } else {
    sigHex = (await rl.question('Paste signature: ')).trim();
  }
  let rHex, sHex;
  if (/^0x[0-9a-fA-F]+$/.test(sigHex)) {
    if (sigHex.length === 2 + 128) {
      ({ r: rHex, s: sHex } = splitRsHex(sigHex));
    } else {
      // assume DER in hex
      ({ r: rHex, s: sHex } = parseDerSig(sigHex));
    }
  } else {
    throw new Error('Signature must be hex (0x...).');
  }
  ensureLowS(sHex); // malleability guard (CBSW enforces low-S).  :contentReference[oaicite:6]{index=6}

  // Encode WebAuthnAuth as a single tuple argument to mirror abi.encode(WebAuthnAuth)
  const webauthnAuthEncoded = encodeAbiParameters(
    [
      {
        type: 'tuple',
        components: [
          { name: 'authenticatorData', type: 'bytes' },
          { name: 'clientDataJSON', type: 'string' },
          { name: 'challengeIndex', type: 'uint256' },
          { name: 'typeIndex', type: 'uint256' },
          { name: 'r', type: 'uint256' },
          { name: 's', type: 'uint256' },
        ],
      },
    ],
    [
      {
        authenticatorData: '0x' + authenticatorData.toString('hex'),
        clientDataJSON,
        challengeIndex: BigInt(challengeIndex),
        typeIndex: BigInt(typeIndex),
        r: BigInt(rHex),
        s: BigInt(sHex),
      },
    ]
  );

  // SignatureWrapper: (uint256 ownerIndex, bytes signatureData)
  // Encode wrapper as plain (uint256, bytes) to match abi.decode(signature, (uint256,bytes))
  const signatureWrapper = encodeAbiParameters(
    [ { type: 'uint256' }, { type: 'bytes' } ],
    [ 0n, webauthnAuthEncoded ]
  ); // CBSW expects userOp.signature = abi.encode(SignatureWrapper)

  // Decode back for local sanity check (ensure ABI layout matches)
  try {
    const [decOwnerIndex, decSignatureData] = decodeAbiParameters(
      [ { type: 'uint256' }, { type: 'bytes' } ],
      signatureWrapper
    );
    const [decTuple] = decodeAbiParameters(
      [
        {
          type: 'tuple',
          components: [
            { type: 'bytes' },
            { type: 'string' },
            { type: 'uint256' },
            { type: 'uint256' },
            { type: 'uint256' },
            { type: 'uint256' },
          ],
        },
      ],
      decSignatureData
    );
    const [decAuthData, decClientJSON, decChIdx, decTypeIdx, decR, decS] = decTuple;
    console.log('\n=== Signature ABI self-check ===');
    console.log('ownerIndex:', decOwnerIndex.toString());
    console.log('authenticatorData(hex):', decAuthData);
    console.log('clientDataJSON:', decClientJSON);
    console.log('challengeIndex:', decChIdx.toString(), 'typeIndex:', decTypeIdx.toString());
    console.log('r:', '0x' + decR.toString(16).padStart(64, '0'));
    console.log('s:', '0x' + decS.toString(16).padStart(64, '0'));
  } catch (e) {
    console.log('Signature ABI self-check failed:', e.message);
  }

  userOp = { ...userOp, signature: signatureWrapper };

  console.log('\n=== Final UserOperation (ready to send) ===');
  console.log(JSON.stringify(userOp, (k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2));

  // Optionally write to file
  if (USEROP_OUT) {
    try {
      writeFileSync(USEROP_OUT, JSON.stringify(userOp, (k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2));
      console.log(`Wrote UserOperation to ${USEROP_OUT}`);
    } catch (e) {
      console.log(`Failed writing ${USEROP_OUT}:`, e.message);
    }
  }

  if (BUNDLER_URL) {
    let send = AUTO_SEND;
    if (!send) {
      send = (await rl.question('\nSend to bundler now? [y/N]: ')).trim().toLowerCase() === 'y';
    }
    if (send) {
      // If you didn’t estimate before, you should call eth_estimateUserOperationGas here.
      const hash = await rpc(BUNDLER_URL, 'eth_sendUserOperation', [userOp, ENTRY_POINT]);
      console.log('Bundler accepted. userOpHash:', hash);
    }
  }

  rl.close();
})().catch((e) => {
  console.error('Error:', e.message);
  process.exit(1);
});
