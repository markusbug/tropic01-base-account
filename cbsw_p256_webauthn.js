// file: prepare-sign-and-build-userop.mjs
// node >=18, ESM
import { createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, decodeAbiParameters, http, keccak256, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
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
const LTUTIL_DEVICE = (typeof process.env.LTUTIL_SPI !== 'undefined')
  ? ''
  : (process.env.LTUTIL_DEVICE || '/dev/ttyACM0');
let LTUTIL_SLOT = process.env.LTUTIL_SLOT || '1';
const LTUTIL_USE_SUDO = (process.env.LTUTIL_USE_SUDO || '0') === '1';
const AUTO_SEND = (process.env.SEND || process.env.AUTO_SEND || '0') === '1';
const USEROP_OUT = process.env.USEROP_OUT || '';
// Smart Wallet factory config
const FACTORY_ADDRESS = (process.env.FACTORY_ADDRESS || '');
const OWNER_NONCE = BigInt(process.env.OWNER_NONCE || '0');
const OWNER_RECOVERY_ADDRESS = process.env.OWNER_RECOVERY_ADDRESS || '';

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

function buildLtArgs(...rest) {
  return (LTUTIL_DEVICE && LTUTIL_DEVICE.length > 0) ? [LTUTIL_DEVICE, ...rest] : rest;
}

async function autoSignWithLtUtil(messageHashHex) {
  ensureLtUtilExists();
  const tmp = mkdtempSync(join(tmpdir(), 'lt-sign-'));
  const out = join(tmp, 'sig_rs.bin');
  const args = buildLtArgs('-e', '-S', String(LTUTIL_SLOT), messageHashHex, out);
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

async function autoFetchPubkeyXY() {
  ensureLtUtilExists();
  // If provided via env, trust it
  if (process.env.PUBKEY_XY && /^0x[0-9a-fA-F]{128}$/.test(process.env.PUBKEY_XY)) {
    return process.env.PUBKEY_XY;
  }
  const tmp = mkdtempSync(join(tmpdir(), 'lt-pub-'));
  const out = join(tmp, 'pubkey_slot.bin');
  const args = buildLtArgs('-e', '-d', String(LTUTIL_SLOT), out);
  try {
    if (LTUTIL_USE_SUDO) {
      await execFilePromise('/usr/bin/sudo', [LTUTIL_BIN, ...args]);
    } else {
      await execFilePromise(LTUTIL_BIN, args);
    }
    const pub = readFileSync(out);
    if (pub.length !== 64) throw new Error(`Expected 64-byte XY, got ${pub.length}`);
    return '0x' + Buffer.from(pub).toString('hex');
  } catch (e) {
    throw new Error(`lt-util pubkey read failed: ${e.message}`);
  }
}

function encodeAddressAsAbi(addressHex) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addressHex)) throw new Error('Bad recovery address');
  const buf = Buffer.alloc(32, 0x00);
  Buffer.from(addressHex.slice(2), 'hex').copy(buf, 12);
  return '0x' + buf.toString('hex');
}

function ensureLtUtilExists() {
  if (existsSync(LTUTIL_BIN)) return;
  const msg = [
    `lt-util binary not found at: ${LTUTIL_BIN}`,
    'Build instructions:',
    '  git submodule update --init --recursive',
    '  cd libtropic-util',
    '  mkdir -p build && cd build',
    '  cmake .. -DUSB_DONGLE_TS1302=1   # or TS1301 / -DLINUX_SPI=1',
    '  make -j',
  ].join('\n');
  throw new Error(msg);
}

async function generateP256KeyInSlot(slotStr) {
  ensureLtUtilExists();
  const args = buildLtArgs('-e', '-g', String(slotStr), 'p256');
  try {
    console.log(`Generating P-256 key in slot ${slotStr}...`);
    if (LTUTIL_USE_SUDO) {
      await execFilePromise('/usr/bin/sudo', [LTUTIL_BIN, ...args]);
    } else {
      await execFilePromise(LTUTIL_BIN, args);
    }
    console.log('Key generation OK.');
  } catch (e) {
    throw new Error(`lt-util key generate failed: ${e.message}`);
  }
}

function ensureFactoryAddress() {
  if (!/^0x[0-9a-fA-F]{40}$/.test(FACTORY_ADDRESS)) {
    const msg = [
      'FACTORY_ADDRESS is not set or invalid.',
      'Set FACTORY_ADDRESS to the Coinbase Smart Wallet factory for your network, e.g.:',
      '  export FACTORY_ADDRESS=0x<factory_on_your_chain>',
      'Then re-run the script.'
    ].join('\n');
    throw new Error(msg);
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

// Factory ABI (getAddress)
const cbswFactoryAbi = [
  {
    type: 'function',
    name: 'getAddress',
    stateMutability: 'view',
    inputs: [
      { name: 'owners', type: 'bytes[]' },
      { name: 'nonce', type: 'uint256' },
    ],
    outputs: [ { name: 'account', type: 'address' } ],
  },
  {
    type: 'function',
    name: 'createAccount',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'owners', type: 'bytes[]' },
      { name: 'nonce', type: 'uint256' },
    ],
    outputs: [ { name: 'account', type: 'address' } ],
  },
];

// EntryPoint v0.6 write ABI (handleOps)
const entryPointWriteAbi = [
  {
    type: 'function',
    name: 'handleOps',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'ops',
        type: 'tuple[]',
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
      { name: 'beneficiary', type: 'address' },
    ],
    outputs: [],
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

  // Ask for Tropic Square P-256 key slot
  const slotAns = (await rl.question(`Tropic Square P-256 key slot (0-31) [${LTUTIL_SLOT}]: `)).trim();
  if (slotAns.length > 0) {
    const n = Number(slotAns);
    if (!Number.isInteger(n) || n < 0 || n > 31) {
      throw new Error('Invalid key slot, expected integer 0-31');
    }
    LTUTIL_SLOT = String(n);
  }
  console.log('Using key slot:', LTUTIL_SLOT);

  // Fetch Owner[0] pubkey (X||Y) from hardware; if empty slot, offer to generate
  let pubXY;
  try {
    pubXY = await autoFetchPubkeyXY();
  } catch (e) {
    console.log('Could not read P-256 public key from slot', LTUTIL_SLOT);
    console.log(e.message);
    const gen = (await rl.question(`Generate new P-256 key in slot ${LTUTIL_SLOT}? [y/N]: `)).trim().toLowerCase() === 'y';
    if (!gen) throw e;
    await generateP256KeyInSlot(LTUTIL_SLOT);
    pubXY = await autoFetchPubkeyXY();
  }
  console.log('Owner[0] P-256 pubkey (X||Y):', pubXY);

  const client = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });

  // Compute predicted sender via factory.getAddress(bytes[] owners, uint256 nonce)
  // Owner[0] as abi.encode((uint256 x, uint256 y)) exactly like Android reference
  const xHex = '0x' + pubXY.slice(2, 66);
  const yHex = '0x' + pubXY.slice(66);
  const firstOwnerEncoded = encodeAbiParameters(
    [ { type: 'tuple', components: [ { type: 'uint256' }, { type: 'uint256' } ] } ],
    [ [ BigInt(xHex), BigInt(yHex) ] ]
  );
  const owners = [firstOwnerEncoded];
  if (OWNER_RECOVERY_ADDRESS) owners.push(encodeAddressAsAbi(OWNER_RECOVERY_ADDRESS));
  ensureFactoryAddress();
  // Debug info for owners encoding
  console.log('Factory:', FACTORY_ADDRESS, 'owners count:', owners.length, 'nonce:', OWNER_NONCE.toString());
  owners.forEach((o, i) => console.log(`owners[${i}] len=${(o.length-2)/2}B`));
  const sender = await client.readContract({
    address: FACTORY_ADDRESS,
    abi: cbswFactoryAbi,
    functionName: 'getAddress',
    args: [owners, OWNER_NONCE],
  });
  console.log('Predicted Smart Wallet address (sender):', sender);

  // Build minimal callData: execute(self, 0, 0x) – a no-op call that succeeds. (ABI: 0xb61d27f6)  :contentReference[oaicite:1]{index=1}
  const callData = encodeFunctionData({
    abi: cbswAbi,
    functionName: 'execute',
    args: [sender, 0n, '0x'],
  });

  // If account not deployed, fill initCode = factory + abi.encodeCall(createAccount(owners, nonce))
  let initCode = '0x';
  try {
    const code = await client.getBytecode({ address: sender });
    const deployed = code && code !== '0x';
    if (!deployed) {
      const factoryCalldata = encodeFunctionData({
        abi: cbswFactoryAbi,
        functionName: 'createAccount',
        args: [owners, OWNER_NONCE],
      });
      initCode = FACTORY_ADDRESS + factoryCalldata.slice(2);
      console.log('Account not deployed. Populating initCode.');
    } else {
      console.log('Account is already deployed. initCode left empty.');
    }
  } catch (e) {
    console.log('Bytecode check failed; leaving initCode empty:', e.message);
  }

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
    initCode,
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

  // Always auto-sign with lt-util (no interactive paste)
  let sigHex;
  try {
    console.log('Attempting lt-util auto-sign...');
    sigHex = await autoSignWithLtUtil(messageHash);
    console.log('lt-util signature:', sigHex);
  } catch (e) {
    throw new Error(`Auto-sign failed: ${e.message}\n` +
      'Check lt-util build/permissions and environment (LTUTIL_DEVICE, LTUTIL_SLOT, LTUTIL_USE_SUDO).');
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

  // Ask if user wants to submit directly to EntryPoint with an EOA private key
  const doPkSubmit = (await rl.question('\nSubmit directly to EntryPoint with an EOA private key now? [y/N]: '))
    .trim().toLowerCase() === 'y';

  if (doPkSubmit) {
    const pkIn = (await rl.question('Private key (0x...): ')).trim();
    const pk = pkIn.startsWith('0x') ? pkIn : ('0x' + pkIn);
    if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error('Invalid private key format. Expected 32-byte hex.');
    const account = privateKeyToAccount(pk);
    const beneficiary = account.address;
    const walletClient = createWalletClient({ account, chain: CHAIN, transport: http(RPC_URL) });
    let txHash;
    try {
      txHash = await walletClient.writeContract({
        address: ENTRY_POINT,
        abi: entryPointWriteAbi,
        functionName: 'handleOps',
        args: [[userOp], beneficiary],
      });
      console.log('Sent handleOps tx (via writeContract):', txHash);
    } catch (e) {
      console.log('writeContract failed (likely due to simulation). Sending raw tx with fallback gas...');
      const data = encodeFunctionData({
        abi: entryPointWriteAbi,
        functionName: 'handleOps',
        args: [[userOp], beneficiary],
      });
      const fallbackGas = BigInt(process.env.FALLBACK_GAS || '2000000');
      txHash = await walletClient.sendTransaction({
        to: ENTRY_POINT,
        data,
        gas: fallbackGas,
        value: 0n,
        account,
      });
      console.log('Sent handleOps tx (raw):', txHash);
    }
  } else {
    console.log('\n=== Final UserOperation (ready to send) ===');
    console.log(JSON.stringify(userOp, (k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2));
    if (USEROP_OUT) {
      try {
        writeFileSync(USEROP_OUT, JSON.stringify(userOp, (k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2));
        console.log(`Wrote UserOperation to ${USEROP_OUT}`);
      } catch (e) {
        console.log(`Failed writing ${USEROP_OUT}:`, e.message);
      }
    }
  }

  rl.close();
})().catch((e) => {
  console.error('Error:', e.message);
  process.exit(1);
});
