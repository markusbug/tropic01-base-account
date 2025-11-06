# Coinbase Smart Wallet + P-256 Hardware Signer (Tropic Square)

This repo demonstrates signing Coinbase Smart Wallet (ERC-4337) UserOperations using a P-256 hardware signer (Tropic Square `lt-util`) and submitting via a bundler.

- WebAuthn envelope is Android-style (indices point to JSON keys; authenticatorData is 33 bytes: rpIdHash(32) + flags(1)).
- Signature wrapper encoding matches common on-chain verifiers (SignatureWrapper = `(uint256 ownerIndex, bytes signatureData)`; `signatureData = abi.encode(WebAuthnAuth)`).

## Repo layout
- `cbsw_p256_webauthn.js` — Build, sign (manual or auto), and optionally submit a UserOp
- `libtropic-util/` — Submodule with Tropic Square `libtropic-util` (contains its own submodules). Build outputs expected at `libtropic-util/build/lt-util`.

## Prerequisites
- Node.js >= 18
- A bundler URL (if sending the UserOp)
- Tropic Square hardware and `lt-util` built for your interface

## Clone with submodules
```
git clone --recurse-submodules <this-repo-url>
cd <repo>
# If you forgot --recurse-submodules:
git submodule update --init --recursive
```

## Install Node deps
```
npm install
```

## Prepare libtropic-util
Enter the submodule and build:
```
cd libtropic-util
mkdir -p build && cd build
cmake .. -DUSB_DONGLE_TS1302=1   # or TS1301 (or -DLINUX_SPI=1)
make -j
```
Sanity check device:
```
./lt-util /dev/ttyACM0 -i
```
Generate or install a P-256 key in slot 1 (optional):
```
./lt-util /dev/ttyACM0 -e -g 1 p256
# or install your own key
# ./lt-util /dev/ttyACM0 -e -i 1 keypair.bin
```
Export Owner[0] pubkey X||Y:
```
./lt-util /dev/ttyACM0 -e -d 1 pubkey_slot1.bin
echo 0x$(xxd -p -c 1000 pubkey_slot1.bin)
```
Use this `0x{X}{Y}` when configuring/deploying your Coinbase Smart Wallet owner.

## Run (manual sign)
```
node ./cbsw_p256_webauthn.js
# Paste the 0x{r}{s} (or DER hex) when prompted
```

## Run (auto-sign with lt-util) and auto-send
```
export LTUTIL_AUTOSIGN=1
export LTUTIL_USE_SUDO=1           # if lt-util needs sudo
export LTUTIL_DEVICE=/dev/ttyACM0
export LTUTIL_SLOT=1
export BUNDLER_URL=<your_bundler_url>
export SEND=1
export USEROP_OUT=./userop.json    # optional: save final UserOp

node ./cbsw_p256_webauthn.js
```

## Troubleshooting
- AA24 signature error: ensure on-chain Owner[0] XY exactly matches your device’s XY and that no UserOp fields changed after hashing/signing.
- Device permissions: either add udev rules or set `LTUTIL_USE_SUDO=1`.


## Security & notes
- This is a reference implementation for demos/testing. Review and harden before any production use.
- The script defaults to Base Sepolia. Configure your bundler accordingly.

## License
MIT


