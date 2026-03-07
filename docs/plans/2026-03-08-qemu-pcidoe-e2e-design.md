# QEMU PCI-DOE E2E Test Design

## Problem

The PCI-DOE transport implementation lacks:
1. Hardware mailbox access — `pcidoe.Transport` frames DOE messages over streams but cannot talk to real PCI DOE hardware (or QEMU-emulated hardware)
2. QEMU socket transport is test-only — exists in `tests/reference/interop/` behind `reference` build tag, not reusable
3. No QEMU-based E2E test — existing tests use loopback or direct socket connection, never exercise the full PCI DOE mailbox path through QEMU
4. DOE secured sessions are broken — `TestInterop_GoRequester_LibspdmResponder_DOEKeyExchange` is skipped due to DecryptError with DOE framing
5. CLI tools only support TCP — `cmd/spdm-requester` and `cmd/spdm-responder` cannot use DOE or QEMU socket transports

## Architecture

```
┌─────────── QEMU VM (guest) ───────────┐
│  cmd/spdm-requester -transport pcidoe │
│    ↕ pcidoe.Transport + MailboxConn   │
│  PCI config space registers (sysfs)   │
│    ↕ NVMe DOE extended capability     │
└───────────┬───────────────────────────┘
            │ QEMU DOE mailbox emulation
            │ QEMU socket protocol (TCP)
            │ [cmd:4B BE][transport:4B BE][size:4B BE][DOE payload]
┌───────────┴───────────────────────────┐
│  cmd/spdm-responder -transport qemu   │
│    ↕ qemusock.Transport               │
│  SPDM responder protocol engine       │
└───────────────────────────────────────┘
```

## Components

### 1. `pkg/transport/pcidoe/mailbox_conn.go` — PCI DOE hardware access

An `io.ReadWriter` implementation that accesses DOE via PCI config space registers. Used by the existing `pcidoe.Transport` via `pcidoe.New(NewMailboxConn(...))`.

DOE mailbox register protocol (offsets relative to capability base):
- `+0x08` Control Register: write GO bit (bit 31), Abort bit (bit 0)
- `+0x0C` Status Register: poll Data Object Ready (bit 31), Busy (bit 0), Error (bit 2)
- `+0x10` Write Data Mailbox: write DWORDs sequentially
- `+0x14` Read Data Mailbox: read DWORDs sequentially

Works identically with real hardware and QEMU-emulated devices.

### 2. `pkg/transport/qemusock/` — QEMU socket transport (promoted from test code)

Refactored from `tests/reference/interop/emu_transport.go` and `transport_bridge.go`:
- Proper package with error types, constants exported
- Server mode (accept connections) for responder use
- Client mode for requester use
- Handles NORMAL, TEST, SHUTDOWN commands
- Wraps DOE-framed payloads in the 12-byte socket header

### 3. `cmd/spdm-requester/` changes

- Add `-transport pcidoe` flag with `-pci-addr` parameter (BDF or "auto")
- Add `-transport qemusock` flag
- Auto-detect PID 1: mount sysfs/procfs, power off on exit (for QEMU guest use)

### 4. `cmd/spdm-responder/` changes

- Add `-transport qemusock` flag (listen on TCP, speak QEMU socket protocol)

### 5. `tests/qemu/` — E2E test harness

Three test combinations:

| Test | Guest (requester) | Host (responder) | Through QEMU? |
|------|-------------------|-------------------|----------------|
| Go+Go | cmd/spdm-requester (pcidoe) | Go SPDM responder (qemusock) | Yes |
| Ref+Go | spdm_requester_emu (PCI_DOE) | Go SPDM responder (qemusock) | No* |
| Go+Ref | cmd/spdm-requester (pcidoe) | spdm_responder_emu | Yes |

*Ref+Go uses socket protocol directly since spdm-emu already speaks it.

Test harness flow:
1. Start host-side responder on a free TCP port
2. Compile guest binary (CGO_ENABLED=0, static)
3. Create initramfs (cpio archive with guest binary as /init)
4. Create 1MB NVMe backing file
5. Start QEMU: `-M q35 -nographic -kernel <vmlinuz> -device nvme,...,spdm_port=<port>`
6. Capture serial output, assert PASS markers
7. Skip if QEMU or kernel unavailable

### 6. Fix DOE secured sessions

Investigate and fix the DOE KEY_EXCHANGE DecryptError (code=0x06) that causes `TestInterop_GoRequester_LibspdmResponder_DOEKeyExchange` to be skipped. Likely a DOE framing issue for secured SPDM messages (DataObjectType 0x02 vs 0x01).

## Gaps Addressed for Production Use

1. **Hardware DOE access** — MailboxConn enables talking to any PCI device with DOE
2. **QEMU integration** — qemusock transport enables QEMU-based development and testing
3. **CLI completeness** — both CLI tools support all transport types
4. **Secured DOE sessions** — fix the known DOE KEY_EXCHANGE issue
5. **DOE Discovery** — future: implement DOE Discovery protocol (vendor_id=0x0001, type=0x00)
