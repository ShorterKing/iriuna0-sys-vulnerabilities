# iriuna0.sys Kernel Vulnerabilities

Kernel vulnerabilities in the Iriun Webcam audio driver (`iriuna0.sys`) allowing local denial of service and potentially local privilege escalation.

## Summary

The Iriun Webcam audio kernel driver (`iriuna0.sys` v10.0.10011.16384) contains multiple vulnerabilities in its IOCTL handlers. A local attacker can trigger kernel pool corruption or a NULL pointer dereference, resulting in a Blue Screen of Death (BSOD).

All custom IOCTLs are registered with `FILE_ANY_ACCESS`, meaning any local user — including low-privilege accounts — can open the device and send crafted requests.

**Affected software:** Iriun Webcam (Windows) — driver `iriuna0.sys` version 10.0.10011.16384  
**Access required:** Local, any user

## Vulnerabilities

### Bug 1: IOCTL 0x222010 — Pool Buffer Overflow

**CVE:** CVE-2026-106934  
**CWE:** CWE-122 (Heap-based Buffer Overflow), CWE-787 (Out-of-bounds Write)  
**Impact:** Local Denial of Service (BSOD). The pool corruption is potentially exploitable for local privilege escalation.

The handler for IOCTL `0x222010` (`METHOD_BUFFERED`) writes 8 bytes to `SystemBuffer` unconditionally, without validating `OutputBufferLength`. When a caller supplies `OutputBufferLength < 8`, the I/O manager allocates a pool buffer smaller than the write, resulting in an out-of-bounds write that corrupts adjacent pool metadata.

**Trigger:** `DeviceIoControl` with `InputBufferLength=2`, `OutputBufferLength=4` → 4-byte pool allocation, 8-byte write, 4-byte overflow.

### Bug 2: IOCTL 0x222008 — NULL Pointer Dereference

**CVE:** Requested (pending assignment)  
**CWE:** CWE-476 (NULL Pointer Dereference)  
**Impact:** Local Denial of Service (BSOD)

The handler for IOCTL `0x222008` (`METHOD_BUFFERED`) writes to `SystemBuffer` without checking for NULL. When called with `InputBufferLength=0` and `OutputBufferLength=0`, the I/O manager sets `SystemBuffer` to NULL, and the handler writes to address `0x0`, causing a `SYSTEM_SERVICE_EXCEPTION` bugcheck.

**Trigger:** `DeviceIoControl` with `InputBufferLength=0`, `OutputBufferLength=0`.

## Reproduction

> **WARNING:** The `nullderef` and `pooloverflow` modes WILL crash the target machine. Run in a VM only.

### Prerequisites

- Windows 10/11 with Iriun Webcam installed
- Iriun app running and connected to a phone (the audio device interface is only enabled during active streaming)
- Python 3.x

### Steps

```
# Step 1: Verify device access (safe, no crash)
python iriun_kernel_poc.py dryrun

# Step 2: Trigger the pool overflow (WILL BSOD)
python iriun_kernel_poc.py pooloverflow

# Step 3: Trigger the NULL deref (WILL BSOD)
python iriun_kernel_poc.py nullderef
```

The `dryrun` mode opens the device handle and confirms the IOCTLs are reachable, without sending a malformed request.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-09-28 | CVE requested via MITRE |
| 2026-10-23 | CVE-2026-106934 assigned (buffer overflow) |
| 2026-10-23 | Second CVE requested (NULL pointer dereference) |
| TBD | Vendor notified |
| TBD | Vendor fix released |
| TBD | Public disclosure |

## Credit

<!-- Replace with your name/handle -->
Discovered by Akshat Singh/ShorterKing

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This proof of concept is provided for educational and authorized security research purposes only. Do not use it against systems you do not own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.
