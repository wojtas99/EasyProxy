import ctypes
import ctypes.wintypes
import time
import sys
import struct

PIPE_ACCESS_INBOUND   = 0x00000001
PIPE_TYPE_MESSAGE     = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT             = 0x00000000
INVALID_HANDLE_VALUE  = ctypes.c_void_p(-1).value
ERROR_PIPE_CONNECTED  = 535

PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
TH32CS_SNAPPROCESS         = 0x00000002
TH32CS_SNAPMODULE          = 0x00000008
TH32CS_SNAPMODULE32        = 0x00000010

kernel32   = ctypes.windll.kernel32
psapi      = ctypes.windll.psapi

# ── Structures ────────────────────────────────────────────────────────────────

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.wintypes.DWORD),
        ("cntUsage",            ctypes.wintypes.DWORD),
        ("th32ProcessID",       ctypes.wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        ctypes.wintypes.DWORD),
        ("cntThreads",          ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        ctypes.wintypes.DWORD),
        ("th32ModuleID",  ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("GlblcntUsage",  ctypes.wintypes.DWORD),
        ("ProccntUsage",  ctypes.wintypes.DWORD),
        ("modBaseAddr",   ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize",   ctypes.wintypes.DWORD),
        ("hModule",       ctypes.wintypes.HMODULE),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]

# ── Process helpers ────────────────────────────────────────────────────────────

def get_pid(process_name: str) -> int | None:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return None
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
            return None
        while True:
            if entry.szExeFile.decode('utf-8', errors='replace').lower() == process_name.lower():
                return entry.th32ProcessID
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                return None
    finally:
        kernel32.CloseHandle(snapshot)

def get_module_base(pid: int, module_name: str) -> int | None:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        return None
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    try:
        if not kernel32.Module32First(snapshot, ctypes.byref(entry)):
            return None
        while True:
            if entry.szModule.decode('utf-8', errors='replace').lower() == module_name.lower():
                return ctypes.addressof(entry.modBaseAddr.contents)
            if not kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                return None
    finally:
        kernel32.CloseHandle(snapshot)

def read_memory(process_handle, address: int, size: int) -> bytes | None:
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)

# ── XTEA ──────────────────────────────────────────────────────────────────────

XTEA_DELTA           = 0x9E3779B9
XTEA_ROUNDS          = 32
MASK32               = 0xFFFFFFFF
UNENCRYPTED_HEADER   = 6

def xtea_decrypt_block(block: bytes, key: list[int]) -> bytes:
    v0, v1 = struct.unpack_from('<II', block, 0)
    s = (XTEA_DELTA * XTEA_ROUNDS) & MASK32
    for _ in range(XTEA_ROUNDS):
        a  = ((((v0 << 4) & MASK32) ^ (v0 >> 5)) + v0) & MASK32
        b  = (s + key[(s >> 11) & 3]) & MASK32
        v1 = (v1 - (a ^ b)) & MASK32
        s  = (s - XTEA_DELTA) & MASK32
        a  = ((((v1 << 4) & MASK32) ^ (v1 >> 5)) + v1) & MASK32
        b  = (s + key[s & 3]) & MASK32
        v0 = (v0 - (a ^ b)) & MASK32
    return struct.pack('<II', v0, v1)

def xtea_decrypt(data: bytes, key: list[int]) -> bytes:
    payload = data[UNENCRYPTED_HEADER:]
    result  = bytearray()
    blocks  = len(payload) // 8
    for i in range(blocks):
        result += xtea_decrypt_block(payload[i*8:(i+1)*8], key)
    tail = len(payload) % 8
    if tail:
        result += payload[len(payload)-tail:]
    return bytes(result)

# ── Key reading ────────────────────────────────────────────────────────────────

PROCESS_NAME   = "otclient_dx_x64.exe"
POINTER_OFFSET = 0x01372D40
KEY_OFFSET     = 0x28

def read_xtea_key() -> list[int] | None:
    pid = get_pid(PROCESS_NAME)
    if pid is None:
        print(f"Process '{PROCESS_NAME}' not found.")
        return None

    base = get_module_base(pid, PROCESS_NAME)
    if base is None:
        print("Failed to get module base address.")
        return None

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print("Failed to open process.")
        return None

    try:
        ptr_addr  = base + POINTER_OFFSET
        ptr_bytes = read_memory(handle, ptr_addr, 8)
        if ptr_bytes is None:
            print(f"Failed to read pointer at 0x{ptr_addr:X}.")
            return None

        key_ptr = struct.unpack('<Q', ptr_bytes)[0]
        key_bytes = read_memory(handle, key_ptr + KEY_OFFSET, 16)
        if key_bytes is None:
            print(f"Failed to read key at 0x{key_ptr + KEY_OFFSET:X}.")
            return None

        key = list(struct.unpack('<4I', key_bytes))
        return key
    finally:
        kernel32.CloseHandle(handle)

# ── Hex dump ──────────────────────────────────────────────────────────────────

def hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'  {hex_part}  |  {ascii_part}')
    return '\n'.join(lines)

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    pipe_name = r"\\.\pipe\EasyProxyPipe"

    while True:
        pipe = kernel32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            None
        )

        if pipe == INVALID_HANDLE_VALUE:
            print("Failed to create pipe.")
            time.sleep(1)
            continue

        print("Waiting for client...")

        connected = kernel32.ConnectNamedPipe(pipe, None)
        if connected == 0 and kernel32.GetLastError() != ERROR_PIPE_CONNECTED:
            kernel32.CloseHandle(pipe)
            continue

        print("Client connected.")

        buffer     = ctypes.create_string_buffer(65536)
        bytes_read = ctypes.c_ulong(0)

        while True:
            success = kernel32.ReadFile(
                pipe,
                buffer,
                ctypes.sizeof(buffer),
                ctypes.byref(bytes_read),
                None
            )

            if success and bytes_read.value > 0:
                raw = buffer.raw[:bytes_read.value]
                text = raw.decode('utf-8', errors='replace').strip()

                lines = text.splitlines()
                header = lines[0] if lines else ""

                hex_lines = [l.strip() for l in lines[1:] if l.strip()]
                if hex_lines:
                    try:
                        encrypted = bytes(int(b, 16) for l in hex_lines for b in l.split())
                    except ValueError:
                        encrypted = None

                    if encrypted and len(encrypted) >= 8:
                        key = read_xtea_key()
                        if key:
                            decrypted = xtea_decrypt(encrypted, key)
                            print()
                            print(f"{header}")
                            print(f"  [Encrypted]")
                            print(hex_dump(encrypted))
                            print()
                            print(f"  [Decrypted] key={[hex(k) for k in key]}")
                            print(hex_dump(decrypted))
                        else:
                            print(f"{header} [Key unavailable - raw hex]")
                            print(hex_dump(encrypted))
                    else:
                        print(text)
                else:
                    print(text)
            else:
                print("Client disconnected.")
                break

        kernel32.DisconnectNamedPipe(pipe)
        kernel32.CloseHandle(pipe)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
