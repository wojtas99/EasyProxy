import ctypes
import ctypes.wintypes
import time
import sys
import struct
import threading
import queue
import tkinter as tk
from tkinter import ttk, font

PIPE_ACCESS_INBOUND   = 0x00000001
PIPE_TYPE_MESSAGE     = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT             = 0x00000000
INVALID_HANDLE_VALUE  = ctypes.c_void_p(-1).value
ERROR_PIPE_CONNECTED  = 535

PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS        = 0x00000002
TH32CS_SNAPMODULE         = 0x00000008
TH32CS_SNAPMODULE32       = 0x00000010

kernel32 = ctypes.windll.kernel32

# ── Structures ─────────────────────────────────────────────────────────────────

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

# ── Process helpers ─────────────────────────────────────────────────────────────

def get_pid(process_name: str):
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

def get_module_base(pid: int, module_name: str):
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

def read_memory(process_handle, address: int, size: int):
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)

# ── XTEA ───────────────────────────────────────────────────────────────────────

XTEA_DELTA         = 0x9E3779B9
XTEA_ROUNDS        = 32
MASK32             = 0xFFFFFFFF
UNENCRYPTED_HEADER = 6

def xtea_decrypt_block(block: bytes, key: list) -> bytes:
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

def xtea_decrypt(data: bytes, key: list) -> bytes:
    payload = data[UNENCRYPTED_HEADER:]
    result  = bytearray()
    blocks  = len(payload) // 8
    for i in range(blocks):
        result += xtea_decrypt_block(payload[i*8:(i+1)*8], key)
    tail = len(payload) % 8
    if tail:
        result += payload[len(payload)-tail:]
    return bytes(result)

# ── Key reading ─────────────────────────────────────────────────────────────────

PROCESS_NAME   = "otclient_dx_x64.exe"
POINTER_OFFSET = 0x01372D40
KEY_OFFSET     = 0x28

def read_xtea_key():
    pid = get_pid(PROCESS_NAME)
    if pid is None:
        return None
    base = get_module_base(pid, PROCESS_NAME)
    if base is None:
        return None
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        ptr_bytes = read_memory(handle, base + POINTER_OFFSET, 8)
        if ptr_bytes is None:
            return None
        key_ptr   = struct.unpack('<Q', ptr_bytes)[0]
        key_bytes = read_memory(handle, key_ptr + KEY_OFFSET, 16)
        if key_bytes is None:
            return None
        return list(struct.unpack('<4I', key_bytes))
    finally:
        kernel32.CloseHandle(handle)

# ── Hex dump ───────────────────────────────────────────────────────────────────

def hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk      = data[i:i+16]
        hex_part   = ' '.join(f'{b:02X}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'  {hex_part}  |  {ascii_part}')
    return '\n'.join(lines)

# ── Packet parsing ──────────────────────────────────────────────────────────────

def parse_packet(raw_text: str):
    lines  = raw_text.strip().splitlines()
    header = lines[0] if lines else ""

    direction = None
    if "[Client->Server]" in header:
        direction = "c2s"
    elif "[Server->Client]" in header:
        direction = "s2c"

    hex_lines = [l.strip() for l in lines[1:] if l.strip()]
    encrypted = None
    if hex_lines:
        try:
            encrypted = bytes(int(b, 16) for l in hex_lines for b in l.split())
        except ValueError:
            pass

    decrypted = None
    key_used  = None
    if encrypted and len(encrypted) > UNENCRYPTED_HEADER + 7:
        key = read_xtea_key()
        if key:
            decrypted = xtea_decrypt(encrypted, key)
            key_used  = key

    return {
        "header":    header,
        "direction": direction,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "key":       key_used,
    }

# ── GUI ─────────────────────────────────────────────────────────────────────────

BG         = "#1a1a2e"
BG2        = "#16213e"
BG3        = "#0f3460"
ACCENT     = "#e94560"
TEXT       = "#e0e0e0"
TEXT_DIM   = "#888888"
C2S_COLOR  = "#4fc3f7"
S2C_COLOR  = "#81c784"
HEX_COLOR  = "#b0bec5"
ASCII_COLOR= "#ffcc80"
KEY_COLOR  = "#ce93d8"

class App(tk.Tk):
    def __init__(self, packet_queue: queue.Queue):
        super().__init__()
        self.packet_queue = packet_queue
        self.packets      = []

        self.title("EasyProxy — Packet Viewer")
        self.configure(bg=BG)
        self.geometry("1100x750")
        self.minsize(800, 500)

        self._build_ui()
        self._poll_queue()

    # ── Layout ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        mono = font.Font(family="Consolas", size=10)

        # ── Top bar ────────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BG3, pady=6, padx=10)
        top.pack(fill=tk.X)

        tk.Label(top, text="EasyProxy", bg=BG3, fg=ACCENT,
                 font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(top, text="Filter:", bg=BG3, fg=TEXT,
                 font=("Segoe UI", 10)).pack(side=tk.LEFT)

        self.show_c2s = tk.BooleanVar(value=True)
        self.show_s2c = tk.BooleanVar(value=True)

        c2s_cb = tk.Checkbutton(top, text="Client→Server", variable=self.show_c2s,
                                bg=BG3, fg=C2S_COLOR, selectcolor=BG,
                                activebackground=BG3, activeforeground=C2S_COLOR,
                                font=("Segoe UI", 10, "bold"),
                                command=self._apply_filter)
        c2s_cb.pack(side=tk.LEFT, padx=(8, 4))

        s2c_cb = tk.Checkbutton(top, text="Server→Client", variable=self.show_s2c,
                                bg=BG3, fg=S2C_COLOR, selectcolor=BG,
                                activebackground=BG3, activeforeground=S2C_COLOR,
                                font=("Segoe UI", 10, "bold"),
                                command=self._apply_filter)
        s2c_cb.pack(side=tk.LEFT, padx=4)

        tk.Button(top, text="Clear", bg=ACCENT, fg="white",
                  activebackground="#c0392b", activeforeground="white",
                  relief=tk.FLAT, padx=12, pady=2,
                  font=("Segoe UI", 10, "bold"),
                  command=self._clear).pack(side=tk.RIGHT, padx=4)

        # ── Main pane ──────────────────────────────────────────────────────────
        pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=BG, sashwidth=4,
                               sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left: packet list
        left = tk.Frame(pane, bg=BG2)
        pane.add(left, minsize=260, width=300)

        tk.Label(left, text="Packets", bg=BG2, fg=TEXT_DIM,
                 font=("Segoe UI", 9, "bold"), anchor="w",
                 padx=8, pady=4).pack(fill=tk.X)

        list_frame = tk.Frame(left, bg=BG2)
        list_frame.pack(fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Pkg.TListbox", background=BG2, foreground=TEXT,
                         selectbackground=BG3, selectforeground=ACCENT,
                         borderwidth=0, highlightthickness=0, relief=tk.FLAT)

        self.listbox = tk.Listbox(list_frame, bg=BG2, fg=TEXT,
                                  selectbackground=BG3, selectforeground=ACCENT,
                                  font=("Consolas", 10), bd=0, highlightthickness=0,
                                  activestyle="none", yscrollcommand=vsb.set)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        vsb.config(command=self.listbox.yview)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        # Right: detail view
        right = tk.Frame(pane, bg=BG)
        pane.add(right, minsize=400)

        tk.Label(right, text="Packet Detail", bg=BG, fg=TEXT_DIM,
                 font=("Segoe UI", 9, "bold"), anchor="w",
                 padx=8, pady=4).pack(fill=tk.X)

        detail_frame = tk.Frame(right, bg=BG)
        detail_frame.pack(fill=tk.BOTH, expand=True)

        dvsb = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL)
        dvsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.detail = tk.Text(detail_frame, bg=BG2, fg=TEXT,
                              font=mono, bd=0, highlightthickness=0,
                              wrap=tk.NONE, state=tk.DISABLED,
                              yscrollcommand=dvsb.set,
                              insertbackground=ACCENT)
        self.detail.pack(fill=tk.BOTH, expand=True)
        dvsb.config(command=self.detail.yview)

        xsb = ttk.Scrollbar(right, orient=tk.HORIZONTAL, command=self.detail.xview)
        xsb.pack(fill=tk.X)
        self.detail.config(xscrollcommand=xsb.set)

        self.detail.tag_config("header_c2s", foreground=C2S_COLOR,
                               font=("Segoe UI", 10, "bold"))
        self.detail.tag_config("header_s2c", foreground=S2C_COLOR,
                               font=("Segoe UI", 10, "bold"))
        self.detail.tag_config("section",    foreground=ACCENT,
                               font=("Consolas", 10, "bold"))
        self.detail.tag_config("hex",        foreground=HEX_COLOR)
        self.detail.tag_config("key",        foreground=KEY_COLOR)
        self.detail.tag_config("dim",        foreground=TEXT_DIM)

        # ── Status bar ─────────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Waiting for client...")
        tk.Label(self, textvariable=self.status_var, bg=BG3, fg=TEXT_DIM,
                 font=("Segoe UI", 9), anchor="w", padx=10, pady=3).pack(
                 fill=tk.X, side=tk.BOTTOM)

    # ── Queue polling ───────────────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                msg = self.packet_queue.get_nowait()
                if msg["type"] == "packet":
                    self._add_packet(msg["data"])
                elif msg["type"] == "status":
                    self.status_var.set(msg["text"])
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    # ── Packet management ───────────────────────────────────────────────────────

    def _add_packet(self, pkt: dict):
        self.packets.append(pkt)
        if self._visible(pkt):
            self._append_to_listbox(pkt, len(self.packets) - 1)

    def _visible(self, pkt: dict) -> bool:
        if pkt["direction"] == "c2s" and not self.show_c2s.get():
            return False
        if pkt["direction"] == "s2c" and not self.show_s2c.get():
            return False
        return True

    def _apply_filter(self):
        self.listbox.delete(0, tk.END)
        for idx, pkt in enumerate(self.packets):
            if self._visible(pkt):
                self._append_to_listbox(pkt, idx)

    def _append_to_listbox(self, pkt: dict, idx: int):
        direction_label = "C→S" if pkt["direction"] == "c2s" else "S→C"
        size_str = f"{len(pkt['encrypted'])} B" if pkt["encrypted"] else "?"
        label = f"#{idx+1:04d}  {direction_label}  {size_str}"
        self.listbox.insert(tk.END, label)
        color = C2S_COLOR if pkt["direction"] == "c2s" else S2C_COLOR
        self.listbox.itemconfig(tk.END, fg=color)

    def _on_select(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        label = self.listbox.get(sel[0])
        try:
            idx = int(label.split()[0].lstrip('#')) - 1
        except (ValueError, IndexError):
            return
        if 0 <= idx < len(self.packets):
            self._show_detail(self.packets[idx])

    def _show_detail(self, pkt: dict):
        self.detail.config(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)

        tag = "header_c2s" if pkt["direction"] == "c2s" else "header_s2c"
        self.detail.insert(tk.END, pkt["header"] + "\n", tag)
        self.detail.insert(tk.END, "─" * 72 + "\n", "dim")

        if pkt["encrypted"]:
            self.detail.insert(tk.END, "  [Encrypted]\n", "section")
            self.detail.insert(tk.END, hex_dump(pkt["encrypted"]) + "\n", "hex")

            if pkt["decrypted"]:
                self.detail.insert(tk.END, "\n", "")
                self.detail.insert(tk.END,
                    f"  [Decrypted]  key={[hex(k) for k in pkt['key']]}\n", "key")
                self.detail.insert(tk.END, hex_dump(pkt["decrypted"]) + "\n", "hex")
            else:
                self.detail.insert(tk.END,
                    "\n  [Key unavailable — decryption skipped]\n", "dim")
        else:
            self.detail.insert(tk.END, pkt["header"] + "\n", "dim")

        self.detail.config(state=tk.DISABLED)

    def _clear(self):
        self.packets.clear()
        self.listbox.delete(0, tk.END)
        self.detail.config(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.config(state=tk.DISABLED)

# ── Pipe listener thread ────────────────────────────────────────────────────────

def pipe_thread(pkt_queue: queue.Queue):
    pipe_name = r"\\.\pipe\EasyProxyPipe"

    while True:
        pipe = kernel32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 65536, 65536, 0, None
        )

        if pipe == INVALID_HANDLE_VALUE:
            pkt_queue.put({"type": "status", "text": "Failed to create pipe — retrying..."})
            time.sleep(1)
            continue

        pkt_queue.put({"type": "status", "text": "Waiting for client..."})

        connected = kernel32.ConnectNamedPipe(pipe, None)
        if connected == 0 and kernel32.GetLastError() != ERROR_PIPE_CONNECTED:
            kernel32.CloseHandle(pipe)
            continue

        pkt_queue.put({"type": "status", "text": "Client connected."})

        buffer     = ctypes.create_string_buffer(65536)
        bytes_read = ctypes.c_ulong(0)

        while True:
            success = kernel32.ReadFile(
                pipe, buffer, ctypes.sizeof(buffer),
                ctypes.byref(bytes_read), None
            )

            if success and bytes_read.value > 0:
                raw  = buffer.raw[:bytes_read.value]
                text = raw.decode('utf-8', errors='replace').strip()
                pkt  = parse_packet(text)
                pkt_queue.put({"type": "packet", "data": pkt})
            else:
                pkt_queue.put({"type": "status", "text": "Client disconnected — waiting..."})
                break

        kernel32.DisconnectNamedPipe(pipe)
        kernel32.CloseHandle(pipe)

# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    pkt_queue = queue.Queue()

    t = threading.Thread(target=pipe_thread, args=(pkt_queue,), daemon=True)
    t.start()

    app = App(pkt_queue)
    try:
        app.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)
