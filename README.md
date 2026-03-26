# 🔮 EasyProxy (Generic Network Proxy)

**EasyProxy** is a high-performance, lightweight native C++ proxy engine based on the WinDivert driver. It provides a non-invasive, transparent bridge for monitoring and modifying real-time network traffic at the packet level.

The core engine is **protocol-agnostic**. It does not care about the contents of the packets, encryption, or application-specific logic. It simply acts as a bridge between the physical network and your custom application.

The communication interface is exposed via a Windows Named Pipe, allowing you to build any tool or script (Python, C#, JS, etc.) to interact with the game/application stream.

## 📡 Connecting to the Engine

EasyProxy opens an asynchronous Windows Named Pipe at the following address for bidirectional communication:

**Named Pipe URL:**
`\\.\pipe\EasyProxyPipe`

You can connect to it using your language's standard I/O (e.g., `open()` in C#, `io.open` in Python, or native Windows API `CreateFile`).

---

## 📥 Receiving Data (Reading)

Once connected, your program should continuously read from the pipe. EasyProxy emits captured events as formatted ASCII strings, each ending with a newline character (`\n`).

### Data Format
Each intercepted packet is reported with a header followed by a hex dump of the payload.

Example output:
```text
Packet ID: 1 [Client->Server] Size 12 bytes
0A 00 5F 31 22 44 ...
```

Your listener can detect these headers and reconstruct the raw binary data for further processing or decryption on your side.

---

## 📤 Injecting Data (Writing)

The engine allows you to forge and inject data directly into an active TCP connection. The proxy automatically handles TCP sequence/acknowledgment numbers and IP header lengths.

### 1. Message Structure

When writing to the pipe, the **FIRST BYTE** of your binary write indicates the direction. All subsequent bytes are the raw data to be sent.

**Direction Flags:**
- `0x00` – Inject into **[Client->Server]** (sent to the remote server).
- `0x01` – Inject into **[Server->Client]** (sent to the local client).

### 2. Protocol Construction

Since the engine is protocol-agnostic, you must provide the **entire, final binary packet** exactly as it should appear on the wire (excluding IP/TCP headers). This includes any length headers, checksums, or encryption required by your specific target.

Example binary structure for a write operation:
```text
[1 Byte - Direction (0x00 or 0x01)]
[X Bytes - Raw application-level packet data]
```

### 3. Synchronization
The engine keeps track of the TCP state. When you inject a packet of size `N`, it automatically updates subsequent sequence numbers for the duration of the session to prevent connection desync.

---

## 🛠️ Diagnostics

If the injection is successful, EasyProxy will pipe back a confirmation string:
`Successfully injected X bytes [Direction]`

If an error occurs (e.g., invalid buffer or permission issues), the engine will report the error back through the pipe in plain text. Monitoring these logs in your listener is essential for reliable operation.
