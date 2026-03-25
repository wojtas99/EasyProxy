import ctypes
import time
import sys

PIPE_ACCESS_INBOUND = 1
PIPE_TYPE_MESSAGE = 4
PIPE_READMODE_MESSAGE = 2
PIPE_WAIT = 0
INVALID_HANDLE_VALUE = -1
ERROR_PIPE_CONNECTED = 535

kernel32 = ctypes.windll.kernel32

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
        
        buffer = ctypes.create_string_buffer(65536)
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
                print(buffer.raw[:bytes_read.value].decode('utf-8', errors='replace').strip())
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
