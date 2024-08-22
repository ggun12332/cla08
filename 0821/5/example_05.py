#!/usr/bin/env python
from pwn import *
import string

BINARY = "./shellcoding_test"

HOST = "3.34.49.33"
PORT = 1005

context.terminal = ["tmux", "split-window", "-h"]

# Load binary
elf = context.binary = ELF(BINARY)

# GDB script
gs = """
b *main+142
continue
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


def craft_shellcode(flag_idx: int, test_byte: int) -> bytes:
    # TODO (Exercise 5.1): Write shellcode to exploit the timing side-channel attack
    #
    # Overall Strategy:
    # Leak a flag string byte-by-byte using a timing side-channel attack.
    #
    # Key Concepts:
    # 1. Create a timing difference based on byte comparison
    # 2. Use comparison (cmp) and conditional jump (je) for timing difference
    # 3. Matching bytes: Enter infinite loop (noticeable delay)
    # 4. Non-matching bytes: Trigger system call (quick exit)
    #
    # Implementation Tips:
    # - Use a label for the infinite loop jump
    # - Access target memory via stack pointer (rbp)
    # - Compare between registers (e.g., al vs bl)
    #
    # Remember: The timing difference between outcomes is crucial for the side-channel attack
    shellcode = asm(
        f"""
    """
    )
    assert len(shellcode) <= 0x100
    return shellcode


def leak_single_byte(byte_offset):
    for char in string.printable:
        shellcode = craft_shellcode(byte_offset, ord(char))

        with conn() as p:
            if args.GDB:
                attach_gdb(p)
            p.send(shellcode)
            try:
                p.recvline(timeout=1)
                return char
            except EOFError:
                continue
    return None


def main():
    flag = ""
    for i in range(0x100):  # Assume a maximum flag length of 256 bytes
        leaked_char = leak_single_byte(i)

        if leaked_char is None:
            print(f"Failed to leak byte at index {i}")
            break

        flag += leaked_char
        print(f"Current flag: {flag}")

        if leaked_char == "}":
            print("Flag extraction complete!")
            break


if __name__ == "__main__":
    main()
