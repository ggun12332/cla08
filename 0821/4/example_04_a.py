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

    # TODO (Exercise 4.1): Implement the Note class with functionalities to communicate with the note service.
    # Implement the following methods:
    #   - write(self, idx, script, emoj)
    #   - re_write(self, idx, script, emoj)
    #   - read(self, idx)
    #   - erase(self, idx)
    #
    # Hint: You can use the _menu(self, choice) private method as a helper function for menu navigation.
    # Remember to use self.conn for all communication with the service.
    def write(self, idx: int, script: bytes, emoj: int):
        # TODO Implement the write
        #self.menu(1)
        self.conn.sendlineafter(">>>",b"1")
        self.conn.sendlineafter(":",str(idx).encode())
        self.conn.sendlineafter(":",script)
        self.conn.sendlineafter(">>>",str(emoj).encode())    

    def re_write(self, idx: int, script: bytes, emoj: int):
        # TODO Implement the re_write
        self.conn.sendlineafter(">>>",b"2")
        self.conn.sendlineafter(":",b"1")
        self.conn.sendlineafter(":",str("hihihi").encode())
        self.conn.sendlineafter(">>>",b"1")
    def read(self, idx: int) -> bytes:
        # TODO Implement the read
        pass

    def erase(self, idx: int):
        # TODO Implement the erase
        pass

    def interactive(self):
        self.conn.interactive()


def print_content(content: bytes):
    if not content:
        content = b""
    try:
        print(f"Note content: {content.decode()}")
    except UnicodeDecodeError:
        parts = content.split(b"\n", 2)
        print(f"Note content: {parts[0].decode()}\n{parts[1]}")


def main():
    p = conn()
    note = Note(p)

    if args.GDB:
        attach_gdb(p)

    # TODO (Exercise 4.2): Analyze the output above and identify the anomal behavior.
    # After implementing the Note class, the followings are executed like this:
    # Note content: ^_____^
    # Happy
    #
    # Note content: T_____T
    # Sad\x05\x06
    note.write(1, b"Happy", 1)
    content = note.read(1)
    print_content(content)
    note.erase(1)

    note.write(2, b"Sad", 2)
    content = note.read(1)
    print_content(content)
    p.interactive()


if __name__ == "__main__":
    main()
