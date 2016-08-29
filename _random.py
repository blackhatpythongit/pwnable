from pwn import *

host = "pwnable.kr"
port = 2222
user = "random"
password = "guest"
binary = "/home/random/random"

random = 0x6b8b4567
key = random ^ 0xdeadbeef

shell = ssh(host=host, port=port, user=user, password=password)
r = shell.run(binary)
r.sendline( str(key) )
flag = r.recvall()
print flag
shell.close()
