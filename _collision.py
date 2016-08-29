from pwn import *

host = "pwnable.kr"
port = 2222
user = "col"
password = "guest"
binary = "/home/col/col"

shell = ssh(host=host, port=port, user=user, password=password)
passcode = p32( 0x39F901FC ) * 5
r = shell.run( binary + " " + passcode )
flag = r.recvall()
print flag
shell.close()
