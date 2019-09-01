# ooollvm

通过动态调试一步一步的调出flag

程序对每个字符的判断逻辑，只有这两种处理方式:

(这是寻找符合条件的代码

```c

for(i = 0;i < 256;i++){
    if(i*0x871f-(i*i*0x143-i*i*i) == 0x12c05d )
        putchar(i);
}

//其中0x871f,0x143,0x12c05d这三个的值会变化

for(i = 0;i < 256;i++){
    if(i*0x84e5-(i*i*320 -i*i*i) == 0x1256a6)
        putchar(i);
}

//其中0x84e5,0x1256a6这两个的值会变化
```

flag{this_is_a_naive_but_hard_obfuscated_program_compiled_by_llvm_pass}

（flag 连蒙带猜的，还好单词没有被替换成数字啥的

这是我调试时写的代码，（很乱

```c
#include <stdio.h>

int main(){
    int i;
    // for(i = 0;i < 256;i++){
        // if(i*0x7a9a-(i*i*0x133-i*i*i) == 0x104e08)
            // putchar(i);
    // }

    // for(i = 0;i < 256;i++){
        // if(i*0x7b67-(i*i*0x134-i*i*i) == 0x1076f4)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x871f-(i*i*0x143-i*i*i) == 0x12c05d)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x97e5-(i*i*0x156-i*i*i) == 0x166ca4)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x98d4-(i*i*0x157-i*i*i) == 0x16a460)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x895c-(i*i*0x145-i*i*i) == 0x135420)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x888b-(i*i*0x144-i*i*i) == 0x132978)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x80cf-(i*i*0x13b-i*i*i) == 0x1180f5)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x80cf-(i*i*0x13b-i*i*i) == 0x1180f5)
            // putchar(i);
    // }
    // flag{this_is_
    // for(i = 0;i < 256;i++){
        // if(i*0x7a3f-(i*i*0x133-i*i*i) == 0x102b8d)
            // putchar(i);
    // }
    // flag{this_is_a_
    // for(i = 0;i < 256;i++){
        // if(i*0x6b3f-(i*i*0x11f-i*i*i) == 0xd5ba1)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x767f-(i*i*0x12e -i*i*i) == 0xf7792)
            // putchar(i);
    // }
    // flag{this_is_a_na
    // for(i = 0;i < 256;i++){
        // if(i*0x7e95-(i*i*0x138 -i*i*i) == 0x11185e)
            // putchar(i);
    // }
    // flag{this_is_a_nai
    // for(i = 0;i < 256;i++){
        // if(i*0x84e5-(i*i*320 -i*i*i) == 0x1256a6)
            // putchar(i);
    // }
    // flag{this_is_a_naiv
    // for(i = 0;i < 256;i++){
        // if(i*0x8861-(i*i*0x144 -i*i*i) == 0x13183e)
            // putchar(i);
    // }
    // flag{this_is_a_naive_
    // for(i = 0;i < 256;i++){
        // if(i*0x7fd3-(i*i*0x13a -i*i*i) == 0x1146b2)
            // putchar(i);
    // }
    // flag{this_is_a_naive_b
    // for(i = 0;i < 256;i++){
        // if(i*0x7083-(i*i*0x126 -i*i*i) == 0xe5916)
            // putchar(i);
    // }
    // flag{this_is_a_naive_bu
    // for(i = 0;i < 256;i++){
        // if(i*0x7c93-(i*i*0x136 -i*i*i) == 0x109ef6)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but
    // for(i = 0;i < 256;i++){
        // if(i*0x8e36-(i*i*0x14b -i*i*i) == 0x144b88)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x8b7b-(i*i*0x148 -i*i*i) == 0x13ac7c)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_
    // for(i = 0;i < 256;i++){
        // if(i*0x80c4-(i*i*0x13b -i*i*i) == 0x117ce0)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_h
    // for(i = 0;i < 256;i++){
        // if(i*0x71ff-(i*i*0x128 -i*i*i) == 0xe9f98)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_ha
    // for(i = 0;i < 256;i++){
        // if(i*0x80ea-(i*i*0x13b -i*i*i) == 0x118c50)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_har
    // for(i = 0;i < 256;i++){
        // if(i*0x7d9e -(i*i*0x137 -i*i*i) == 0x10df88)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard
    // for(i = 0;i < 256;i++){
        // if(i*0x7bf2 -(i*i*0x135 -i*i*i) == 0x108678)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_
    // for(i = 0;i < 256;i++){
        // if(i*0x79a9 -(i*i*0x132 -i*i*i) == 0x101724)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_o
    // for(i = 0;i < 256;i++){
        // if(i*0x780d -(i*i*0x130 -i*i*i) == 0xfc4c2)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_ob
    // for(i = 0;i < 256;i++){
        // if(i*0x7dc4 -(i*i*0x137 -i*i*i) == 0x10ee34)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obf
    // for(i = 0;i < 256;i++){
        // if(i*0x8274 -(i*i*0x13d -i*i*i) == 0x11d87c)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_
    // for(i = 0;i < 256;i++){
        // if(i*0x7a6c -(i*i*0x133 -i*i*i) == 0x103c40)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_p
    // for(i = 0;i < 256;i++){
        // if(i*0x7a6c -(i*i*0x133 -i*i*i) == 0x103c40)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_pr
    // for(i = 0;i < 256;i++){
        // if(i*0x85be -(i*i*0x141 -i*i*i) == 0x128220)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_pro
    // for(i = 0;i < 256;i++){
        // if(i*0x93de -(i*i*0x151 -i*i*i) == 0x15a020)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program
    // for(i = 0;i < 256;i++){
        // if(i*0x8509 -(i*i*320 -i*i*i) == 0x12644a)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x75bf -(i*i*0x12d -i*i*i) == 0xf5393)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_c
    // for(i = 0;i < 256;i++){
        // if(i*0x7757 -(i*i*0x12f -i*i*i) == 0xfa479)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_co
    // for(i = 0;i < 256;i++){
        // if(i*0x78db -(i*i*0x131 -i*i*i) == 0xfedf3)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x8457 -(i*i*0x13f -i*i*i) == 0x1246e9)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compi
    // for(i = 0;i < 256;i++){
        // if(i*0x8f83 -(i*i*0x14c -i*i*i) == 0x14ad50)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x8a55 -(i*i*0x146 -i*i*i) == 0x138f30)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compile
    // for(i = 0;i < 256;i++){
        // if(i*0x897c -(i*i*0x145 -i*i*i) == 0x136140)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled
    // for(i = 0;i < 256;i++){
        // if(i*0x7c40 -(i*i*0x135 -i*i*i) == 0x10a4f0)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled_
    // for(i = 0;i < 256;i++){
        // if(i*0x720b -(i*i*0x128 -i*i*i) == 0xea40c)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled_b
    // for(i = 0;i < 256;i++){
        // if(i*0x6fc2 -(i*i*0x125 -i*i*i) == 0xe34b8)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled_by_
    // for(i = 0;i < 256;i++){
        // if(i*0x7f97 -(i*i*0x13a -i*i*i) == 0x11306e)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled_by_llvm
    // for(i = 0;i < 256;i++){
        // if(i*0x8807 -(i*i*0x144-i*i*i) == 0x12f174)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x867b -(i*i*0x142-i*i*i) == 0x12a502)
            // putchar(i);
    // }
    // flag{this_is_a_naive_but_hard_obfuscated_program_compiled_by_llvm_pas
    // for(i = 0;i < 256;i++){
        // if(i*0x81b3 -(i*i*0x13c-i*i*i) == 0x11b250)
            // putchar(i);
    // }
    // for(i = 0;i < 256;i++){
        // if(i*0x77ff -(i*i*0x130-i*i*i) == 0xfbf90)
            // putchar(i);
    // }
    for(i = 0;i < 256;i++){
        if(i*0x8853 -(i*i*0x144-i*i*i) == 0x131050)
            putchar(i);
    }
    puts("");
    return 0;
}

```
