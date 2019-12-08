# Clever_Bird

跳过游戏部分, 判断逻辑是这样,

```c
# while ( *(&ConsoleCursorInfo[0].dwSize + idx_v17) == ((v11 >> v19) ^ (Dst[idx_v17] - '0')) )
# {
# v19 += 8;
# ++idx_v17;
# if ( v19 >= 32 )

ida_chars = [0x16, 0xE4, 0xB3, 0xBD]
v11 = 0xA991E504
flag = ""
v11 = [0x04, 0xe5, 0x91, 0xa9]
for i in range(len(ida_chars)):
    flag += chr((ida_chars[i] ^ (v11[i])) + 0x30)
    print(flag)
```

flag 前 4 个: flag{B1RD.....

这是后面的判断

```c
if ( v12 ) {
    v16 = &v37;
    while ( 1 ) {
        v17 = *v16++;
        if ( v17 != v12 % 2 + 48 )
            break;
        v12 /= 2;
        if ( !v12 )
            goto LABEL_20;
    }
}
```

只要知道 v12 是多少就行了，v12 是我们的 score，爆破就好了。最后脚本：

```c

#include<stdio.h>
#include<string.h>

int main(){

    int win_count;
    for(win_count = 1;win_count != 0xffffffff;win_count++){
        float t = ((float)win_count)*0.5;
        int bvisible = *(int*)(&t);

        t = (float)win_count;
        int dwCursorPosition = 0x5F3759DF-((*(int*)(&t))>>1);

        int res = (int)
                ( ((((((1.5-((*(float*)(&dwCursorPosition))*(*((float*)&bvisible)))*(*(float*)(&dwCursorPosition)))*(*(float*)(&dwCursorPosition)))
                    *  100000000.0) * 10.0) + 5.0) / 10.0)
                        );
        if(res == 0x436AE){
            printf("find! res is %d\n",win_count);
            break;
        }
    }
    return 0;
}
```

最后的 v12 = 0x20002，flag 为 flag{B1RD010000000000000001}
