# Tổng Quan về Heap
- Về cơ bản heap là một vùng bộ nhớ được sử dụng để phân bổ động (có nghĩa là nó có thể phân bổ một lượng không gian không được biết đến tại thời điểm biên dịch), thường thông qua việc sử dụng những thứ như malloc. Vấn đề là malloc có rất nhiều chức năng đằng sau cách nó hoạt động để thực hiện hiệu quả công việc của mình (cả về độ phức tạp của không gian và thời gian chạy). Điều này mang lại cho chúng ta một bề mặt tấn công lớn vào malloc, làm thế nào trong một số tình huống nhất định, chúng ta có thể tận dụng một cái gì đó như tràn một byte null duy nhất vào thực thi mã từ xa đầy đủ. Tuy nhiên, để thực hiện các cuộc tấn công này một cách hiệu quả, bạn sẽ cần hiểu cách thức hoạt động của một số phần nhất định của đống (nó có thể phức tạp hơn một chút so với việc ghi đè lên địa chỉ trả về đã lưu của ngăn xếp). Mục đích của mô-đun này là để giải thích một số phần đó. Hãy bắt tay vào làm việc. Hãy bắt tay vào làm việc.
## Malloc Chunk.
- Khi chúng ta gọi malloc, nó trả về một con trỏ đến một đoạn. Chúng ta hãy xem xét phân bổ bộ nhớ của đoạn cho mã này:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(void)
{
    char *ptr;

    ptr = malloc(0x10);

    strcpy(ptr, "panda");
}

```
- chúng ta có thể thấy memory of the heap chunk ở đây:
```
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555514b <main+22>        mov    rax, QWORD PTR [rbp-0x8]
   0x55555555514f <main+26>        mov    DWORD PTR [rax], 0x646e6170
   0x555555555155 <main+32>        mov    WORD PTR [rax+0x4], 0x61
 → 0x55555555515b <main+38>        nop    
   0x55555555515c <main+39>        leave  
   0x55555555515d <main+40>        ret    
   0x55555555515e                  xchg   ax, ax
   0x555555555160 <__libc_csu_init+0> push   r15
   0x555555555162 <__libc_csu_init+2> mov    r15, rdx
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555515b → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern panda
[+] Searching 'panda' in memory
[+] In '[heap]'(0x555555559000-0x55555557a000), permission=rw-
  0x555555559260 - 0x555555559265  →   "panda"
gef➤  x/4g 0x555555559250
0x555555559250:    0x0    0x21
0x555555559260:    0x61646e6170    0x0

```
- Vì vậy, chúng ta có thể thấy đây là khối đống của chúng tôi. Mỗi heap chunk có một cái gì đó gọi là heap header (tôi thường gọi nó là heap metadata). Trên các hệ thống x64, đó là 0x10 byte trước đó kể từ khi bắt đầu heap chunk và trên các hệ thống x86, đó là 0x8 byte trước đó. Nó chứa hai giá trị riêng biệt, kích thước khối trước đó và kích thước khối.
```
0x0:    0x00     - Previous Chunk Size
0x8:    0x21     - Chunk Size
0x10:     "pada"     - Content of chunk

```
Kích thước đoạn trước đó (nếu nó được đặt, trong trường hợp này không phải là kích thước) chỉ định kích thước của một đoạn trước đó trong bố cục đống đã được giải phóng. Kích thước đống trong trường hợp này là 0x21, khác với kích thước chúng tôi yêu cầu. Đó là bởi vì kích thước chúng tôi chuyển đến malloc, chỉ là dung lượng tối thiểu chúng tôi muốn có thể lưu trữ dữ liệu. Do tiêu đề heap, 0x10 byte bổ sung được thêm vào các hệ thống x64 (thêm 0x8 byte được thêm vào các hệ thống x86). Ngoài ra trong một số trường hợp, nó sẽ làm tròn một số lên, vì vậy nó có thể xử lý nó tốt hơn với những thứ như binning. Ví dụ: nếu bạn đưa malloc một kích thước 0x7f, nó sẽ trả về kích thước 0x91. Nó sẽ làm tròn kích thước 0x7f để 0x80 để nó có thể đối phó với nó tốt hơn. Có thêm 0x10 byte cho tiêu đề heap. Ngoài ra, 0x1 từ cả 0x91 và 0x21 đến từ bit sử dụng trước đó, điều này chỉ biểu thị nếu đoạn trước đó đang được sử dụng và không được giải phóng.

Ngoài ra, ba bit đầu tiên của kích thước malloc là các lá cờ chỉ định những thứ khác nhau (một phần lý do để làm tròn). Nếu bit được đặt, điều đó có nghĩa là bất cứ điều gì cờ chỉ định là đúng (và ngược lại):

``````
0x1:     Previous in Use     - Specifies that the chunk before it in memory is in use
0x2:    Is MMAPPED               - Specifies that the chunk was obtained with mmap()
0x4:     Non Main Arena         - Specifies that the chunk was obtained from outside of the main arena
``````
Chúng ta sẽ nói về một số điều này có nghĩa là gì sau.
## 1. Fast Bin.
- `Fast bin` bao gồm 7 danh sách được liên kết, thường được gọi bằng idx của chúng. Trên x64, kích thước dao động từ 0x20 - 0x80 theo mặc định. Mỗi idx (là một chỉ mục cho các fastbin chỉ định một danh sách được liên kết của thùng nhanh) được phân tách theo kích thước. Vì vậy, một đoạn kích thước 0x20-0x2f sẽ phù hợp với idx 0, một đoạn kích thước 0x30-0x3f sẽ phù hợp với idx 1, v.v.idx
```
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
```
- Không phải cấu trúc thực tế của `fastbin` là một danh sách được liên kết, trong đó nó trỏ đến đoạn tiếp theo trong danh sách (được cấp nó trỏ đến tiêu đề đống của đoạn tiếp theo):
```
gef➤  x/g 0x602010
0x602010: 0x602020
gef➤  x/4g 0x602020
0x602020: 0x0 0x21
0x602030: 0x0 0x0
```
- Bây giờ `fastbin` được gọi như vậy, bởi vì phân bổ từ thùng nhanh thường là một trong những phương pháp cấp phát bộ nhớ nhanh hơn mà malloc sử dụng. Ngoài ra các khối được chèn vào đầu thùng rác nhanh trước. Điều này có nghĩa là thùng nhanh là LIFO, có nghĩa là phần cuối cùng đi vào danh sách thùng rác nhanh là phần đầu tiên ra ngoài (thường có ở phiên bản `libc 2.23`).
## 2. Tcache.
- `Tcache` giống như `Fast Bins`, tuy nhiên nó có sự khác biệt.

`Tcahce` là một loại cơ chế binning mới được giới thiệu trong `libc 2.26` (trước đó, bạn sẽ không thấy tcahce). Tcache dành riêng cho từng luồng, vì vậy mỗi luồng có tcache riêng. Mục đích của việc này là để tăng tốc hiệu suất vì malloc sẽ không phải khóa thùng rác để chỉnh sửa nó. Ngoài ra trong các phiên bản libc có tcache, tcache là nơi đầu tiên mà nó sẽ tìm cách phân bổ các khối từ hoặc đặt các khối được giải phóng (vì nó nhanh hơn).

Một danh sách bộ nhớ cache thực tế được lưu trữ giống như một Fast Bin, nơi nó là một danh sách được liên kết. Cũng giống như `Fast Bin`, nó là LIFO. Tuy nhiên, một danh sách bộ nhớ cache chỉ có thể chứa 7 khối cùng một lúc. Nếu một đoạn được giải phóng đáp ứng yêu cầu kích thước của bộ nhớ cache tuy nhiên danh sách của nó đã đầy, thì nó sẽ được chèn vào loại `bin` khác theo đáp ứng các yêu cầu về kích thước của nó.
- Hãy xem điều này trong ví dụ sau:
```
#include <stdlib.h>

void main(void)
{
  char *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7;

  p0 = malloc(0x10);
  p1 = malloc(0x10);
  p2 = malloc(0x10);
  p3 = malloc(0x10);
  p4 = malloc(0x10);
  p5 = malloc(0x10);
  p6 = malloc(0x10);
  p7 = malloc(0x10);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(p0);
  free(p1);
  free(p2);
  free(p3);
  free(p4);
  free(p5);
  free(p6);
  free(p7);
}
```
- Với chương trình sau , khi được giải `free()` thì `heap chunk` hoạt động như sau: 
```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7ffff7faec40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7ffff7faec40 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x555555559340, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
- bạn có thể thấy khi mà phiên bản libc của bạn là `libc 2.26` trở đi chương trình sẽ ưu tiên sử dụng `Tcache` sau đấy mới sửu dụng đến `fastbin`.
- Ngoài ra, chỉ cần nhấn mạnh rằng giới hạn đoạn 0x7 chỉ là trên mỗi danh sách của tcache, không phải tổng số khối trong toàn bộ tcache bin, chúng ta có thể thấy ở đây rằng tcache chứa 14 khối trên hai thùng riêng biệt:
```
gef➤  heap bins
─────────────────────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7faec40 ───────────────────────────────────────────────────────────────────────────────────
--Tcachebin--[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
--Tcachebins--[idx=1, size=0x20] count=7  ←  Chunk(addr=0x555555559460, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559430, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559400, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555593d0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555593a0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559370, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559340, size=0x30, flags=PREV_INUSE)
──────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7ffff7faec40 ────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
- Có tổng cộng 64 danh sách tcache, với các giá trị idx từ 0-63, cho kích thước đoạn từ 0x20-0x410:

``````
gef➤  heap bins
─────────────────────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7faec40 ───────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x10] count=1  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x555555559280, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x5555555592b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x5555555592f0, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=4, size=0x50] count=1  ←  Chunk(addr=0x555555559340, size=0x60, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x5555555593a0, size=0x70, flags=PREV_INUSE)
Tcachebins[idx=6, size=0x70] count=1  ←  Chunk(addr=0x555555559410, size=0x80, flags=PREV_INUSE)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x555555559490, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=8, size=0x90] count=1  ←  Chunk(addr=0x555555559520, size=0xa0, flags=PREV_INUSE)
Tcachebins[idx=9, size=0xa0] count=1  ←  Chunk(addr=0x5555555595c0, size=0xb0, flags=PREV_INUSE)
Tcachebins[idx=10, size=0xb0] count=1  ←  Chunk(addr=0x555555559670, size=0xc0, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x555555559730, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=12, size=0xd0] count=1  ←  Chunk(addr=0x555555559800, size=0xe0, flags=PREV_INUSE)
Tcachebins[idx=13, size=0xe0] count=1  ←  Chunk(addr=0x5555555598e0, size=0xf0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x5555555599d0, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=15, size=0x100] count=1  ←  Chunk(addr=0x555555559ad0, size=0x110, flags=PREV_INUSE)
Tcachebins[idx=16, size=0x110] count=1  ←  Chunk(addr=0x555555559be0, size=0x120, flags=PREV_INUSE)
Tcachebins[idx=17, size=0x120] count=1  ←  Chunk(addr=0x555555559d00, size=0x130, flags=PREV_INUSE)
Tcachebins[idx=18, size=0x130] count=1  ←  Chunk(addr=0x555555559e30, size=0x140, flags=PREV_INUSE)
Tcachebins[idx=19, size=0x140] count=1  ←  Chunk(addr=0x555555559f70, size=0x150, flags=PREV_INUSE)
Tcachebins[idx=20, size=0x150] count=1  ←  Chunk(addr=0x55555555a0c0, size=0x160, flags=PREV_INUSE)
Tcachebins[idx=21, size=0x160] count=1  ←  Chunk(addr=0x55555555a220, size=0x170, flags=PREV_INUSE)
Tcachebins[idx=22, size=0x170] count=1  ←  Chunk(addr=0x55555555a390, size=0x180, flags=PREV_INUSE)
Tcachebins[idx=23, size=0x180] count=1  ←  Chunk(addr=0x55555555a510, size=0x190, flags=PREV_INUSE)
Tcachebins[idx=24, size=0x190] count=1  ←  Chunk(addr=0x55555555a6a0, size=0x1a0, flags=PREV_INUSE)
Tcachebins[idx=25, size=0x1a0] count=1  ←  Chunk(addr=0x55555555a840, size=0x1b0, flags=PREV_INUSE)
Tcachebins[idx=26, size=0x1b0] count=1  ←  Chunk(addr=0x55555555a9f0, size=0x1c0, flags=PREV_INUSE)
Tcachebins[idx=27, size=0x1c0] count=1  ←  Chunk(addr=0x55555555abb0, size=0x1d0, flags=PREV_INUSE)
Tcachebins[idx=28, size=0x1d0] count=1  ←  Chunk(addr=0x55555555ad80, size=0x1e0, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x55555555af60, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=30, size=0x1f0] count=1  ←  Chunk(addr=0x55555555b150, size=0x200, flags=PREV_INUSE)
Tcachebins[idx=31, size=0x200] count=1  ←  Chunk(addr=0x55555555b350, size=0x210, flags=PREV_INUSE)
Tcachebins[idx=32, size=0x210] count=1  ←  Chunk(addr=0x55555555b560, size=0x220, flags=PREV_INUSE)
Tcachebins[idx=33, size=0x220] count=1  ←  Chunk(addr=0x55555555b780, size=0x230, flags=PREV_INUSE)
Tcachebins[idx=34, size=0x230] count=1  ←  Chunk(addr=0x55555555b9b0, size=0x240, flags=PREV_INUSE)
Tcachebins[idx=35, size=0x240] count=1  ←  Chunk(addr=0x55555555bbf0, size=0x250, flags=PREV_INUSE)
Tcachebins[idx=36, size=0x250] count=1  ←  Chunk(addr=0x55555555be40, size=0x260, flags=PREV_INUSE)
Tcachebins[idx=37, size=0x260] count=1  ←  Chunk(addr=0x55555555c0a0, size=0x270, flags=PREV_INUSE)
Tcachebins[idx=38, size=0x270] count=1  ←  Chunk(addr=0x55555555c310, size=0x280, flags=PREV_INUSE)
Tcachebins[idx=39, size=0x280] count=1  ←  Chunk(addr=0x55555555c590, size=0x290, flags=PREV_INUSE)
Tcachebins[idx=40, size=0x290] count=1  ←  Chunk(addr=0x55555555c820, size=0x2a0, flags=PREV_INUSE)
Tcachebins[idx=41, size=0x2a0] count=1  ←  Chunk(addr=0x55555555cac0, size=0x2b0, flags=PREV_INUSE)
Tcachebins[idx=42, size=0x2b0] count=1  ←  Chunk(addr=0x55555555cd70, size=0x2c0, flags=PREV_INUSE)
Tcachebins[idx=43, size=0x2c0] count=1  ←  Chunk(addr=0x55555555d030, size=0x2d0, flags=PREV_INUSE)
Tcachebins[idx=44, size=0x2d0] count=1  ←  Chunk(addr=0x55555555d300, size=0x2e0, flags=PREV_INUSE)
Tcachebins[idx=45, size=0x2e0] count=1  ←  Chunk(addr=0x55555555d5e0, size=0x2f0, flags=PREV_INUSE)
Tcachebins[idx=46, size=0x2f0] count=1  ←  Chunk(addr=0x55555555d8d0, size=0x300, flags=PREV_INUSE)
Tcachebins[idx=47, size=0x300] count=1  ←  Chunk(addr=0x55555555dbd0, size=0x310, flags=PREV_INUSE)
Tcachebins[idx=48, size=0x310] count=1  ←  Chunk(addr=0x55555555dee0, size=0x320, flags=PREV_INUSE)
Tcachebins[idx=49, size=0x320] count=1  ←  Chunk(addr=0x55555555e200, size=0x330, flags=PREV_INUSE)
Tcachebins[idx=50, size=0x330] count=1  ←  Chunk(addr=0x55555555e530, size=0x340, flags=PREV_INUSE)
Tcachebins[idx=51, size=0x340] count=1  ←  Chunk(addr=0x55555555e870, size=0x350, flags=PREV_INUSE)
Tcachebins[idx=52, size=0x350] count=1  ←  Chunk(addr=0x55555555ebc0, size=0x360, flags=PREV_INUSE)
Tcachebins[idx=53, size=0x360] count=1  ←  Chunk(addr=0x55555555ef20, size=0x370, flags=PREV_INUSE)
Tcachebins[idx=54, size=0x370] count=1  ←  Chunk(addr=0x55555555f290, size=0x380, flags=PREV_INUSE)
Tcachebins[idx=55, size=0x380] count=1  ←  Chunk(addr=0x55555555f610, size=0x390, flags=PREV_INUSE)
Tcachebins[idx=56, size=0x390] count=1  ←  Chunk(addr=0x55555555f9a0, size=0x3a0, flags=PREV_INUSE)
Tcachebins[idx=57, size=0x3a0] count=1  ←  Chunk(addr=0x55555555fd40, size=0x3b0, flags=PREV_INUSE)
Tcachebins[idx=58, size=0x3b0] count=1  ←  Chunk(addr=0x5555555600f0, size=0x3c0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x5555555604b0, size=0x3d0, flags=PREV_INUSE)
Tcachebins[idx=60, size=0x3d0] count=1  ←  Chunk(addr=0x555555560880, size=0x3e0, flags=PREV_INUSE)
Tcachebins[idx=61, size=0x3e0] count=1  ←  Chunk(addr=0x555555560c60, size=0x3f0, flags=PREV_INUSE)
Tcachebins[idx=62, size=0x3f0] count=1  ←  Chunk(addr=0x555555561050, size=0x400, flags=PREV_INUSE)
Tcachebins[idx=63, size=0x400] count=1  ←  Chunk(addr=0x555555561450, size=0x410, flags=PREV_INUSE)
──────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7ffff7faec40 ────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555561850, bk=0x555555561850
 →   Chunk(addr=0x555555561860, size=0x19b0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
``````
- Nếu nó làm sáng tỏ bất cứ điều gì, tôi cảm thấy như sự tương tự đơn giản tốt nhất mà tôi đã nghe cho tcache là đó là thùng rác nhanh với ít kiểm tra hơn (và có thể lấy các khối lớn hơn một chút).

## Unsorted, Large and Small Bins
- `Unsorted, Large and Small Bins` được gắn chặt với nhau hơn trong cách chúng hoạt động so với các thùng khác. Các thùng chưa được phân loại, lớn và nhỏ đều sống cùng nhau trong cùng một mảng. Mỗi thùng có các chỉ mục khác nhau cho mảng này:

``````
0x00:         Not Used
0x01:         Unsorted Bin
0x02 - 0x3f:  Small Bin
0x40 - 0x7e:  Large Bin
``````
- Có một danh sách cho Thùng chưa được sắp xếp, 62 cho Thùng nhỏ và 63 cho Thùng lớn. Trước tiên hãy nói về `Unsorted bin`.

- Tuy nhiên, đối với các khối được chèn vào một trong các thùng, tuy nhiên không được chèn vào thùng rác nhanh hoặc tcache, trước tiên nó sẽ được chèn vào Thùng chưa được sắp xếp. Các khối sẽ vẫn ở đó cho đến khi chúng được sắp xếp. Điều này xảy ra khi một cuộc gọi khác được thực hiện đến malloc. Sau đó, nó sẽ kiểm tra thông qua Thùng chưa được sắp xếp để tìm bất kỳ khối nào có thể đáp ứng phân bổ. Ngoài ra một điều mà bạn sẽ thấy trong thùng rác chưa được sắp xếp, là nó có khả năng tạo ra một phần của một đoạn để phục vụ một yêu cầu (nó cũng có thể hợp nhất các khối lại với nhau). Ngoài ra khi nó kiểm tra thùng chưa được sắp xếp, nó sẽ kiểm tra xem có khối nào thuộc một trong các danh sách thùng nhỏ / lớn hay không. Nếu có, nó sẽ di chuyển những khối đó vào các thùng thích hợp.
- Khi mà `free()` 1 hàm `malloc(0x410)` trong trường hợp `Tcache và fastbin` đều full hoặc không thỏa đc giới hạn lưu trữ thì nó sẽ đc lưu vào `Unsorted bin`,
- `LƯU Ý:` khi ta `mallooc()` và `free()` các `size` = bằng và liền kề nhau trong `Unsorted bin` thì nó sẽ tự động gộp vào với nhau.
- Còn về `large và small bin` hoạt động như thế nào , về cơ bản ta hiể như sau:
    - *SMALL BIN* : khi trong `Unsorted bin` có 1 `chunk a ` với 1 `size cố định` thì khi ta `malloc()` 1 size bé hơn `chunk a` và nếu khi `malloc()` 1 size nằm trong khoản `0x20 ==> 0x410` thì khi ta `malloc()` hết `size của chunk a` nó sẽ được xếp vào `small bin`.
    - *LARGE BIN* : khi trong `Unsorted bin` có 1 `chunk a ` với 1 `size cố định` thì khi ta `malloc()` 1 size lớn hơn `chunk a` và nếu khi `malloc()` 1 size nằm trong khoản `0x420+` thì khi ta `malloc()` hết `size của chunk a` nó sẽ được xếp vào `large bin` hoặc khi ta `malloc()` 1 `size > size chunk a` thì chương trình sẽ lấy `TOP chunk` trong `Unsorted bin` đê khởi tạo 1 `large bin` với `size = size chunk a`.

