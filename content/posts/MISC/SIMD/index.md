---
title: "SIMD"
date: 2025-09-10
draft: false
description: SIMD for beginner
tags: ["Reverse"]
---

## What is SIMD?
SIMD (Single Instruction, Multiple Data) is a CPU architecture technique which is created for handling multiple data at the same time, which increase effectiveness and performance. It is well used to simultaneously calculate repeative task in such as graphic handling, computer sciencies. Today, I will concentrate on explain and list out some simd instruction that is useful and widely used in some reverse engineering task. This blog aim to teach you survive while reading many SIMD instruction, it will teach you how to infer the usage of SIMD instruction instead of list out all the available stuff

## Explanation
First we have a few things we need to know first
### SIMD register sizes
```
xmm = 128-bit register
ymm = 256-bit register
zmm = 512-bit register
```
And from some primitive size we have known `byte, word, dword, qword`
We could easily calculate that xmm is
```
16 x uint_8
8 x uint_16
....
```
And so on
For example 
```paddb xmm0, xmm1``` is translated into 
```python
for i in range(16):
    xmm0.u8[i] += xmm1.u8[i]
```
### Mnemonic rules
There is some suffix rules
```
b, w, d, q is respectively byte, word, dword, qword
```
For example
```
paddb is add packed bytes
paddw is add packed words
```
There is also some floating-point suffixes (this is important!!)
```
ps is packed single-precision float, 32-bit float vector
pd is packed double-precision float, 64-bit float vector
ss is scalar single float, only one 32-bit float
sd is scalar double float, only one 64-bit float
```
Vector is similar to packed, which stores multiple data with the same data size
Instruction example 

For example
```asm
addps xmm0, xmm1 is adding 4 packed 32-bit float
addpd ymm0, ymm1 is adding 4 packed 64-bit float
addss xmm0, xmm1 is adding low 32-bit float 
addss ymm0, ymm1 is adding low 64-bit float
```
One more important note here is packed is vector (mentioned above) and scalar operation only affects the low element
In this section we have to understand and remember clearly the SIMD data type as well as its suffixes meaning 

### AVX / SSE rules
SSE style is what our examples above illustrate, it usually has two operands
For example: ```addps xmm0, xmm1```
Which means 
```python 
for i in range(4) 
    xmm0.f32[i] += xmm1.f32[i]
```

Whereas AVX style usually comprise of 3 operands with a clearer type definition
For example
```vpaddb xmm0, xmm1, xmm2```
Which means ```xmm0 = xmm1 + xmm2```
We could easily see AVX often has the `v` prefix

## SIMD instruction family
### Load/Stores
```asm
movdqu xmm0, [rsp]
movdqa xmm0, [rsp]
movaps, ymm0, [rsp]
vmovdqa, ymm0, [rsp]
vmovdqu, ymm0, [rsp]
vmovusd, ymm0, [rsp]
```
`a/u is respectively aligned and unaligned` 
In aligned mode, the address we used to load must be aligned (which is divisible) by the data type of SIMD register (16/32/64)

### Bitwise
```pxor, pand, por, pandn```
```vpxor, vpand, vpor, vpandn```

### Arithmetic
```paddb/w/d/q psubb/w/d/q pmullwd```
Fact: There is no pmullb because bytes is super easy to get overflowed, so in CTF many people often do
```unpack to 16bit -> pmullw -> pack back to 8 bytes```
These padd/psub consume overflowed bit. Often called non saturating arithmetic
Fact: There is no signed or unsigned in this situation

### Saturing Arithmetic 
These operation wont comsume the overflowed bit, they will clamp it
```asm
paddsb = signed byte add
paddusb = unsigned byte add
psubsb = signed byte sub
psubusb = unsigned byte sub
...
```
For example
```asm
paddusb xmm0, xmm1
```
Is 
```python
for i in range(16):
    xmm0.u8[i] = xmm0.u8[i] + xmm1.u8[i]
    if OF flag:
        xmm0.u8[i] = 0xff
```

### Multiplication 
We mentioned above but here is a more detail explanation
```asm
pmullw = mull 16-bit lanes, remain 16-bit low
pmulhw = mull 16-bit lanes, remain 16-bit high
pmulhwu = unsigned mull 16-bit lanes, remain 16-bit high
....
```
For example
```asm
pmullw xmm0, xmm1
```
Is equal to 
```python
for i in range(16)
    xmm0.16[i] = low_16_bit(xmm0.16[i] * xmm1.16[i])
```

### Comparision 
Formular 
pcmp[type][data_type]
For example
```
pcmpeqw = compare packed word if equal 
pcmpgtw = compare packed word if greater 
```
Visualize
```asm
pcmpeqb xmm0, xmm1
```
is
```python
for i in range(8):
    xmm0.u8[i] = (xmm0.u8[i] == xmm1.u8[i]) ? 0xff : 0x00
```
The comparision operation should return the whole bit on/off not just only 1 or 0

### Vector mask to scalar 
This is a very important knowledge and feature used in many CTF challenge
```asm
pmovmskb eax, xmm0
```
It would take every bit of each lane and pack them into register (eax in this case)
Regular pattern in CTF we will meet
```asm
pcmpeqb xmm0, xmm1
pmovmskb eax, xmm0
cmp eax, 0xffff
jz equal_branch
diff_branch
```
or we could use this really fast pattern
```asm
ptest xmm0, xmm0
jz fail
```

### Shuffle 
This is the most interesting features and in my opinion I see this commonly in many challenge Reverse Engineering related to SIMD instruction
For example
```asm
pshufb
pshufw
pshufld
pshufhw
...
```
`pshufb xmm0, xmm1` is a bit simpler than other types, the mask is exactly xmm1, if you learned crypto it looks like a small permunation sbox that can be showed like
```python
for i in range(16):
    if xmm1.u8[i] & 0x80:
        xmm0.u8[i] = 0
    else: 
        xmm0.u8[i] = old_xmm0.u8[xmm1.u8[i] & 0x0F]
```
Others have one more 8-bit immediate act like a mask like `ins dest, src, mask`

### Unpack
You can see those instruction 
```asm
punpcklbw
punpckhbw
...
```
This is instruction's formular
```
punpck = unpacking packed
l/h = low/high half
bw/wd/dq = byte to word / word to dword / dword to qword
```
It will get the low or high part of the two source register and unpack into a larger datatype 
Example
```asm 
punpcklbw xmm0, xmm1
```
```
xmm0 = [a0 a1 a2 a3 a4 a5 a6 a7 ...] |
                                     |=> xmm0 = [a0 b0 a1 b1 a2 b2 a3 b3 ...]
xmm1 = [b0 b1 b2 b3 b4 b5 b6 b7 ...] |
```
Or
```asm 
punpckhbw xmm0, xmm1
```
```
xmm0 = [a0 a1 a2 a3 a4 a5 a6 a7 ...] |
                                     |=> xmm0 = [a8 b8 a9 b9 a10 b10 a11 b11 ...]
xmm1 = [b0 b1 b2 b3 b4 b5 b6 b7 ...] |
```

### Pack
This is the opposite site of unpack instruction
For example
```asm
packsswb
packuswb
packssdw
packusdw
```
Name meaning
```
packss = pack signed with signed saturation
packus = pack unsigned with unsigned saturation
wb/dw = word to byte/ dword to word
```
This is simple clamp all signed/unsigned words/dwords value back into byte/word. Then pack it
For example
```python 
# packsswb xmm0, xmm1
def clamp(x):
    if x < -127:
        return 127
    if x > 128
        return 128
    return x
for i in range(16)
    if (i < 8)
        res[i] = clamp(xmm0.u16[i]) 
    else:
        res[i] = clamp(xmm1.u16[i - 8])
xmm0.u8 = res
```

### Shift 
```asm
psllw/pslld/psllq
psrlw/psrld/psrlq
psraw/psrad
```
Formular
```
ps = shift prefix
l/r = left/right
l/a = logical/arithmetic
w/d/q = data type
```
Logical is unsigned shift while arithmetic is signed shift

### Horizontal operation
Normal instructions work lane-by-lane
This instruction combines lane
For example 
```
phaddw
phaddd
haddps
haddpd
psadbw
```
Visualize
```python
# phaddw xmm0, xmm1
xmm0  = [ A0, A1,  A2, A3,  A4, A5,  A6, A7 ]
xmm1  = [ B0, B1,  B2, B3,  B4, B5,  B6, B7 ]
Result = [ A0+A1,  A2+A3,  A4+A5,  A6+A7,  B0+B1,  B2+B3,  B4+B5,  B6+B7 ]
```
`psadbw` is command instruction which is sum of absolute differences of bytes
```python
sum_low = 0
sum_high = 0
for i in range(8)
    sum_low += abs(xmm0.u8[i] - xmm1.u8[i])
    sum_high += abs(xmm0.u8[i + 8] - xmm1.u8[i + 8])
xmm0.u16 = [sum_low, 0, 0, 0, sum_high, 0, 0, 0]
```

### Blend / Select
For example
```asm
pblendw
blendps
blendpd
vpblendd
vpblendvb
```
It means choose some lanes from first source and some lanes from second source, then combine them
```c
# pblendw xmm0, xmm1, 123
for (int i = 0; i < 8; ++i)
    xmm0.u16[i] = mask[i] ? xmm0.u16[i] : xmm1.u16[i]
```

### Conversation Instructions
Example
```asm
pmovsxbd
pmovzxbd
pmovsxbw
pmovzxbw
cvtdq2ps
cvtps2dq
```
Rules
```
pmovsx = packed move with signed-extension
pmovzx = packed move with unsigned-extension
```
```python
# pmovsxbw xmm0, [rax]
for i in range(4)
    xmm0.u32[i] = *(int8_t *)((char *)rax + i)
``` 
Others are
```
cvtdq2ps = convert double qword to packed singled-precision float
cvtps2dq = is reverse
```

## Important Notes
### How to infer the instruction meaning?
Lets take a look at this
```asm
vpmovzxbd xmm0, [rax]
```
We could see that
`v` is AVX form
`p` is packed vector
`movzx` is move with zero extended
`bd` is byte to dword
So this instruction is belongs to conversation instruction which move bytes from rax (zero extended) to dword in SIMD register
```asm
vpcmpeqb ymm0, ymm1, ymm2
```
We could see that
`v` is AVX form
`p` is packed vector
`cmpeq` is compare if equal
`b` is byte
So this instruction is equivalent to
```c
for (int i = 0; i < 32; ++i))
    ymm0.u8[i] = (ymm1.u8[i] == ymm2.u8[i]) ? 0xff : 0x00 
```
```asm 
vpshufd xmm0, xmm1, 0x1b
```
We could see that
`v` is AVX form
`p` is packed vector
`shuf` is shuffle type
`d` is dword
So this instruction is reorder 32-bit lanes xmm1 to xmm0 using mask 0x1b

### Signed and Unsigned / Saturation or Wraparound
Becareful about which instruction is used as signed number or vice versa
Take care of these
```asm
pcmpgtb
pmulhw
pmulhuw
paddsb
paddusb
pmovsx
pmovzx
packss
packus
```
And saturation is limit by the max bound or min bound whereas wraparound means take the normal number with overflowed bit become zero

### Shuffle is layout not math
Do not trying to think shuffle as mathematic operation, it just an operation performed by a prebuilt layouts

## How to read this better
I'm not really sure if I can read this better but in my really short-term experience
SIMD instruction is often used to optimized a simple operation, not too complicated because this is used on a repeated data, so complicated 
logic would not be easily used these instruction (unless the author deliberate it in some specific challenge)
The SIMD instruction is read by layouts

For example it usually includes normal assembly instruction hints like `mov/cmp/add/xor/and/mul...` with data type `byte/word/dword/qword`
Some special is `v` for AVX form, `p` for packed vector, `ps/pd/ss/sd` or saturation operation `ss/us` or some transformation like `bd = byte to dword or bw = byte to word` 

Moreover there is a familiar pattern
```
Read/load data
Reshape data
Transform data
Compare data
Collapse data
Store/Write data
Decide next branch
```

Some familar SIMD instruction you first need to remember (GPT recommended :D)
```
movdqu / vmovdqu       load/store vector
pxor / vpxor           xor / zero register / xor key
pand / por             bitwise logic
paddb/w/d              add lanes
psubb/w/d              subtract lanes
paddusb / paddsb       saturating add
psubusb / psubsb       saturating sub
pmullw / pmulld        multiply lanes
pcmpeqb/w/d            compare equal
pcmpgtb/w/d            compare greater-than
pmovmskb               vector mask to scalar
ptest                  test vector mask
pshufb                 byte shuffle
pshufd                 dword shuffle
punpcklbw/hbw          interleave / widen bytes
packuswb / packsswb    narrow with saturation
psll/psrl/psra         shifts
psadbw                 sum absolute byte differences
```

One more important note is if you're a IDA user, IDA often has their own SIMD instruction helper in C-like pseudocode, this is easier to read and understand but prepare some knowledge about SIMD instruction in assembly levels would help you read it easier 

Huge thanks for those who read till there!! This blog is not only made for sharing knowledge but also for me to remember those ^^. You could refer this blog and rewrite in your styles, while writing it would help you remember stuff easier
Don't forget to jump into some exercise challenge to get more familar with these SIMD :D Seee yahhhh! 