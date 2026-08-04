---
title: "Dreamhack M Challenge"
date: 2026-07-28
draft: false
description: Tough relocation-style challenge
tags: ["Reverse", "Obfuscated"]
---

### Troll branch

I gonna make this real quick because this is a fake flag

So basically there are multiple ELF binary files embedded in the main executable. Each ELF binary validates every 7 consecutive bytes of the flag by encrypting it with XTEA and comparing with the constant hard-coded in the binary

The 7 consecutive bytes are changed into 8-byte sequence by this modification: `a[i] = variable + variable / 255 + 1` and `variable /= 255`

We could recover the `variable` by using these steps
```C
variable = 255 * k + r
a[i] = (variable + variable / 255 + 1) % 256 
     = (255 * k + r + k + 1) % 256 
     = (256 * k + r + 1) % 256 = r + 1
=> variable = 255 * k + a[i] - 1
Whereas K is the previous "variable" value
```

The `memfd_create -> fork -> fexecve` is pretty insane and new to me, read the [Lesson Learnt](#lesson-learnt) for more details

In the solve script I used z3 because I was lazy to infer the reverse formula

Solve script
```python 
#!/usr/bin/env python3

from pwn import *
from z3 import *

with open('main', 'rb') as f:
    data = f.read()

length = 995
embedded_blob = 0x1F018
embedded_offset = 0x1A180

key_fos = 0x1283

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9

def xtea_decrypt(data: int, key: list[int]) -> int:
    key = [word & MASK for word in key]

    v0 = data & MASK
    v1 = (data >> 32) & MASK
    total = (DELTA * 32) & MASK

    for _ in range(32):
        v1 = (
            v1
            - (
                (((v0 << 4) ^ (v0 >> 5)) + v0)
                ^ (total + key[(total >> 11) & 3])
            )
        ) & MASK

        total = (total - DELTA) & MASK

        v0 = (
            v0
            - (
                (((v1 << 4) ^ (v1 >> 5)) + v1)
                ^ (total + key[total & 3])
            )
        ) & MASK

    return v0 | (v1 << 32)

png = b''

DEBUG = False

blob_offset = 0

for elf_id in range(length):
    if elf_id % 100 == 0:
        print(f"Phase {elf_id}")

    offset = u64(data[embedded_offset + blob_offset: embedded_offset + blob_offset + 8])
    size = u64(data[embedded_offset + blob_offset + 8: embedded_offset + blob_offset + 16])
    blob_offset += 16

    assert(data[:4] == b'\x7fELF')
    ELF_Off = embedded_blob + offset + key_fos
    key = [
        int.from_bytes(data[ELF_Off:ELF_Off+7][3:], 'little'),
        int.from_bytes(data[ELF_Off+7:ELF_Off+14][3:], 'little'),
        int.from_bytes(data[ELF_Off+14:ELF_Off+21][3:], 'little'),
        int.from_bytes(data[ELF_Off+21:ELF_Off+28][3:], 'little'),
    ]
    
    result = int.from_bytes(
        data[
            embedded_blob + offset + 0x13c3:
            embedded_blob + offset + 0x13c3 + 8 
        ]
        , 'little'
    )
    llll = xtea_decrypt(result, key)
    res = p64(llll)

    s = Solver()
    x = BitVec('x', 64)
    value = x
    s.add(value | 0xffffffffffffff == 0xffffffffffffff)
    for i in range(8):
        s.add(
            (value + UDiv(value, 255) + 1) & 0xff == int(res[7 - i])
        )
        value = UDiv(value, 255)
    if s.check() == sat:
        model = s.model()
        flag = model.eval(x).as_long()
    else:
        print(f"Not good! {elf_id} {blob_offset}")
        assert(False)
    if DEBUG:
        print(' '.join(hex(i) for i in key))
        print(hex(llll))
        print(hex(flag))
        print(hex(result))
        print(int.to_bytes(flag, 7, 'big'))
    try:
        png += int.to_bytes(flag, 7, 'big')
    except:
        print(hex(flag))
        exit(0)
    
with open('flag.png', 'wb') as f:
    f.write(png)
```

-----------------------------------------------------------------------------------------
### Challenge Trick
These are things you need to understand to figure out the author's trick. I'm pretty sure you guys already know these things before but haven't done any serious research on them, and yeah neither have I. So we will explore them together
#### Relocation
The structure of ELF64_Rela is
```C
struct ELF64_Rela {
    Elf64_Addr r_offset; // offset of an address with base address
    Elf64_Xword r_info; // The high dword is symbol index, and low is operation type 
    Elf64_Sxword r_addend; // addend value used to adjust the computation
};
```
For example: 
R_X86_64_64: Write at offset `r_offset` the value of symbol's address + Addend
Formula: `P = S + A`

R_X86_64_COPY: Copy the symbol's actualy data into P
Formula: `memcpy(P, S, sizeof(S))`

R_X86_64_RELATIVE64: Write Base + Addend to offset `r_offset`
Formula: `P = B + A`

R_X86_64_GLOB_DAT: Write its symbol's address at runtime to offset `r_offset`
Formula: `P = S`

R_X86_64_PC32/64: Write to offset `r_offset` a 32-bit/64-bit displacement from `r_offset` to the symbol's address + r_addend
Formula: `P = S + A - P`

#### Symbol
The structure of ELF64_Sym is
```C
struct ELF64_Sym {
    // index to string table for example .strtab for
    // static symbols, .dynstr for dynamic symbols/imporots
    uint32_t st_name; 
    // some info 
    unsigned char st_info; 
    // byte that show symbol's visibility (0 = DEFAULT, 2 = HIDDEN)
    unsigned char st_other;
    // index that tell linker which section does this symbol belongs
    // to for example .text, .data, .bss
    uint16_t st_shndx; 
    // depend on what symbol is that, it could be virtual address (after
    // statically resolved), or offset compared to section header in object (.o) file
    uint64_t st_value;
    // Size of symbol for example functions, object, ...
    // For example size in bytes of function, or primitive data type size,... 
    uint64_t st_size;
};
```
The `st_info` is important here. It is an one-byte variable storing two packed fields, I will mention only the important ones

The high 4-bit is Binding
1. STB_LOCAL (0) visible only inside object file
2. STB_GLOBAL (1) visible to all object files being linked
3. STB_WEAK (2) Like STB_GLOBAL, but has weaker precedence

The low 4-bit is Type
1. STT_NOTYPE (0) Undefined type
2. STT_OBJECT (1) A data variable (Like array or struct)
3. STT_FUNC (2) Executable code / function
4. STT_GNU_IFUNC (10) GNU IFUNC

The significant pivot we need to take a look is STB_WEAK and STT_GNU_IFUNC. They could be used to change the program execution flow deliberately

When a program wants to resolve an address of a specific symbol, it does

Firstly if the symbol is defined in current binary, which usually means `st_shndx != SHN_UNDEF`, the program will get the value of `st_value` which is already resolved at the static linking phase by `ld.so`. Additionally, if `STT_GNH_IFUNC` flag is enabled, the shellcode stored at `st_value` will be trigger to resolve the address

Secondly, if the symbol is not defined, the program will hunt for the symbol's address globally base on the string stored at index `st_name` in the dynamic string table

#### LinkMap
As you know in ELF there is a thing called `Lazy Binding`. Because of this feature, the address of a function in shared library will be dynamically resolved by `ld.so` directly or whenever the function is being called.

And the address is resolved and stored in GOT (Global Offset Table). Whenever a program wants to use a function, it calls an indirect stub called PLT (procedure linkage table) which is used to lazily resolved the GOT address or the PLT

In GOT, the first 3 elements are special.

| Index | Meaning |
| --- | --- |
| GOT[0] | Store the address to the dynamic section which supplies the information for `ld.so` |
| GOT[1] | Store a pointer to link_map structure used by `ld.so` to track loaded object |
| GOT[2] | Hold an address of dynamic runtime resolver `_dl_runtime_resolved`           |

Alright these seem important but remembering it is unnecessary in some case, however in this challenge, the author abuses the `GOT[1]` to access the binary data before a binary's entry point is actually executed

There is a technique in terms of exploiting called ret2dlresolve by hijacking the `reloc_arg` passed through the `_dl_runtime_resolved`. We could manually control the function that `_dt_runtime_resolved` resolves

Well talking about that would take a huge amount of time of me and you, so we only mention about how the challenge abuses it. If there is any other techniques using it, we could do research later

So basically its layout is
```C
struct link_map {
    /* 0x00 */ ElfW(Addr) l_addr;      // The ASLR slide (base address difference)
    /* 0x08 */ char *l_name;           // Absolute path to the loaded library
    /* 0x10 */ ElfW(Dyn) *l_ld;        // Pointer to the object's .dynamic section
    /* 0x18 */ struct link_map *l_next; // Next object in the chain
    /* 0x20 */ struct link_map *l_prev; // Previous object in the chain
    
    /* 0x40 */ ElfW(Addr) l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM ...];
};
```

`l_info` is using to cache the address of other dynamic sections. For example `l_info[DT_SYMTAB] -> .dynsym`

`l_addr` often stores loading bias, usually means the difference between the actual loaded base address with the preferred base address. For example, It could be used to leak `libc base address` because `libc` declares its static base in ELF header is `0x0`. So `loading bias = libc base`

-----------------------------------------------------------------------------------------
### The real one

The general concept of this binary is leveraging the ability of the relocation process that linker performs to hide main the validation, 

#### Suspicious Pivot
The first thing that we could notice is a weird `rela.tivity` section. By inspecting it, we could see that it is used to modifty the `DT_RELASZ` of each embedded binary. This part is not really important in terms of analyzing but drive a huge effect to the result of the challenge because the default embedded `DT_RELASZ` is not large enough to cover the whole hidden logic. So this part is used to expand. This is just a small obfuscation that could confuse us a little bit.

```C
ryou@Ryou:~/reverse/m_chall_dh$ readelf -SW main
There are 31 section headers, starting at offset 0x16975760:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000000318 000318 00001c 00   A  0   0  1
  ......
  [ 8] .gnu.version      VERSYM          0000000000000804 000804 00003a 02   A  6   0  2
  [ 9] .gnu.version_r    VERNEED         0000000000000840 000840 000070 00   A  7   1  8
  [10] .rela.dyn         RELA            00000000000008b0 0008b0 000108 18   A  6   0  8
  [11] .rela.tivity      RELA            00000000000009b8 0009b8 017520 18  WA  6   0  1
  [12] .rela.plt         RELA            0000000000017ed8 017ed8 0001e0 18  AI  6  24  8
    ......
  [29] .strtab           STRTAB          0000000000000000 169751e8 000455 00      0   0  1
  [30] .shstrtab         STRTAB          0000000000000000 1697563d 00011e 00      0   0  1
  ```
Idk why I put this output here but yeah make it less "full text blog" 

The truth is that in each relocation section of child program, it is redesigned to act like a simplified Virtual Machine that changes the value of the exit status variable

At first `wrong = 1/correct = 0` so the `exit()` will explicitly show the correct result if the `XTEA encrypted value` match the hard-coded value. However, after passing the hidden validation in the relocation phase, if the input is not satisify, the correct will be changed to 1 -> The program always returns false. 

So next we need to validate each relocation in each binary child. However it must be definitely a pattern, so we just need to analyze once. I will do with the first binary `bin_0`

---

#### Analyze the relocation VM
Well at this point, we need to do a little research, The following part abuses the `link_map` to access a hidden value in `ld.so` that stores information about the arguments. 

The following logs are my translated instruction from the relocating progress, involving 4 relocation types

```C
0x1005000    0x403fd8 = 0x0
0x1005018    0x403fe0 = 0x0
0x1005030    0x804110 = 0x403ff0
0x1005048    memcpy(0x804110, 0x403ff0, 0x8)
0x1005060    0x804140 = 0x18
0x1005078    memcpy(0x804140, 0x18, 0x8)
0x1005090    0x804140 = 0x18
0x10050a8    memcpy(0x804140, 0x18, 0x8)
0x10050c0    0x804140 = 0x18
0x10050d8    memcpy(0x804140, 0x18, 0x8)
0x10050f0    memcpy(0x804140, 0x0, 0x8)
0x1005108    0x804128 = 0x392d0
0x1005120    memcpy(0x804128, 0x392d0, 0x8)
0x1005138    0x804128 = 0xfffffffffffffff0
0x1005150    memcpy(0x804158, 0xfffffffffffffff0, 0x8)
0x1005168    memcpy(0x804180, 0x0, 0x8)
```

Let's analyze this shit carefully. Sorry, my disassembler is such a mess but I don't know how to demonstrate the logs better.

Firstly, there is a repeated pattern you need to figure out
```C
symbol.st_value = addr
memcpy(addr, symbol.st_value, 0x8)
```
This means to retrieve a 8-byte sequence at the address stored in `symbol.st_value`, then It will be copied into a specified address

Because `0x403ff0` is pointing to `GOT[1]` in our binary, it is iterating throw `link_map` 3 times
> *(uint64_t *)link_map->l_next->l_next->l_next

It is equivalently getting the base address of `ld.so`, and then adding with offset `0x392d0`. I don't know what this is either, but after debugging the program, it shows an incrediable result
The value at `0x804180` is pointing to `argv[1]` which is our input

After doing a few research, I have known that it is trying to obtain the pointer pointing into the initial process stack through loader/linker internal data, by calculating the base address of `ld.so` and after that adding it with offset `0x392d0`, we could leak the stack! Wow this is amazing the magic number `0x392d0` is insane, but should I remember this? Nah I just need to know there is such a magic like this, whenever I need it, I will find again

Now we know one observation what `0x804180` is. This is an enormous data because instead of blindly translate the assembly code we could concentrate on hunting for the input modification branch

There is a really weird part that took me a lot of time to figure out (of course using AI, although my assumption about this was at first correct but I ignored it because it just a flash idea flew throw my mind lol). That is, when I debug a program, I don't understand why a function with `0xA` flag enabled is not executed. The reason is the challenge set the `st_shndx` to zero (I mentioned the reason above)

> To be honest, I don't know, knowing these things are actually helpful or not because I feel like it is way too specific toward this challenge and reflex a tiny applicatable benefits

Well basically, when dealing with such a challenge highly obfuscated this like, I'm guessing that this virtual machine is also scrambled and modifed to be taxing to comprehend (after suffering a lots). So I think reading purely each line will break our mind (tried T_T). So we need to lifting it to IR for easier analysis. 

So we need to recreate our interpreter to make it more clean and then we extract slightly each consecutive instruction and witness its repetition and merge it into a block with specific meaning.

For example
```C
0x8040b0 = some_value
next_reloc = 0x8041a0
memcpy(0x8041a0, 0x8040b0, 0x1)
```
This part could be totally lifted into
```C
0x8041a0 = * (_BYTE *) 0x8040b0 // or we could replaced directly to the value at 0x8040b0 
// because 0x8040b0 is just a temporary variable
```

Or this pattern
```C
0x1005828    0x1005840 = 0x205b308
0x1005840    0x205b308 = 0xc348c38348
0x1005858    0x8040e0 = 0x205b308
0x1005870    0x1005888 = 0x205b300
0x1005888    0x205b300 = 0xc
0x10058a0    0x804170 = 0x205b300
0x10058b8    memcpy(0x8040de, 0x205b300, 0x2)
0x10058d0    0x804170 = 0x0
0x10058e8    0x404040 = 0x205b308
```

Let's analyze this
1. First it occupies the address of next function to `0x205b308` which is the `RWE`section to store shellcode
2. Then it pulls shellcode and set the value of `st_shndx` to `0xc` (or any value that diff wth zeero) and execute it
3. Then it will `0x404040` as an deliverer to execute the `STT_GNU_IFUNC` (and it always use `0x404040`)

We can lift those to

```C
JUMP to 0x1005948
```

There is also another `JUMP` pattern (the not executed one). The clear signal we could figure out is setting `0x8040de` to zero we could also be able to lift this pattern and eliminate useless logs parallelly

There is also a failed jump, just making it short and clear, decoy instruction for example setup variable, data is inessential if they're actually the same

By merging respectively clear pattern with clean meaning we could understand what does this program do

After merging pattern and lifting some basic blob I came up with this script
```python
#!/usr/bin/env python3

from pwn import *   
import struct, io
from elftools.elf.elffile import *
from collections import *
from capstone import *
from capstone.x86_const import *

with open('main', 'rb') as f:
    data = f.read()

blob_list = 995
blob_info_offset = 0x1A180
blob_offset = 0x1F018

relocation_offset = 0x5000

bin_id = 1
ELF64_Rela = struct.Struct('<QQq')
ELF64_Sym = struct.Struct('<IBBHQQ')

R_X86_64_GLOB_DAT = 0x6
R_X86_64_64 = 0x1
R_X86_64_COPY = 0x5
R_X86_64_RELATIVE64 = 0x26

def get_relocation_size():
    global bin_id
    offset = 0x9B8 + 0x60 * bin_id
    return u64(data[offset + 0x40 : offset + 0x48]) - u64(data[offset + 0x10 : offset + 0x18]) - 0x10


offset = u64(data[
    blob_info_offset + bin_id * 16: 
    blob_info_offset + bin_id * 16 + 8
])
size = u64(data[
    blob_info_offset + bin_id * 16 + 8:
    blob_info_offset + bin_id * 16 + 16
])

ELF = data[blob_offset + offset : blob_offset + offset + size]
assert(ELF[:4] == b'\x7fELF')

io = io.BytesIO(ELF)
elf = ELFFile(io)

def va_to_file_offset(addr):
    try:
        for iter in elf.iter_segments():
            if iter['p_type'] != 'PT_LOAD':
                continue
            p_vaddr = iter['p_vaddr']
            p_memsz = iter['p_memsz']
            p_filesz = iter['p_filesz']
            p_offset = iter['p_offset']

            if p_vaddr <= addr < p_vaddr + p_memsz:
                if addr >= p_vaddr + p_filesz:
                    return -1
                return addr - p_vaddr + p_offset
    except: pass
    return -1

def get_symbol(index):
    addr = index * 0x18 + dt_sym
    return ELF64_Sym.unpack(ELF[addr : addr + 0x18])

def write_addr(addr, data):
    global ELF
    offset = va_to_file_offset(addr)
    if offset <= 0: return
    ELF = ELF[:offset] + data + ELF[offset + len(data):]
    return

def read_addr(addr, sz):
    global ELF
    offset = va_to_file_offset(addr)
    if offset <= 0: return b'\x00' * sz
    return ELF[offset:offset+sz]

write_addr(0x804180, p64(0xa1fff170fe938d01))

dt_sym = 0x4000
dt_rela = 0x5000
dt_relasz = get_relocation_size()

MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff

access = defaultdict(int)
read = defaultdict(int)
symbol = defaultdict(int)

write_addr(0x804180, p64(0xaaaaaaaaaaaaaaaa))

symbol = {
    0x8040c8: "Sym[8].st_value",
}
data_type = {
    1: "byte", 2: "word", 4: "dword", 8: "qword"
}

def resolve_symbol(x):
    if x in symbol:
        return symbol[x]
    if isinstance(x, int): return hex(x)
    return x

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
def resolve_ifunc(data):
    for ins in md.disasm(data, 0):
        type = ins.mnemonic
        offset = ins.operands[1].imm  
        if type == "sub":
            return -offset
        elif type == "add":
            return offset
        else:
            raise RuntimeError()
    raise RuntimeError()

ic = 0

pc = dt_rela

cache = []
execution_flow = ""
RELOCATION_BASE = 0x1005000

def flush():
    for i in cache: print(i)
    cache.clear()

while pc < dt_rela + dt_relasz:
    ic += 1
    if ic <= 16:
        pc += ELF64_Rela.size
        continue

    r_offset, r_info, r_addend = ELF64_Rela.unpack(ELF[pc : pc + 0x18])

    rela_type = r_info & MASK32
    sym_i = (r_info >> 32) & MASK32

    r_addend &= MASK64
    st_info = get_symbol(sym_i)[1] & MASK64
    st_shndx = get_symbol(sym_i)[3] & MASK64
    st_value = get_symbol(sym_i)[4] & MASK64
    st_size = get_symbol(sym_i)[5] & MASK64

    curr = ""
    curr += f"{(pc - dt_rela + RELOCATION_BASE):#x}    "
    constant = curr

    if rela_type == R_X86_64_64:

        add = (st_value + r_addend) & MASK64

        # if ("0x8040c8" in cache[-1]) and (ELF64_Rela.unpack(ELF[pc - 0x18 : pc])[2] == 1):
            

        if len(cache) > 1 and r_offset == 0x8040e0 and ("0x205b308" in cache[-1]) and ("0x205b308" in cache[-2]):
            cache.pop()
            cache.pop()
            curr += f"Setup Jump to offset {pc + 3 * ELF64_Rela.size - dt_rela + RELOCATION_BASE + resolve_ifunc(read_addr(0x205b308, 8)):#x}"
        else: 
            curr += f"{hex(r_offset)} = {hex(add)}"
        
        write_addr(r_offset, p64(add))

        pass

    if rela_type == R_X86_64_COPY:

        read_data = read_addr(st_value, st_size)
        write_addr(r_offset, read_data)

        """
            need to solve this pattern
            0x1006ad0    0x8040c8 = 0x1
            0x1006ae8    0x1006b00 = 0x804191
            0x1006b00    memcpy(0x804191, 0x8040c8, 0x1)
        """

        if (st_value == 0x8040c8) and (f"{hex(r_offset)}" in cache[-1]) and ("0x8040c8 = 0x" in cache[-2]):
            cache.pop(), cache.pop()
            curr += f"{resolve_symbol(r_offset)} = {hex(int.from_bytes(read_addr(r_offset, st_size), 'little'))}"
            pass
        elif "0x8040b0" in cache[-1]:
            cache.pop()
            curr += f"{resolve_symbol(r_offset)} = {resolve_symbol(st_value)}.{data_type[st_size]}"
        # elif "Prepare" in cache[-1]:
        else:
            curr += f"memcpy({hex(r_offset)}, {hex(st_value)}, {hex(st_size)})"

        pass

    if rela_type == R_X86_64_GLOB_DAT:
        if st_shndx != 0 and st_info == 0xa:
            Function = read_addr(st_value, 8)
            K = 0
            try:
                K += resolve_ifunc(Function)
            except:
                print(f"Function {Function} is not recognized! shndx={st_shndx}, st_value={st_value}")
                exit(0)
            pc += K
            curr += f"JUMP to {pc + ELF64_Rela.size - dt_rela + RELOCATION_BASE:#x}"
        else:
            write_addr(r_offset, p64(st_value))

            if (len(cache) > 1) and (r_offset == 0x404040) and ("memcpy" in cache[-1]) and ("offset" in cache[-2]):
                cache[-2] += f" ({cache[-1].split(", ")[1]} == 0) ---> Failed"
                cache.pop()
                # print("Lmao ", cache[-1])
                # exit(0)
                pass
            else: 
                curr += f"{hex(r_offset)} = {hex(st_value)}"
        pass

    if rela_type == R_X86_64_RELATIVE64:

        write_addr(r_offset, p64(r_addend))

        curr += f"{hex(r_offset)} = {hex(r_addend)}"
        if "0x804170 = 0x0" in curr:
            for i in range(7):
                cache.pop()
            curr = ""
        pass

    if curr != constant and len(curr) > 0:
        cache.append(curr)

    if len(cache) == 100:
        for i in cache[:90]:
            print(i)
        del cache[:90]

    pc += ELF64_Rela.size

flush()
```
*pure human suffering btw*

Btw just in case these steps took likely over 20 hours in total for trial and error hypothesis, writing script, analyzing IR so tough right?? ... I tried GPT and it solved within 60 minutes holy whats a funny joke

You could download the raw log [Here](raw.txt), and the lifted/deobfuscated log [Here](clean.txt)

So basically the validation is
> 1. It first generates a target array stored in 0x804198 -> 0x80419f
> 2. It generates a constant array call `addend[i]` at 0x804190 -> 0x804197
> 3. It stores its transformed input into 0x804188 -> 0x80418f
> 4. The transformation formula is `res[i] = 7 * input[i] + addend[i]` 
> 5. Then it check with the target array

So far we only need these information, hunting for how the program change the exit_status or other stuff is unnecessary anymore

And from that we could reproduce the execution of each child and write a general solver to reverse the transformation and get the input

But there is an inconvenient thing is the `addend[i]` is not only come from the `[0x804190,  0x804197]`, there is a small amount of instruction for each input which hard-coded in the binary used to add additional value for variable, and it is not enough proof to prove it is stored at any specific address so we have to manually reproduce the process to figure out this value by performing a really complicated pattern matching (or it could be more simple but I haven't tried so I don't know)

The easier solution is first we still create an interpreter but we will feed a decoy value, then we could calculate the total addend and just from that calculate the target value. The easiest decoy value is input all zero. Because we just need to inspect the transformed value, the total addend will be revealed `transformed[i] = 7 * 0 + addend[i]`

Sorry I could not provide the exact solver script because of dreamhack's rule but these analysis are my raw working process hope you guys like it. If you need any hints or how to write a proper solve script you could contact me. I'm very pleasant to share my works :D 

---

### Lesson Learnt
1. Hmm what should we got here? Well from the fake flag we could see that, any thing that executed before the main could be the choke point for reverse engineering, without clashing with such an equivalent challenge, it would be difficult to figure out the correct path.

2. The `memfd_create` create an anonymous file descriptor, it acts exactly the same with normal file descriptor, like we can `read`, `write`, `mmap`, ... But it does not exist in the filesystem (which means disk does not store this). `Fork` create a child process inherited everything from its parent from process, memory, the `PPID` of child will be the program created it. And finally `fexecve` is executing a program from known file descriptor (unlike the `execve` executes program using pathname)

3. Unlike other reverse engineering challenge, this challenge "reverse" part of this fake-branch is kind of simple and easy to do, there is no hard trick, obfuscation, packer, cryptography (well there is XTEA but not hard). Although it is not effortless to reverse it, still need to spend a lot of time to understand but by just reading code we could apprehend

4. There could be other technique related to `ld.so` used to hidden deliberated branch

5. If there is a suspicous section with weird permission. For example `WRITE` for uncessary section like Relocation or `RWX` for a random section could be a strong signal

6. To get better at analyzing the virtual machine, we could write disassembler/interpreter and run it with our input, the interpreter is luck based because we're hardly able to manage all the internal logic but the only thing it need to be accurate is `meaning` and `execution branch`. 

7. Lifting raw disassembled/interpreted script to readable IR version is a goodway to deobfuscate and making pattern more clearly. The proof is me, I was working with the raw version and took almost 15 hours without harvesting any idea, while just 3-4 hours with the lifted IR I could solve the challenge

---

If you see any misunderstand or incorrect part in my writeup, don't hesitate to DM me, I would be very pleasant :D