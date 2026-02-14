---
title: "Relocation Table In PE"
date: 2026-02-14
draft: false
categories: ["Reverse"]
---

__Prolouge__: The purpose of this page is to describe what is Relocation in Window PE and analyze Relocation Table in Window PE!

## Introduction
Basically, Relocation is just a loader apply the base relocation table to fix all aboslute value of (EXE/DLL) files if they were not loaded into the prefered ImageBase. This can happen due to ASLR mechanism or due to the fact that the expected loading base has been mapped (collision)

> ASLR (Address Space Layout Randomization) is another mechanism of Window which randomizes the ImageBase for security purpose

Take a look at: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only

The base relocation table is often loaded in the `.reloc` section. However, you can also find it in the Data Directory 6'th element in the `OptionalHeader` of `IMAGE_NT_HEADERS`  

So base relocation table is divided into multiple block. Each block represent for a 4K page. The reason why the divsion is necessary is due to the memory optimization *(you can google this for more detail)*. 

So each block contains many values.
1. The first one is the value that pointing to RVA of the 4K Page of current relocation block
2. The second one is the size of the whole that relocation block. 
3. After the size is an array, represent the entry each entry is a WORD (2 bytes) number divided into 2 part. 
4. The 4 high bit part is the type *the type that specify the operation need to do with the absolute address* and the offset part is the 12 bit value, lead to the address need to be relocation. 


## Script 
All thing is clear now, lets try to extract those attribute clearly. We will write a small script

Now first of all we have to  add type library MSSDK in ida like this. This is just for using struct like `IMAGE_DOS_HEADER`, ... etc
![image](first.png)
*The second one*

```python
import idaapi as api

dos_tp = api.Appcall.typedobj('IMAGE_DOS_HEADER;')
inh_tp = api.Appcall.typedobj('IMAGE_NT_HEADERS;')

def reloc_type_from_value(v: int) -> str:
    m = {
        0: ["IMAGE_REL_BASED_ABSOLUTE"],
        1: ["IMAGE_REL_BASED_HIGH"],
        2: ["IMAGE_REL_BASED_LOW"],
        3: ["IMAGE_REL_BASED_HIGHLOW"],
        4: ["IMAGE_REL_BASED_HIGHADJ"],
        5: ["IMAGE_REL_BASED_MIPS_JMPADDR", "IMAGE_REL_BASED_ARM_MOV32", "IMAGE_REL_BASED_RISCV_HIGH20"],
        6: ["IMAGE_REL_BASED_RESERVED"],
        7: ["IMAGE_REL_BASED_THUMB_MOV32", "IMAGE_REL_BASED_RISCV_LOW12I"],
        8: ["IMAGE_REL_BASED_RISCV_LOW12S", "IMAGE_REL_BASED_LOONGARCH32_MARK_LA", "IMAGE_REL_BASED_LOONGARCH64_MARK_LA"],
        9: ["IMAGE_REL_BASED_MIPS_JMPADDR16"],
        10: ["IMAGE_REL_BASED_DIR64"],
    }
    names = m.get(int(v))
    if not names:
        return f"UNKNOWN({v})"
    return names[0] if len(names) == 1 else " / ".join(names)

def retrieve(type, ea):
    ok, v = type.retrieve(ea)
    if not ok:
        print(f'Error ocurred!')
        return None
    return v

def dump_reloc_address(base):
    print(f'Program ImageBase {base:#x}')
    
    dos = retrieve(dos_tp, base)
    if not dos: 
        return
    
    inh_ea = base + dos.e_lfanew
    
    inh = retrieve(inh_tp, inh_ea)
    if not inh:
        return;
    
    reloc_tbl = inh.OptionalHeader.DataDirectory['5']
    reloc_addr = reloc_tbl.VirtualAddress + base
    reloc_addr_end = reloc_addr + reloc_tbl.Size
    
    count = 0
    
    while reloc_addr < reloc_addr_end:
        count += 1
        Addr = api.get_wide_dword(reloc_addr) + base
        Size = api.get_wide_dword(reloc_addr + 4)
        number_of_entries = (Size - 8) // 2
        print(f'Relocation Table #{count}, Address {reloc_addr:#x} ----> {Addr:#x} / {Size} / {number_of_entries}')
        
        for i in range(number_of_entries):
            entry = api.get_wide_word(reloc_addr + 8 + 2 * i)
            type = entry >> 12
            offset = entry & 0xFFF
            
            fixup_addr = Addr + offset
            
            if type != 0:
                print(f'Entry #{i} Type: {type} Offset {offset} ----> Fixup {fixup_addr:#x} Type: {reloc_type_from_value(type)}')
            
        reloc_addr += Size
        print('')
        
api.msg_clear()
dump_reloc_address(api.get_imagebase())
```


You can open abitrary EXE/DLL file on your window computer or download on the internet and load it into IDA and use this script for testing.

>[!Note]
If you found any misleading knowledge or something about my understanding, please comment I will fix it!


