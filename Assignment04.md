## Assignment #4: Create Encoding Scheme
---
---
### Introduction
---
This assignment consist on creating a Custom Encoder like the Insertion Encoder, and create a PoC using the [Execve-Stack](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Execve-Stack.nasm) as the shellcode. 
Once this is done, a decoder stub has to be implemented in ASM to decode our shellcode and run it. The encoder will be done using C language.

### Encoder Schema
---
The Encoder requires a working shellcode as input. This string containing the shellcode, will be encoded with the schema and the results will be printed in hexadecimal. 

The encoder will do the following: 
- Rotate each byte of the shellcode 3 bits to left 
- Do a ROT25 on each byte of the shellcode 

#### Left Shift Byte Bits
First to do in the Encoder is to shift 3 bites to left on each byte of the original shellcode:

- Get a byte from the shellcode string
- Shift the bits three positions to left
- If the most significant bit is "1" it should rotate to the less significant bit

This is implemented in the following way:
```pseudocode
shifted_byte = ( original_byte << SHIFTS ) | ( original_byte >> ( BITS_TO_ROTATE - SHIFTS ))
```
Where:
- SHIFTS is how many shifts to do. It our case, is "3" shifts to left
- BITS_TO_ROTATE indicates how many bits are implied in the rotation. As we are working with bytes, it's value is "8" bits.

#### ROT 25
Once the original shellcode has been Left Shifted, it's time to ROT25 it. As we work with bytes it's values can go from 0x00 to 0xFF
- Each byte of the shellcode will get a new value that’s the actual value + 25
- In the case of the last 25 possible values for a byte, we will start from 0x00. 

This table will show the idea:
```markdown
  --------------------------------------------------------------------------------
  |  Original Value    0x00   0x01   ...   0x80   ...   0xe7   0xe8   ...   0xff |
  |  Decimal Value        0      1   ...    128   ...    231    232   ...    255 |
  |  ROT25 Value       0x19   0x1a   ...   0x99   ...   0x00   0x01   ...   0x18 |
  --------------------------------------------------------------------------------
```
This will be implemented for each byte in this way:
```pseudocode
rot_max_value = 256 – 25		                       ; 231 (0xe7) 
if (original_value < rot_max_value) then 
   rot25_value = original_value + 25 
else				                                         ; Here the value will be 231 or greater 
   rot25_value = (original_value + rot) – 256    ; It's rotated from the start
end if 
```
### Encoder Implementation
---



### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment03) for this assignment contains the following files:

- [EggHunter.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunter.nasm) : This is the ASM source code for the first version of the Egg Hunter. It's with NULLs and not caring on the shellcode size, but is more clear to understand the code.
- [EggHunterV2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunterV2.nasm) : This is the NULL free code for the Egg Hunter.
- [ReverseShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/ReverseShell-ExecveStack_V2.nasm) : This is the NULL free code for the Egg Hunter.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/shellcode.c) : The C template with the V2 of the Egg Hunter Shellcode and ReverseShell Shellcode, ready to compile and execute
- [pagesize.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/pagesize.c) : A C program that just prints the size of memory pages in the system

### The End
---
This pages have been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: PA-14628
 
