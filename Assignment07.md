## Assignment #4: Custom Crypter
---
---
### Introduction
---
This assignment requires to create a crypter using any existing encryption schema. It can be done in the progrmaming language desireed.

The cypher that's going to be implemented is the [TwoFish Cypher](https://en.wikipedia.org/wiki/Twofish). More information on the algorythm for TwoFish can be found at [Bruce Schneier blog](https://www.schneier.com/academic/twofish/).

The original shellcode to crypt is the generated from [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment7/Execve-Stack.nasm). This shellcode will be crypted using the code in the [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) file, and the crypted code, will be decrypted and then executed in the [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) file.

To implement the TwoFish, the `mcrypt` library is used. Documentation and examples on how to use `macrypt` can be found [here](https://fossies.org/dox/libmcrypt-2.5.8/index.html). In Debian Buster GNU/Linux, is required to install the develop libraries for `mcrypt` to use them.

### Implementation Using `mcrypt`

To work with TwoFish, `mcrypt` requires the following inputs:

- A password that will be used to crypt and decrypt. Password needs to be between 1 and 32 bytes length 
- A Initialization Vector (IV). The size of this IV will be 16 bytes 
- The shellcode (a string) to crypt 

The password and IV that's used to encrypt, needs to be the same ones for the decrypt process And the shellcode string will be in hex format.

Steps to follow for using `mcrypt` in a C Programm are:

1. Initialize `mcrypt` to work with TwoFish in CFB mode. This is done with the `mcrypt_module_open` function, that returns a `MCRYPT` object that is saved as id_crypt 
```c
id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL); 
```
2. Generate a random IV of 16 bytes long 
```c
int iv_size = mcrypt_enc_get_iv_size(id_crypt);   // Will return 16 bytes

for (int i = 0; i < iv_size; i++) {               // For each byte of the IV
    IV[i] = (unsigned char)rand();                // It is ramdomly generated
} 
```
3. Initialize the crypt (or decrypt) process for `mcrypt` for the id_crypt with the right password and generated IV 
```c
mcrypt_generic_init(id_crypt, password, iv_size, IV); 
```
4. Encrypt or decrypt a string (shellcode) 
```c
// Crypt
mcrypt_generic(id_crypt, code, code_length); 
// DeCrypt
mdecrypt_generic(id_crypt, code, code_length); 
```
5. Close mcrypt id before exiting the programm 
```c
mcrypt_generic_end(id_crypt); 
```
For the assignment, two files are created:

- [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) : This code crypts the shellcode. The shellcode is placed into a string in hex format. 
- [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) : Decrypts a TwoFish crypted shellcode. Needs the same password and IV used in the crypt process. Once the shellcode is decrypted, program passes execution to it.

### Crypt: Twofish.c




### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment07) for this assignment contains the following files:

- [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) : Implements the Crypt to the Shellcode
- [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) : Decrypts the Shellcode and Runs it
- [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment7/Execve-Stack.nasm) : This is the code for the shellcode to use in the PoC.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
