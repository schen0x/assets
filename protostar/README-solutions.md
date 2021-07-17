# the solutions of protostar

## stack0

```asm
(gdb)disassemble
Dump of assembler code for function main:
=> 0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     and    esp,0xfffffff0
   0x080483fa <+6>:     sub    esp,0x60                    # allocating space. char buffer[64]
   0x080483fd <+9>:     mov    DWORD PTR [esp+0x5c],0x0    # volatile int modified
   0x08048405 <+17>:    lea    eax,[esp+0x1c]
   0x08048409 <+21>:    mov    DWORD PTR [esp],eax
   0x0804840c <+24>:    call   0x804830c <gets@plt>
   0x08048411 <+29>:    mov    eax,DWORD PTR [esp+0x5c]
   0x08048415 <+33>:    test   eax,eax
   0x08048417 <+35>:    je     0x8048427 <main+51>
   0x08048419 <+37>:    mov    DWORD PTR [esp],0x8048500
   0x08048420 <+44>:    call   0x804832c <puts@plt>
   0x08048425 <+49>:    jmp    0x8048433 <main+63>
   0x08048427 <+51>:    mov    DWORD PTR [esp],0x8048529
   0x0804842e <+58>:    call   0x804832c <puts@plt>
   0x08048433 <+63>:    leave
   0x08048434 <+64>:    ret
```

+ `[esp+0x1c]`: the variable
+ `[esp+0x5c]`: the stack buffer

+ when input length > buffer.size, the bottom of the stack (ebp) gets overwrited

+ **Think about the pointer. `buffer[65]` points to a higher address than `buffer[0]`.**
+ The actual memory location of the `buffer` could be printed using `printf("%p\n", (void *) buffer)`, or `$esp+0x1c` @ `*main + 17`.
+ Hence when the buffer overflows, the variable stored at `[esp+0x5c]` @ `*main + 9`, which is higher than the aforementioned `buffer`, will be overwritten eventually.
