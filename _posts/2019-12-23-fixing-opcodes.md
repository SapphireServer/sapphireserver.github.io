---
layout: post
title: "Fixing Packet Opcodes"
date: 2019-12-23 20:26:12 +1100
categories: dev
author: Adam
---

Annoyingly, SE now randomises all client and server opcode enums, likely as a (bad) attempt to curb the usage of things such as triggers and so on. This is going to be a deep dive into everything networking and a bit of everything else too, so strap yourselves in. I'll be (attempting) to write this as I go along, so it should be easy enough to follow but let me know if anything needs further elaboration and I'll update the post.

<!-- excerpt -->

## Server Packet Handler
Firstly I'd like to talk about how the client handles incoming packets, mainly because it's low hanging fruit and _totally not_ because it's more interesting to everyone. The server packet handler, or `ZoneDownHandler` is basically a single massive function that handles all the routing of incoming packets. This used to make our life pretty easy (and still does to an extent) because you can gain a lot of information about how packets are used just from static analysis. It's also remarkably easy to find by sorting functions by their size and picking the 10th biggest function. There's _better_ ways to find it, but this is brainless to do and doesn't require you to do anything fancy. In case you're curious, the largest function is the GM command handler, the second biggest being the actor control handler.

So lets dive right in. Here's the start of the 5.0 client handler:

```
Client__Network__ZoneDownHandler proc near
                                        ; DATA XREF: .rdata:000000014149DD38↓o
                                        ; .rdata:00000001416184B8↓o ...

; FUNCTION CHUNK AT .text:0000000140B415D0 SIZE 0000002D BYTES

                mov     [rsp+arg_10], rsi
                push    rdi
                sub     rsp, 50h
                mov     esi, edx
                mov     rdi, r8
                movzx   edx, word ptr [r8+2]
                mov     ecx, esi
                call    sub_140713970
                movzx   edx, word ptr [rdi+2]
                lea     eax, [rdx-77h]  ; switch 608 cases
                cmp     eax, 25Fh
                ja      def_140F6ED26   ; jumptable 0000000140F6ED26 default case
                lea     r8, __ImageBase
                cdqe

loc_140F6ED16:                          ; DATA XREF: .rdata:00000001418D85D0↓o
                                        ; .rdata:00000001418D85E4↓o ...
                mov     [rsp+58h+arg_0], rbx
                mov     ecx, ds:(jpt_140F6ED26 - 140000000h)[r8+rax*4]
                add     rcx, r8
                jmp     rcx             ; switch jump
```

If you find something that looks like this, you know you've found the right function. Something interesting to note is that the number of cases is how many opcodes are in the handler. It isn't likely to be 'true' count of opcodes, many debug opcodes are stripped out during release builds, which show up as gaps or are essentially unhandled by client but still exist in the jumptable. Guess SE couldn't decide how they wanted to strip code out of the handler. 

Anyway, rest of the above is basically reading out the opcode from the [IPC header](https://github.com/SapphireServer/Sapphire/blob/002850167b70fd83b4d04536d1f0c5e4e3ece315/src/common/Network/CommonNetwork.h#L161-L169) and then jumping to the correct segment. Time for things to get _actually_ interesting. Consider the two following segments of code, one is from the 5.0 executable, another is from 5.1 (I think; it doesn't matter -- opcodes are different). Note that these 2 segments are also copied from the same place, or in other words, in the same order that code is generated in. If that doesn't make sense and I suck at explaining things, it _should_ make sense shortly.

5.0:

```
loc_140F6ED28:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 125
                mov     rdx, rdi
                lea     ecx, [r8+8]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; ---------------------------------------------------------------------------

loc_140F6ED46:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 255
                mov     rdx, rdi
                lea     ecx, [r8+9]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; 
```

5.1 (probably):

```
loc_141009B38:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                mov     ecx, 8          ; jumptable 0000000141009B36 case 840
                mov     rdx, rdi
                xor     r8d, r8d
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; ---------------------------------------------------------------------------

loc_141009B57:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: .pdata:0000000141EA22C8↓o ...
                mov     ecx, 9          ; jumptable 0000000141009B36 case 110
                mov     rdx, rdi
                xor     r8d, r8d
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
```

<!-- Firstly, here's the [opcode list for 5.0x](https://github.com/SapphireServer/Sapphire/blob/v5.08/src/common/Network/PacketDef/Ipcs.h). -->

There's a few things going on here, so we'll start with something simpler first. The `case <number>` is the opcode in decimal form. Now that the simple stuff is over and out of the way, the second thing I want you to look for is what's going on with `rcx`. It's used in two seperate ways in both executables, but the idea is the same. If you're not sure what's going on yet, I'll explain the boring shit like calling conventions and register usage.

As per [x64 calling conventions](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019#parameter-passing), the first 4 integer parameters are passed through with registers `rcx`, `rdx`, `r8` and `r9` and the rest goes on the stack. Floating point args are passed through `xmm0-3` but that's not relevant here so we'll ignore that for now. Continuing on...

> but adam, `rcx` isnt even used in the code you posted above? wtf?

So, all registers on x64 architecture are also addressable via other operands that address different segments of a register. `rcx` for example can also be addressed in the following ways:

* `ecx` is the lower 32 bits
* `cx` is the lower 16 bits
* `cl` is the lower 8 bits

Starting to make sense? This is also how you can attempt to deduce the type of something, or at least how I _think_ IDA does it. There's a [handy table here with other operands](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture).

With your new found knowledge of x64 registers, you should see what's going on with the value of `rcx` -- notice how they both have the same value? In the 5.1 executable, the first block sets `ecx` to 8 and the second sets `ecx` to 9. The 5.0 executable is similar enough, but slightly different. If you check that handy operand table that I linked before, `r8d` is the lower 32 bits of `r8`. The difference here is that for (whatever reason), MSVC uses `r8` to generate zero -- `xor r8d, r8d` sets the lower 32 bits to zero -- instead of just moving the value directly into `ecx` like it does in the 5.1 executable. Not really sure why, but it ends up just being `r8 + 8` or `0 + 8` in `ecx`. In this case, it also doesn't matter if `r8` has garbage data in the high 32 bits of the register as we move `r8 + 9` into `ecx` which can only fit 32 bits.

Let's try a different opcode, we'll try the 5th block in the handler, again first up is 5.0:

```
loc_140F6EDA0:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
                mov     rcx, cs:g_framework ; jumptable 0000000140F6ED26 case 260
                call    sub_14008FC70
                test    rax, rax
                jz      short loc_140F6EDC8
                mov     r10, [rax]
                xor     r8d, r8d
                mov     r9, rdi
                mov     rcx, rax
                lea     edx, [r8+1]
                call    qword ptr [r10+290h]

loc_140F6EDC8:                          ; CODE XREF: Client__Network__ZoneDownHandler+CF↑j
                lea     rdx, [rdi+10h]
                mov     ecx, esi
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     sub_140711A20
```

5.1:

```
loc_141009BB4:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: .pdata:0000000141EA22EC↓o ...
                mov     rcx, cs:g_framework ; jumptable 0000000141009B36 case 631
                call    sub_140090120
                test    rax, rax
                jz      short loc_141009BDC
                mov     r10, [rax]
                xor     r8d, r8d
                mov     r9, rdi
                mov     rcx, rax
                lea     edx, [r8+1]
                call    qword ptr [r10+2A0h]

loc_141009BDC:                          ; CODE XREF: Client__Network__ZoneDownHandler+D3↑j
                lea     rdx, [rdi+10h]
                mov     ecx, esi
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     sub_140745B70
```

Bit simpler, but same thing, notice how it's the same thing?

![oh yeah, it's all coming together](/assets/garbage/oh-yeah.jpg)

As a quick aside, the opcode is 260 (0x104) in 5.0 and 631 (0x277) in 5.1. If we consult the handy opcode list located [here](https://github.com/SapphireServer/Sapphire/blob/v5.08/src/common/Network/PacketDef/Ipcs.h) for 5.0, we can see it's the region chat packet, and that it's now at 0x277. It was also at this point that I realised that my IDB is not actually the 5.1 client and it's some other 5.1x client, but I don't know which. Uh oh. Oh well.

## Automating Server Opcode Fixes

Now you know how all this stuff fits together, so lets try automating it. I have a couple ideas on how this can work, one is pretty meme-tastic, the other is likely going to be an absolute pain in the ass but probably more reliable. We're gonna do the meme-tastic method first though, because it sounds like more fun.

### The Meme-tastic Method

Someone will probably reel back in their chair after reading this but I don't care because it's fantastically lazy and might just be crazy enough to work. You know how I've shown you how the code generation order is the _same_? See how all this disassembly is text? I hope you see where this is going.

So first of all, we need the entire function as text from both executables. Probably isn't an easier way of doing this without spending more time trying to figure it out (lmao), so we'll just copy it all out. After doing that, we need to remove the section and address from each line, so a quick regex replace later, we get something like this:

```
; ---------------------------------------------------------------------------

loc_140F6ED28:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 125
                mov     rdx, rdi
                lea     ecx, [r8+8]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; ---------------------------------------------------------------------------

loc_140F6ED46:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 255
                mov     rdx, rdi
                lea     ecx, [r8+9]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
```

So we run the magic command `diff -ur 5.0.txt 5.1.txt > lmao.diff` and open it up in your favourite text editor. So the first 2 cases are up first, and interestingly enough, it actually works well:

```diff
 ; ---------------------------------------------------------------------------
 
-loc_140F6ED28:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
-                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o
-                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 125
+loc_141009B38:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
+                mov     ecx, 8          ; jumptable 0000000141009B36 case 840
                 mov     rdx, rdi
-                lea     ecx, [r8+8]
+                xor     r8d, r8d
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
@@ -60,11 +49,11 @@
                 jmp     net__somegenericweirdshit
 ; ---------------------------------------------------------------------------
 
-loc_140F6ED46:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
-                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
-                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 255
+loc_141009B57:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
+                                        ; DATA XREF: .pdata:0000000141EA22C8↓o ...
+                mov     ecx, 9          ; jumptable 0000000141009B36 case 110
                 mov     rdx, rdi
-                lea     ecx, [r8+9]
+                xor     r8d, r8d
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
@@ -72,11 +61,11 @@
                 jmp     net__somegenericweirdshit
```

So lets see if we can find something actually useful and further down the handler, like `PlayerSpawn`. Consulting our [5.0 opcodes](https://github.com/SapphireServer/Sapphire/blob/v5.08/src/common/Network/PacketDef/Ipcs.h) list, we know that `PlayerSpawn` is 0x17F. So we convert that to decimal and search the diff for `case 383`, and look at what we find:

```diff
-loc_140F6EE92:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
-                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
-                lea     r8, [rdi+10h]   ; jumptable 0000000140F6ED26 case 383
+loc_141009CA2:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
+                                        ; DATA XREF: .pdata:0000000141EA2334↓o ...
+                lea     r8, [rdi+10h]   ; jumptable 0000000141009B36 case 801
                 mov     edx, esi
-                lea     rcx, unk_141B2D520
-                call    sub_14063D7A0
-                test    byte ptr cs:qword_141B2DC1B, 4
-                jnz     short loc_140F6EE68
+                lea     rcx, unk_141BFD170
+                call    sub_14066FE20
+                test    byte ptr cs:qword_141BFD883, 4
+                jnz     short loc_141009C78
                 lea     rdx, [rdi+10h]
                 mov     ecx, esi
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
                 pop     rdi
-                jmp     sub_140700670
+                jmp     sub_140734480
```

Yeah. I was surprised too. We'll try another one further down to see if this is just sheer dumb luck or it _actually_ works. We'll do `Mount` which is 0x1F3. Same thing as before, search for `case 499`:

```diff
-loc_140F714C8:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
-                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
-                lea     r8, [rdi+10h]   ; jumptable 0000000140F6ED26 case 499
+loc_14100C387:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
+                                        ; DATA XREF: .pdata:0000000141EA30A8↓o ...
+                lea     r8, [rdi+10h]   ; jumptable 0000000141009B36 case 187
                 mov     edx, esi
-                lea     rcx, unk_141B2D520
-                call    sub_14063E7B0
-                test    byte ptr cs:qword_141B2DC1B, 4
-                jnz     loc_140F6EE68
+                lea     rcx, unk_141BFD170
+                call    sub_140670E30
+                test    byte ptr cs:qword_141BFD883, 4
+                jnz     loc_141009C78
                 lea     rdx, [rdi+10h]
                 mov     ecx, esi
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
                 pop     rdi
-                jmp     sub_140713C10
+                jmp     sub_140747C40
```

Just to prove I'm not yanking your chain, I'll show you how it's the same thing a bit more.

`sub_14063E7B0` and `sub_140670E30` are duty recorder related functions in 5.0 and 5.1x respectively -- we'll skip those, no fun to be had. The stuff we're actually interested in is the last jump, that's where the `Mount` handler is actually located. The test before it is basically a game state check, make sure that you're in game or some shit. Basically it always passes and we'll land at the last jump if you're in game.

5.0 handler:

```
sub_140713C10   proc near               ; CODE XREF: sub_1406403C0+8C0↑p
                                        ; Client__Network__ZoneDownHandler+281C↓j
                                        ; DATA XREF: ...

var_18          = dword ptr -18h
var_10          = byte ptr -10h

                push    rbx
                sub     rsp, 30h
                mov     rbx, rdx
                mov     edx, ecx
                lea     rcx, g_charaMgr ; g_charaMgr
                call    getCharacterById ; getCharacterById(uint)
                test    rax, rax
                jz      short loc_140713C4E
                movzx   ecx, byte ptr [rbx+1]
                mov     r9d, [rbx+8]
                mov     r8d, [rbx+4]
                movzx   edx, byte ptr [rbx]
                mov     [rsp+38h+var_10], cl
                mov     ecx, [rbx+0Ch]
                mov     [rsp+38h+var_18], ecx
                mov     rcx, rax
                call    sub_1406DD370

loc_140713C4E:                          ; CODE XREF: sub_140713C10+1A↑j
                add     rsp, 30h
                pop     rbx
                retn
sub_140713C10   endp
```

5.1x handler:

```
sub_140747C40   proc near               ; CODE XREF: sub_140672AB0+407↑p
                                        ; Client__Network__ZoneDownHandler+28CB↓j
                                        ; DATA XREF: ...

var_18          = dword ptr -18h
var_10          = byte ptr -10h

                push    rbx
                sub     rsp, 30h
                mov     rbx, rdx
                mov     edx, ecx
                lea     rcx, g_charaMgr ; g_charaMgr
                call    getCharacterById ; getCharacterById(uint)
                test    rax, rax
                jz      short loc_140747C7E
                movzx   ecx, byte ptr [rbx+1]
                mov     r9d, [rbx+8]
                mov     r8d, [rbx+4]
                movzx   edx, byte ptr [rbx]
                mov     [rsp+38h+var_10], cl
                mov     ecx, [rbx+0Ch]
                mov     [rsp+38h+var_18], ecx
                mov     rcx, rax
                call    sub_140711880

loc_140747C7E:                          ; CODE XREF: sub_140747C40+1A↑j
                add     rsp, 30h
                pop     rbx
                retn
sub_140747C40   endp
```

Here's a few more I did with the same method:

| Packet Name        | 5.0 Opcode | 5.1x Opcode |
|--------------------|------------|-------------|
| EventFinish        | 0x1BF      | 0x87        |
| DirectorVars       | 0x1F5      | 0x381       |
| EquipDisplayFlags  | 0x220      | 0x57        |
| EorzeaTimeOffset   | 0x214      | 0x353       |
| PlayerSetup        | 0x18F      | 0xAB        |

![holy shit](/assets/garbage/surprised-pikachu.png)

Pretty cool, right?

What if we could automate it even more? Doing this manually is still time consuming -- but admittedly, it's faster than how I used to do it. Unfortunately it's not all sunshine and rainbows, consider the following:

```diff
-loc_140F70322:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
-                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
-                movzx   r8d, dx         ; jumptable 0000000140F6ED26 cases 437-444
+loc_14100B164:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
+                                        ; DATA XREF: .pdata:0000000141EA2A30↓o ...
+                movzx   r8d, dx         ; jumptable 0000000141009B36 cases 25,49,220,252,382,455,683,861
                 lea     r9, [rdi+10h]
                 mov     edx, esi
-                lea     rcx, unk_141B2D520
-                call    sub_14063DED0
+                lea     rcx, unk_141BFD170
+                call    sub_140670550
                 movzx   eax, byte ptr [rdi+28h]
                 lea     rdx, [rdi+2Ch]
                 mov     r9, [rdi+20h]
@@ -2150,7 +2148,7 @@
                 mov     byte ptr [rsp+58h+var_30], al
                 mov     [rsp+58h+var_38], rdx
                 mov     edx, [rdi+18h]
-                call    sub_1406FB9B0
+                call    sub_14072FB10
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
@@ -2158,9 +2156,9 @@
                 retn
```

The opcodes are no longer in order, so while you know what opcodes are in use for the same original code, you can't easily figure out which ones actually do what any more without inspecting what's actually nested in here. This is for the `EventPlay[8,16,32,64,128,256,512,1024]` opcodes. Inventory opcodes work in a similar way, where the routing logic is done inside a nested handler.

### The Unfun But (Potentially) Reliable Method

Now we're at the juicy part and I spent more time trying to think of a witty title for this than I should have. Anyway, while the last method was a total and absolute meme, we learnt a few interesting things:

* The order of handlers in the executable is preserved between builds for the most part -- meaning unless packets get added or removed, order is the same
* The actual code pretty much doesn't change in the handler itself, packets are parsed external to `ZoneDownHandler`
* Some opcodes are grouped and have nested handlers which requires us to navigate into said handlers to be able to correctly remap opcodes

Additional food for thought: What if SE removes an opcode? Alternatively, what if they add a new one? How can we detect that semi-reliably? Realistically, the answer is that we probably don't have to, or at least, not at this stage, but this is something that we could _easily_ find out by doing it this way.

So what we need to do amounts to something along the lines of the following:

1. Automagically find `ZoneDownHandler`
2. Find the jumptable and discover all regions inside the handler and their associated opcodes
3. For each region, read the raw instructions and follow xrefs to a certain depth to essentially create a sub-tree-like representation of a particular packet (or group of packets) in `ZoneDownHandler`
4. Spit all this info out to a JSON file
5. Run this magical script on old and new executable
6. Make another magical script to get the two JSON files and remap opcodes from old -> new
7. Profit?!?

#### Finding ZoneDownHandler

Well, we've already found it. But now we sprinkle some magic in. First things first though, navigate to your HexRays plugins folder and make a new `*.py` file. It's located here: `%appdata%\Hex-Rays\IDA Pro\plugins`. We'll start out with the following code:

```python
import idaapi

class xiv_opcode_parser_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL

    wanted_name = "Find FFXIV Opcodes"
    wanted_hotkey = ""

    comment = 'Does magic and shit'
    help = 'no'
 
    def init(self):
        return idaapi.PLUGIN_OK
 
    def run(self, arg):
        pass
 
    def term(self):
        pass
 
def PLUGIN_ENTRY():
    return xiv_opcode_parser_t()
```

Quick thing to note, `flags = idaapi.PLUGIN_UNL` is the most useful shit ever. Every time you run your script, it'll reload it from disk. You'll need to close and reopen your IDB or reopen IDA for this to get loaded for the first time. Now we embrace the magic.

If you have a plugin like sigmaker installed, you can just use that to get a signature for the handler. An auto-generated one is: `48 89 74 24 ? 57 48 83 EC 50 8B F2 49 8B F8` but you could make a more verbose one and capture more of the actual code if you'd like to by selecting a region of code -- though it's probably not going to make too much difference.

Now we use the pattern to find the handler:

```python
def find_pattern(pattern):
    return ida_search.find_binary(0, ida_ida.cvar.inf.max_ea, pattern, 16, ida_search.SEARCH_DOWN)

def run():
    handler_ea = find_pattern('48 89 74 24 ? 57 48 83 EC 50 8B F2 49 8B F8')

    if handler_ea == ida_idaapi.BADADDR:
        print('couldn''t find server opcode handler')
        return

    print('found opcode handler @ %x' % handler_ea)
```

Update the run method inside `xiv_opcode_parser_t` to call your new run method instead of doing nothing. Now you should be able to run this by going to Edit -> Plugins -> Find FFXIV Opcodes and it should spit out an address. You can double click it and it'll take you straight to the function. Magic.

You'll also find out very quickly that the IDA API is garbage to work with because the docs are shit and reverse engineering is witchcraft. I'm not going to explain the above because its both disgusting and irrelevant and its only gonna get worse here on out.

#### Finding The Jumptable

First thing we need is the start and end of the handler function, this'll be more useful later but we'll get it now.

```python
def run():
    func_ea = find_pattern('48 89 74 24 ? 57 48 83 EC 50 8B F2 49 8B F8')

    if func_ea == ida_idaapi.BADADDR:
        print('couldn''t find server opcode handler')
        return

    func_end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

    print('found opcode handler @ %x -> %x' % (func_ea, func_end_ea))
```

Pretty simple for now, but now we need to locate the jumptable. This is just going to be more magic, but in a nutshell, we need to iterate over each 'chunk' of a function and then within those, we need to find each 'head', where a head is basically a data item or an instruction. For each of those, we check if we can get switch info using `get_switch_info_ex` and if we can, we've probably found the correct switch. There's only one switch inside `ZoneDownHandler` so this works pretty well.

```python
def log(str, indent=0):
    print('%s%s' % ('  ' * indent, str))

def find_switch(ea):
    # get all chunks that belong to a function, which are apparently not contiguous or some shit
    for (start_ea, end_ea) in idautils.Chunks(ea):
        for head in idautils.Heads(start_ea, end_ea):
            switch = idaapi.get_switch_info_ex(head)

            if switch != None:
                log('found switch @ %x, cases: %d' % (head, switch.get_jtable_size()))
                return (head, switch)

def run():
    # ....

    log('found opcode handler @ %x -> %x' % (func_ea, func_end_ea))

    # find switch
    head, switch = find_switch(func_ea)

    if switch == None:
        log('failed to find switch in opcode handler')
        return
    
    # get switch cases
    res = idaapi.calc_switch_cases(head, switch)

    for idx, case in enumerate(res.cases):
        log('case: %x' % res.targets[idx], 1)

        for cidx, opcode in enumerate(case):
            log('case: %x (%d)' % (opcode, opcode), 2)
```
With the above code, you'll get an output something like the following:

```
found opcode handler @ 140f6ece0 -> 140f72afc
found switch @ 140f6ed26, cases: 608
  case: 140f6ed28
    case: 7d (125)
  case: 140f6ed46
    case: ff (255)
  case: 140f6ed64
    case: 77 (119)
  ...
   case: 140f70322
     case: 1b5 (437)
     case: 1b6 (438)
     case: 1b7 (439)
     case: 1b8 (440)
     case: 1b9 (441)
     case: 1ba (442)
     case: 1bb (443)
     case: 1bc (444)
```

And if we go back to the original code that's here, we have the following:

```
loc_140F6ED28:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 125
                mov     rdx, rdi
                lea     ecx, [r8+8]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; ---------------------------------------------------------------------------

loc_140F6ED46:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 255
                mov     rdx, rdi
                lea     ecx, [r8+9]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
; ---------------------------------------------------------------------------

loc_140F6ED64:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                        ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o ...
                xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 119
                mov     rdx, rdi
                lea     ecx, [r8+7]
                mov     rbx, [rsp+58h+arg_0]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                jmp     net__somegenericweirdshit
```

:sunglasses:

Now we need to get the end EA of each block, which was a pain in the ass to figure out but ended up being really simple in the end:

```python
def find_block(ea, blocks):
    for block in blocks:
        if block.startEA == ea:
            return block

def run():
    ...

    # get switch cases
    res = idaapi.calc_switch_cases(head, switch)

    # get basic blocks
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))

    for idx, case in enumerate(res.cases):
        case_ea = res.targets[idx];

        block = find_block(case_ea, blocks)

        log('case: %x' % case_ea, 1)
        
        if block != None:
            # -1 to make it actually clickable in the output window and it goes to the right place
            log('end: %x, size: %x' % ((block.endEA - 1), block.endEA - case_ea), 2)

        for opcode in case:
            log('opcode: %x (%d)' % (opcode, opcode), 2)

```

Because each handler ends with an unconditional jump, IDA can construct blocks which represent each segment of the switch. We can use that information to get the start and end EA of each case. It's actually smarter than that and uses witchcraft and fuckery to deduce this so we don't have to, but in our case, most switch cases end with an unconditional jump -- usually to the actual packet handler. Either way, now we can use that information to iterate over each head for a specific switch case and follow any called functions for example.

There's one last thing we want to do here before we move on, and that's put all this info into a more usable data structure -- maybe something we can export and look at a bit easier. Realistically, you can do this in any way you'd want but here's what I've done:

```python
    case_infos = []

    for idx, case in enumerate(res.cases):
        case_ea = res.targets[idx];
        rel_ea = case_ea - func_ea

        case_info = {
            'start_ea': case_ea,
            'rel_ea': rel_ea
        }

        block = find_block(case_ea, blocks)
        
        if block != None:
            case_info['end_ea'] = block.endEA;
            case_info['size'] = block.endEA - case_ea

            # -1 to make it actually clickable in the output window and it goes to the right place
            #log('end: %x, size: %x' % ((block.endEA - 1), case_info['size']), 2)

        else:
            log('failed to get block for %x' % case_ea)
            continue

        case_info['opcodes'] = [int(oc) for oc in case]

        case_infos.append(case_info)

    log('got %d case info objs, switch blocks: %d' % (len(case_infos), len(res.cases)))
```

Most of what we're putting in there should have an obvious purpose, but `rel_ea` is likely the most useful thing here and it's pretty powerful just by itself. If we dump `case_infos` to JSON, we'll get something like this:

5.0:

```json
[
  {
    "rel_ea":72,
    "opcodes":[
      125
    ],
    "start_ea":5384891688,
    "end_ea":5384891718,
    "size":30
  },
  {
    "rel_ea":102,
    "opcodes":[
      255
    ],
    "start_ea":5384891718,
    "end_ea":5384891748,
    "size":30
  }
]
```

5.15:

```json
[
  {
    "rel_ea":72,
    "opcodes":[
      893
    ],
    "start_ea":5385527992,
    "end_ea":5385528023,
    "size":31
  },
  {
    "rel_ea":103,
    "opcodes":[
      945
    ],
    "start_ea":5385528023,
    "end_ea":5385528054,
    "size":31
  }
]
```

The two objects in the JSON dump match the assembly just above in both executables, near perfectly. The relative EA, or its offset from the start of the handler are identical and the size is nearly the same. We don't even do any complicated checks yet, but we can pretty accurately remap opcodes already. We'll try `PlayerSpawn` again, see if we can get similar results. `PlayerSpawn` is 0x17F in 5.0, so:

5.0:

```json
{
  "rel_ea":434,
  "opcodes":[
    383
  ],
  "start_ea":5384892050,
  "end_ea":5384892077,
  "size":27
}
```

5.15:

```json
{
  "rel_ea":434,
  "opcodes":[
    220
  ],
  "start_ea":5385528354,
  "end_ea":5385528381,
  "size":27
}
```

Unfortunately, this alone won't be enough as the further you go down the handler, the bigger changes there are in respect to relative addresses. As a naive demonstration, here's the last case in both executables:

5.0:

```json
{
  "rel_ea":13442,
  "opcodes":[
    726
  ],
  "start_ea":5384905058,
  "end_ea":5384905082,
  "size":24
}
```

5.15:

```json
{
  "rel_ea":13975,
  "opcodes":[
    408
  ],
  "start_ea":5385541895,
  "end_ea":5385541926,
  "size":31
}
```

Unlikely to be the same thing but decided to humour myself and go check, and it's not. So we'll need to continue on and collect more identifiable information about what's in each case. It's probably a good idea to get this information regardless as we can then decide with more confidence whether something is the same packet or a completely different one, but at least the relative EA allows you to start by searching nearby cases first instead of searching blindly.

#### Building Handler Trees

This shit is actually pretty cursed, so what I'm going to do is paste a heap of code and then make it slightly more digestible. I also don't want to spend more time on this because it hurts the soul and maybe with what we have, we might be able to get somewhere somewhat reliably.

```python
def ea_to_rva(ea):
    return ea - idaapi.get_imagebase()

def get_bytes_str(start_ea, end_ea):
    size = end_ea - start_ea

    bytes = []
    for ea in range(start_ea, end_ea):
        b = '{:02x}'.format(ida_bytes.get_byte(ea))
        bytes.append(b)

    return ' '.join(bytes)

def get_func_name(ea):
    name = ida_funcs.get_func_name(ea)
    demangled = ida_name.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))

    return demangled or name

def postprocess_func(fn, depth = 0):
    func = {
        'ea': fn.startEA,
        'rva': ea_to_rva(fn.startEA),
        'body': get_bytes_str(fn.startEA, fn.endEA)
    }

    # total aids
    switch_ea, switch = find_switch(fn.startEA)

    if switch and switch_ea != main_jumptable:
        sw = func['switch'] = {}

        res = idaapi.calc_switch_cases(switch_ea, switch)
        
        case_ids = []
        for case in res.cases:
            for i in case:
                case_ids.append(int(i))

        sw['cases'] = [i for i in set(case_ids)]

    else:
        func['switch'] = None

    return func

def process_func(func, start_ea, end_ea):
    for head in idautils.Heads(start_ea, end_ea):
        flags = idaapi.getFlags(head)
        if idaapi.isCode(flags):

            mnem = idc.GetMnem(head)

            if mnem == 'call' or mnem == 'jmp':
                op_ea = idc.GetOperandValue(head, 0)
                fn = ida_funcs.get_func(op_ea)

                if fn:
                    fn_info = postprocess_func(fn)

                    if fn_info:
                        func['xrefs'][get_func_name(op_ea)] = fn_info

def process_case(case, id):
    func = case['func'] = {}
    body = func['body'] = get_bytes_str(case['start_ea'], case['end_ea'])
    func['xrefs'] = {}

    process_func(func, case['start_ea'], case['end_ea'])



def run():
    # [same as before]

    # find switch
    head, switch = find_switch(func_ea)

    global main_jumptable
    main_jumptable = head

    # [also same as before]

    for k, v in enumerate(case_infos):
        process_case(v, k)
```

Don't say I didn't warn you. Anyway, `run()` is basically the same thing with a few minor changes.

* We store the EA of the jumptable inside `ZoneDownHandler` so we don't duplicate it in the event that we are inside a case that refers to itself. Mainly because its just more junk to output that we really don't need
* We loop over each `case_info` dictionary that we created before and do things...

... so we'll start from `process_case(...)` and go from there:

```python
def process_case(case, id):
    func = case['func'] = {}
    body = func['body'] = get_bytes_str(case['start_ea'], case['end_ea'])
    func['calls'] = {}

    process_func(func, case['start_ea'], case['end_ea'])
```

`process_case(...)` is pretty self explanatory, pretty much just sets up a dictionary and passes the ref through with the start and end EA of the segment of code we'll look at. We also get all the bytes of the case segment as a string, meaning this disassembly: 

```
loc_140F6ED28:                          ; CODE XREF: Client__Network__ZoneDownHandler+46↑j
                                         ; DATA XREF: Client__Network__ZoneDownHandler:jpt_140F6ED26↓o
                 xor     r8d, r8d        ; jumptable 0000000140F6ED26 case 125
                 mov     rdx, rdi
                 lea     ecx, [r8+8]
                 mov     rbx, [rsp+58h+arg_0]
                 mov     rsi, [rsp+58h+arg_10]
                 add     rsp, 50h
                 pop     rdi
                 jmp     net__somegenericweirdshit
```

Becomes this in the output:

```json
"body":"45 33 c0 48 8b d7 41 8d 48 08 48 8b 5c 24 60 48 8b 74 24 70 48 83 c4 50 5f e9 7a 40 00 00"
```

Nothing too complex, but there's a possible 'improvement' with this. Currently all references to data and so on is preserved as is, so in the event of the executable being rebuilt, it's very likely that some of the bytes in here will change. What's probably a good idea to do is to replace references to data and code with wildcards, so we know that during the processing step wildcards can be completely ignored and subsequently if then any of the remaining bytes change, there's either a code change or it's not the same thing. But we can cross that bridge later.

Moving on...

```python
def process_func(func, start_ea, end_ea):
    for head in idautils.Heads(start_ea, end_ea):
        flags = idaapi.getFlags(head)
        if idaapi.isCode(flags):

            mnem = idc.GetMnem(head)

            if mnem == 'call' or mnem == 'jmp':
                op_ea = idc.GetOperandValue(head, 0)
                fn = ida_funcs.get_func(op_ea)

                if fn:
                    fn_info = postprocess_func(fn)

                    if fn_info:
                        func['calls'][get_func_name(op_ea)] = fn_info
```

This is where it starts getting fucked. So, again, this is how it goes:

1. Loop over every instruction in the range `start_ea ... end_ea`
2. Check if it's actually code, though the check is probably redundant in this case and I think something I left in from before, its all a blur now
3. Get the mnemonic by name and check if it's a `call` or `jmp` instruction
4. If it is, we get the first operand value, or the instructions parameter -- in this case it should be the EA of a function
5. Call `get_func` on it and check if it actually is a function -- it returns `None` if its not
6. Do more shit with that function (see below)
7. Store the result in the dictionary keyed by the function name

Not totally indigestible, but it's pretty gnarly. So lets make it even worse and check out `postprocess_func`!

```python
def postprocess_func(fn, depth = 0):
    func = {
        'ea': fn.startEA,
        'rva': ea_to_rva(fn.startEA),
        'body': get_bytes_str(fn.startEA, fn.endEA)
    }

    # total aids
    switch_ea, switch = find_switch(fn.startEA)

    if switch and switch_ea != main_jumptable:
        sw = func['switch'] = {}

        res = idaapi.calc_switch_cases(switch_ea, switch)
        
        case_ids = []
        for case in res.cases:
            for i in case:
                case_ids.append(int(i))

        sw['cases'] = [i for i in set(case_ids)]

    else:
        func['switch'] = None

    return func
```

There's not anything 'new' here but it's pretty gross nonetheless. For the most part though, this is simply an isolated function where we can do everything later without being trapped in 60 layers of indentation. Check if we have a switch in the function, if we do, grab some info about it and then attach it to the `func` dictionary.

Something we could do here is grab the bytes of each case in the nested switches, so we can then distinguish nested switches at the same time but we'll come back to this later. I don't want to be battling this stupid shit without the easier stuff working properly first.

#### I Can't Believe That Writing JSON to the Clipboard Deserves It's Own Section

Now we'll export all this garbage and throw it into the clipboard so you can do things with it. Luckily this is actually pretty easy:

```python
from PyQt5.Qt import QApplication

def set_clipboard(data):
    QApplication.clipboard().setText(data)

def set_clipboard_json(data):
    set_clipboard(json.dumps(data, indent=2, separators=(',', ':')))
    log('copied parsed data to clipboard')
```

[Wow](https://www.youtube.com/watch?v=TRIwAHX3aHM). At the end of `run()`, just insert `set_clipboard_json(output)` and away you go. You'll get something like this, or maybe better if you're less retarded than I am:

```json
{
  "rva":16182568,
  "func":{
    "body":"45 33 c0 48 8b d7 41 8d 48 08 48 8b 5c 24 60 48 8b 74 24 70 48 83 c4 50 5f e9 7a 40 00 00",
    "calls":{
      "net::somegenericweirdshit":{
        "body":"48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 8b f1 41 8b d8 48 8b 0d 4d 87 b9 00 48 8b fa e8 8d ce 11 ff 48 85 c0 74 15 4c 8b 10 4c 8b cf 44 8b c3 8b d6 48 8b c8 41 ff 92 90 02 00 00 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f c3",
        "rva":16199104,
        "ea":5384908224,
        "switch":null
      }
    }
  },
  "rel_ea":72,
  "opcodes":[
    125
  ],
  "start_ea":5384891688,
  "end_ea":5384891718,
  "size":30
}
```

And just to compare, here's the 5.15 equivalent:

```json
{
  "rva":16818872,
  "func":{
    "body":"b9 08 00 00 00 48 8b d7 45 33 c0 48 8b 5c 24 60 48 8b 74 24 70 48 83 c4 50 5f e9 39 47 00 00",
    "calls":{
      "sub_14100EA10":{
        "body":"48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 8b f1 41 8b d8 48 8b 0d 7d 3c bd 00 48 8b fa e8 ed 16 08 ff 48 85 c0 74 15 4c 8b 10 4c 8b cf 44 8b c3 8b d6 48 8b c8 41 ff 92 a0 02 00 00 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f c3",
        "rva":16837136,
        "ea":5385546256,
        "switch":null
      }
    }
  },
  "rel_ea":72,
  "opcodes":[
    893
  ],
  "start_ea":5385527992,
  "end_ea":5385528023,
  "size":31
}
```

As mentioned already, there's a few ways this can be improved but for now this should work as a proof of concept.