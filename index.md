## Behemoth0

This one is quite simple. I will show a several methods to get the code:
# using _gdb_
1) Fire up gdb
2) Disassemble main
3) Find compare command and check the value being compared to our pass
```
behemoth0@behemoth:/behemoth$ gdb behemoth0 
GNU gdb (Debian 7.12-6) 7.12.0.20161007-git
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from behemoth0...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x080485b1 <+0>:	push   %ebp
   0x080485b2 <+1>:	mov    %esp,%ebp
   0x080485b4 <+3>:	push   %ebx
   0x080485b5 <+4>:	sub    $0x5c,%esp
   0x080485b8 <+7>:	movl   $0x475e4b4f,-0x1c(%ebp)
   0x080485bf <+14>:	movl   $0x45425953,-0x18(%ebp)
   0x080485c6 <+21>:	movl   $0x595e58,-0x14(%ebp)
   0x080485cd <+28>:	movl   $0x8048700,-0x8(%ebp)
   0x080485d4 <+35>:	movl   $0x8048718,-0xc(%ebp)
   0x080485db <+42>:	movl   $0x804872d,-0x10(%ebp)
   0x080485e2 <+49>:	push   $0x8048741
   0x080485e7 <+54>:	call   0x8048400 <printf@plt>             ;prints 'password: '. Can be checked with x/s 0x8048741,
                                                                 which is the address of the string being pushed to printf
   0x080485ec <+59>:	add    $0x4,%esp
   0x080485ef <+62>:	lea    -0x5d(%ebp),%eax                   ;our input will be storned in -0x5d(%ebp)
   0x080485f2 <+65>:	push   %eax
   0x080485f3 <+66>:	push   $0x804874c
   0x080485f8 <+71>:	call   0x8048470 <__isoc99_scanf@plt>     ;receives our input
   0x080485fd <+76>:	add    $0x8,%esp
   0x08048600 <+79>:	lea    -0x1c(%ebp),%eax
   0x08048603 <+82>:	push   %eax
   0x08048604 <+83>:	call   0x8048450 <strlen@plt>
   0x08048609 <+88>:	add    $0x4,%esp
   0x0804860c <+91>:	push   %eax
   0x0804860d <+92>:	lea    -0x1c(%ebp),%eax
   0x08048610 <+95>:	push   %eax
   0x08048611 <+96>:	call   0x804858b <memfrob>
---Type <return> to continue, or q <return> to quit---
   0x08048616 <+101>:	add    $0x8,%esp
   0x08048619 <+104>:	lea    -0x1c(%ebp),%eax                   ;the real password to be compared, we want to print $eax value
                                                                 here
   0x0804861c <+107>:	push   %eax
   0x0804861d <+108>:	lea    -0x5d(%ebp),%eax                   ;our input
   0x08048620 <+111>:	push   %eax
   0x08048621 <+112>:	call   0x80483f0 <strcmp@plt>
   0x08048626 <+117>:	add    $0x8,%esp
   0x08048629 <+120>:	test   %eax,%eax
   0x0804862b <+122>:	jne    0x804865f <main+174>
   0x0804862d <+124>:	push   $0x8048751
   0x08048632 <+129>:	call   0x8048420 <puts@plt>
   0x08048637 <+134>:	add    $0x4,%esp
   0x0804863a <+137>:	call   0x8048410 <geteuid@plt>
   0x0804863f <+142>:	mov    %eax,%ebx
   0x08048641 <+144>:	call   0x8048410 <geteuid@plt>
   0x08048646 <+149>:	push   %ebx
   0x08048647 <+150>:	push   %eax
   0x08048648 <+151>:	call   0x8048440 <setreuid@plt>
   0x0804864d <+156>:	add    $0x8,%esp
   0x08048650 <+159>:	push   $0x8048762
   0x08048655 <+164>:	call   0x8048430 <system@plt>
   0x0804865a <+169>:	add    $0x4,%esp
   0x0804865d <+172>:	jmp    0x804866c <main+187>
   0x0804865f <+174>:	push   $0x804876a
   0x08048664 <+179>:	call   0x8048420 <puts@plt>
   0x08048669 <+184>:	add    $0x4,%esp
   0x0804866c <+187>:	mov    $0x0,%eax
---Type <return> to continue, or q <return> to quit---
   0x08048671 <+192>:	mov    -0x4(%ebp),%ebx
   0x08048674 <+195>:	leave  
   0x08048675 <+196>:	ret    
End of assembler dump.
```
let's break at x08048619:
```(gdb) b *0x08048619 ```
step to the next command so eax will be loaded with the real pass:
```
(gdb) ni
```
okay now eax should contain the string:
```
(gdb) x/s $eax
0xbffff69c:	"eatmyshorts"
```
wallah.

# next method - using ltrace
ltrace and strace are very useful tools for analysing function calls. ltrace traces all internal function that were called
during the run of our program:
```
behemoth0@behemoth:/behemoth$ ltrace ./behemoth0 
__libc_start_main(0x80485b1, 1, 0xbffff774, 0x8048680 <unfinished ...>
printf("Password: ")                                                     = 10
__isoc99_scanf(0x804874c, 0xbffff67b, 0xb7fc8000, 13Password: NOTTHEPASS
)                    = 1
strlen("OK^GSYBEX^Y")                                                    = 11
strcmp("NOTTHEPASS", "eatmyshorts")                                      = -1
puts("Access denied.."Access denied..
)                                                  = 16
+++ exited (status 0) +++
```
As we can see, strcmp was called and compared our value 'NOTTHEPASS' with 'eatmyshorts'. Wallah.

# sometimes, it even possible to use 'strings' in order to print all prinitable charaters in our program. here it won't be useful:
```
behemoth0@behemoth:/behemoth$ strings behemoth0
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
memfrob
__isoc99_scanf
puts
setreuid
printf
strlen
system
geteuid
strcmp
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.0
PTRh
OK^G
SYBE
u2hQ
UWVS
t$,U
[^_]
unixisbetterthanwindows
followthewhiterabbit
pacmanishighoncrack
Password: 
%64s
Access granted..
/bin/sh
Access denied..
;*2$"
GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.6587
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
behemoth0.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strcmp@@GLIBC_2.0
__x86.get_pc_thunk.bx
printf@@GLIBC_2.0
_edata
geteuid@@GLIBC_2.0
__data_start
puts@@GLIBC_2.0
system@@GLIBC_2.0
__gmon_start__
__dso_handle
_IO_stdin_used
setreuid@@GLIBC_2.0
strlen@@GLIBC_2.0
__libc_start_main@@GLIBC_2.0
__libc_csu_init
_fp_hw
__bss_start
main
__isoc99_scanf@@GLIBC_2.7
memfrob
__TMC_END__
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment
```
'eatmyshorts' does appear, but without analysing the program itself, it will be a bit tedious job. but still possible.

There are planty of another ways, but we will finish here. Ahead to the next one:
```
behemoth0@behemoth:/behemoth$ ./behemoth0 eatmyshorts
Password: eatmyshorts
Access granted..
$ cat /etc/behemoth_pass/behemoth1
...
```




You can use the [editor on GitHub](https://github.com/int3rsys/behemoth-solutions/edit/master/README.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/int3rsys/behemoth-solutions/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
