# CRACKER-UAE (fù FS-UAE) by ZorroDJ

Hi Guys, welcome to this fork of FS-UAE, with some addictions for the **modern & brave Amiga cracker**, optimized for Linux:

## Flexi-debugger ##

### Local TCP command interface ###
- Opt-in server bound to 127.0.0.1, with a configurable port.
- Enabled through --debug_server=1 --debug_server_port=23456, or equivalent environment variables.
- Line-based protocol with OK/ERR replies and a . response terminator.
- Python client: tools/cracker-uae-debug.py.
### Remote commands ###
- ping, help, frames
- regs — CPU register dump
- mem <hex-address> <length> — guest memory hex dump
- floppy <path> - insert an image into DF0
- reset, quit
- screenshot [path] - capture the emulator’s post-planar-conversion RGB framebuffer, directly to PNG.
We also fixed screenshot handling to respect the framebuffer’s actual row stride, eliminating distorted captures.
- the original debugger interface can be invoked in that way (enjoy a bit of italian!):
```
debug h          → help originale dei comandi disponibili
debug T          → task list
debug K          → stato libtrace
debug t          → single-step
debug f ADDRESS  → breakpoint
debug g          → riprende l’esecuzione
debug x          → esce dal debugger e riprende
debug status     → stato running/halted, senza interrompere
debug detach     → rilascia il controllo remoto
```

## Libtrace++ (Libtrace port to FS-UAE 5) ##
[libtrace](https://lallafa.de/blog/2016/09/libtrace-a-library-function-tracer-for-fs-uae/) by lallafa with fixes & extensions. Now you can easily trace also BCPL system calls from Kickstart 1.x (backend LVO non-JMP and BCPL calls profiles)! **Please don't enable JIT for best results!**, es: set CRACKER_UAE_LIBTRACE=1 on shell, like:
```
libtrace config /path/to/profile.cfg
libtrace output /path/to/calls.log
libtrace task Initial CLI
libtrace enable 1
reset
```

### Original features ###
- Ported the original libtrace and FD metadata parser.
- Fixed resident activation by lowering its priority below Expansion.
- Debugger commands: K, Ke, Kc, Kt, Ko; K replaces the original L prefix because L already means “load memory.”
###  TCP controls: ###
libtrace config <path>
libtrace output <path>
libtrace task <name>
libtrace enable <0|1>
- Configuration changes are queued on the emulation thread; installation occurs on reset.
###  DOS 1.x and native BCPL tracing ###
- Added a read-only instruction observer for non-JMP DOS library vectors.
- Added native BCPL SAVE/RET observation using the live global vector and BCPL frame.
- Captures public DOS results in D0, native BCPL results in D1, and bounded, escaped BSTR previews.
- Initial BCPL signatures: writes, writef, wrch, writen, newline, rdch, readn, input, output.
###  Validation ###
- Added tools/libtrace-smoke.py for tracing, filtering, reset and re-enable tests.
- Verified on Workbench 1.2 / Kickstart 1.3, including the original BCPL Echo and a mixed C/BCPL probe.
- The new instruction-observer backend currently supports the 68000 interpreter without JIT.

# WHY

1) Because it's fun
2) To make a world-first: writing a [VBCC](http://www.compilers.de/vbcc.html) backed to skip C runtime and use BCPL from C in Kickstart 1.x to make CLI commands smaller
3) To trace/investigate/crack anything with ease

Check [od-fs/README.md](od-fs/README.md) for plain old FS-UAE README file.

# WHOAMI

You know who I'm. I'm a fine software engineer from Italy, you know.
