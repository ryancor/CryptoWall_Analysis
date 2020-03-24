# py -m pip install r2pipe
# download radare2, and put it in your PATH
import r2pipe
import json

r = r2pipe.open(
    filename="cryptowall.bin", flags=['-b 32']
)

def get_eip():
    return json.loads(r.cmd('drj'))['rip']

r.cmd('aaaa')
r.cmd('e asm.bits=32')
r.cmd('doo')
r.cmd('db main')
r.cmd('doo')
r.cmd('dc')
r.cmd('dc')
r.cmd('dc') # should be in main now
print('Current addr: ' + hex(get_eip()))

r.cmd('db 0x00402dda') # breakpoint at the end of push eax
r.cmd('dc')
print(r.cmd('ds 2')) # step into eax
print(r.cmd('pd 10')) # now we are inside the stage 2 of unpacking

VirtualAlloc = r.cmd('? [sym.imp.KERNEL32.dll_VirtualAlloc]')
print('VirtualAlloc is at: ' + VirtualAlloc)
r.cmd('db [sym.imp.KERNEL32.dll_VirtualAlloc]')
print('Current addr: ' + hex(get_eip()))
r.cmd('dc')
print('Current after stepping into VirtualAlloc: ' + hex(get_eip()))
