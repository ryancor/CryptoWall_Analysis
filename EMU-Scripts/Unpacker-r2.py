# py -m pip install r2pipe
# download radare2, and put it in your PATH
import r2pipe
import json

r = r2pipe.open(
    filename="cryptowall.bin"
)

def get_eip():
    return json.loads(r.cmd('drj'))['rip']

r.cmd('aaaa')
r.cmd('doo')
r.cmd('db main')
r.cmd('doo')
r.cmd('dc')
r.cmd('dc')
r.cmd('dc') # should be in main now
print('Found main: ' + hex(get_eip()))

r.cmd('db 0x00402dda') # breakpoint at the end of push eax
r.cmd('dc')
r.cmd('ds 2') # step into eax
print('Found Second stage loader: ' + hex(get_eip()))
print(r.cmd('pd 10')) # now we are inside the stage 2 of unpacking

print("Hold your horses... this may take awhile")
r.cmd('dsu 0x0302CA57')
print('Inside Second stage loaders call to EAX: ' + hex(get_eip()))
r.cmd('ds 1') #step into EAX
print('Inside Third stage loader: ' + hex(get_eip()))
r.cmd('dsu 0x00191446')
r.cmd('dr al=0xC0')
r.cmd('ds 2')
print('Patched Third stage loader debugger check: ' + hex(get_eip()))

VirtualAlloc = r.cmd('? [sym.imp.KERNEL32.dll_VirtualAlloc]')
print('\nVirtualAlloc is at: ' + VirtualAlloc)

r.cmd('db [sym.imp.KERNEL32.dll_VirtualAlloc]')
r.cmd('dc')
print('Inside VirtualAlloc Part I: ' + hex(get_eip()))
# try stepping out of VA and see if you hit the 0055 addresses
r.cmd('ds 4')
r.cmd('db [sym.imp.KERNEL32.dll_VirtualAlloc]')
r.cmd('dsu [sym.imp.KERNEL32.dll_VirtualAlloc]')
print('Inside VirtualAlloc Part II: ' + hex(get_eip()))
r.cmd('ds 4')

r.cmd('db [sym.imp.KERNEL32.dll_WriteProcessMemory]')
r.cmd('dc')
print('Inside WriteProcessMemory Part I: ' + hex(get_eip()))
r.cmd('ds 4')
r.cmd('db [sym.imp.KERNEL32.dll_WriteProcessMemory]')
r.cmd('dc')
print('Inside WriteProcessMemory Part II: ' + hex(get_eip()))

print("\nFound dumped PE:")
print(r.cmd('px @ rcx'))
