# Download x64Dbg plugins -> extract all plugins files to <arch> dir
# Make sure >python2.11 is in your PATH
from x64dbgpy.pluginsdk import *
import sys

debug.Run()

cip = register.GetCIP()
if cip == 0x00403487:
    gui.Message("Found main: %s" % hex(cip))

debug.SetBreakpoint(0x00402dda)
debug.Run()
debug.StepIn()
debug.StepIn()
cip = register.GetCIP()
if cip == 0x0302C940:
    gui.Message("Found 2nd stage loader: %s" % hex(cip))

debug.SetBreakpoint(0x0302CA57)
debug.Run()
debug.StepIn()
cip = register.GetCIP()
if cip == 0x001912A6:
    gui.Message("Found 3rd stage loader: %s" % hex(cip))

debug.SetBreakpoint(0x00191446)
debug.StepOver()
debug.Run()
x64dbg.DbgCmdExecDirect("eax = 0xc0")
comment.Set(0, "Patched anti-vm check")

x64dbg.DbgCmdExecDirect("bp VirtualAlloc")
x64dbg.DbgCmdExecDirect("bp WriteProcessMemory")

debug.Run() # First hit on VirtualAlloc

# Get past access violations
for i in range(17):
    debug.Run()

debug.Run() # VirtualAlloc 2nd time
debug.Run() # First hit on WriteProcessMemory
debug.Run() # Second hit on WriteProcessMemory

ecx = register.GetECX()
if  memory.ReadWord(ecx) == 0x4D5A:
    gui.Message("Found Hidden PE File")

x64dbg.DbgCmdExecDirect("savedata cryptowall_dump.exe, ecx, 0x00021000")
gui.Message("Dumped PE File")
