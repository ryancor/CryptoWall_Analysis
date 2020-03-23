from qiling import *

# Have a lot more to add here
# Just testing the hooking technique

def killerswitch(uc, address, size, ql):
	if address == 0x004108A2:
		print("\n---\nCryptoWall Unpacked Address Found, Emulation Stop\n---\n")
		ql.uc.emu_stop()

if __name__ == "__main__":
	ql = Qiling(["/home/ryancor/Desktop/SandBoxMalware/cryptowall/bin/cryptowall.exe"], "/home/ryancor/Desktop/SandBoxMalware/cryptowall", output = "debug")
	ql.hook_code(killerswitch, ql)
	ql.run()
