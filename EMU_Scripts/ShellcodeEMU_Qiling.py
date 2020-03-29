from qiling import *
from qiling.exception import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *


X86_WIN = unhexlify(
    'fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300'
    )


def ReturnShellcodeBytes(filename):
	f = open(filename, 'rb')
	shellcode = f.read()
	f.close()
	return shellcode


def test_windowssc_x86(filename):
    ql = Qiling(shellcoder=ReturnShellcodeBytes(filename), archtype="x86",
                ostype="windows",
                rootfs="/home/rootfs", # directory to Windows/SYSWoW64 dir
                output="default")
    ql.run()
    del ql
