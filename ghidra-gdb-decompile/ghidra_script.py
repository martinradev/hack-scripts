from ghidra.app.decompiler import DecompInterface
import socket
import struct

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def rd(sock, n):
    data = b""
    rem = n
    while rem > 0:
        data = sock.recv(rem)
        rem = rem - len(data)
    return data

def wr(sock, data):
    sz = len(data)
    i = 0
    while i < sz:
        s = sock.send(data[i:])
        i = i + s

fm = currentProgram.getFunctionManager()
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(("localhost", 14444))
serversocket.listen(1)

while True:
    try:
        (sock, address) = serversocket.accept()
        while True:
            addr_req = rd(sock, 8)
            fixed_addr = struct.unpack("<Q", addr_req)[0]
            addr_obj = getAddress(fixed_addr)
            func = fm.getFunctionContaining(addr_obj)
            status = decompiler.decompileFunction(func, 0, None)
            if status != None and status.getDecompiledFunction():
                c_code = status.getDecompiledFunction().getC()
                wr(sock, struct.pack("<I", (len(c_code))))
                wr(sock, c_code.encode("ascii"))
    except:
        print("Ok, connection died I guess")
    
