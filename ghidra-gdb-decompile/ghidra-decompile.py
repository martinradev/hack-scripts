import gdb
import struct
import socket

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

class DecompileMe(gdb.Command):
	def __init__(self):
		super(DecompileMe, self).__init__("deghi", gdb.COMMAND_DATA)
		self.init_socket()

	def init_socket(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect(("localhost", 14444))
		self.sock = sock
		print("init")

	def invoke(self, arg, from_tty):
		addr = struct.pack("<Q", int(arg, 16))
		wr(self.sock, addr)
		l = struct.unpack("<I", rd(self.sock, 4))[0]
		src = rd(self.sock, l)
		print(src.decode("ascii"))
	

DecompileMe()
