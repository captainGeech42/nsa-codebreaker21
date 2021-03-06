#!/usr/bin/env python3

import binascii
import hashlib
import io
import string
import uuid
from multiprocessing import Pool

import nacl.exceptions
import nacl.secret
from scapy.all import *

# From here https://pen-testing.sans.org/blog/2017/10/13/scapy-full-duplex-stream-reassembly
def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport],key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport] ,key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id] ,key=str)) 
            else:
                sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto] ,key=str)) 
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst],key=str)) 
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess

def get_length(data):
    assert(len(data) == 4)
    random_bytes, encoded_len = struct.unpack(">HH", data)
    body_length = encoded_len + random_bytes - 0x10000
    return body_length

def decrypt_pkt_with_session_key(pkt, key):
    data = pkt[Raw].load

    length = get_length(data[:4])
    nonce = data[4:0x18+4]
    enc_data = data[0x18+4:]

    assert(len(data) == length + 4)

    box = nacl.secret.SecretBox(key)

    ptxt = box.decrypt(enc_data, nonce=nonce)

    return ptxt

def generate_session_key(u, v, ts):
    data = f"{u}+{v}+{ts}".encode()
    return hashlib.sha256(data).digest()

def test_session_key(pkt, key):
    magic_start = b"\x16\x16\xbf\x7d"

    try:
        dec = decrypt_pkt_with_session_key(pkt, key)
        if dec[:4] == magic_start or dec[:4] == magic_start[::-1]:
            return True
    except nacl.exceptions.CryptoError:
        return False

    print(f"no error but not magic, key = {binascii.hexlify(key).decode()}")
    return False


x = lambda d: binascii.hexlify(d).decode()

def parse_packet(data):
    # this code is literal garbage

    MAGIC_START = b"\x16\x16\xbf\x7d"
    MAGIC_END = b"\xef\x3b\x1b\xbf"

    COMMAND_INIT = b"\x00\x02"
    COMMAND_UPLOAD = b"\x00\x06"
    COMMAND_FIN = b"\x00\x07"

    PARAM_CMD = b"\x69\x00"
    PARAM_UUID = b"\x69\x08"
    PARAM_DIRNAME = b"\x69\x14"
    PARAM_FILENAME = b"\x69\x1c"
    PARAM_CONTENTS = b"\x69\x20"
    PARAM_MORE = b"\x69\x24"
    PARAM_CODE = b"\x69\x28"

    RESPONSE_CODE_LENGTH = 4

    # below are from protocol analysis
    # PARAM_CONTENTS is used for server response, "RUN: [cmd]\n" or "EXEC: [cmd]\n"
    COMMAND_GET_TASKING_PATH = b"\x00\x03" # send some data back including /tmp/endpoints/{uuid}/tasking\x00 sus (PARAM_DIRNAME response)
    COMMAND_GET_TASK_ID = b"\x00\x04" # sends the tasking path (6918 response)
    COMMAND_GET_TASK = b"\x00\x05" # sends the tasking path and the task id

    PARAM_TASK_ID = b"\x69\x18"

    stream = io.BytesIO(data)

    # packets might just be a list of PARAMs, encapculated in MAGICs
    # too lazy to do that rn

    assert(stream.read(4) == MAGIC_START)

    param = stream.read(2)
    if param == PARAM_CMD:
        cmd_length = struct.unpack(">H", stream.read(2))[0]
        command = stream.read(cmd_length)
        if command == COMMAND_INIT:
            print("COMMAND_INIT")
            param2 = stream.read(2)
            if param2 != PARAM_UUID:
                print(f"wrong param in COMMAND_INIT (should be UUID): {x(param2)}")
                return
            uuid_len = struct.unpack(">H", stream.read(2))[0]
            uuid = stream.read(uuid_len)
            print(f"uuid = {UUID(bytes=uuid)}")
        elif command == COMMAND_UPLOAD:
            print("COMMAND_UPLOAD")
            param2 = stream.read(2)
            if param2 != PARAM_UUID:
                print(f"wrong param in COMMAND_UPLOAD (should be UUID): {x(param2)}")
                return
            uuid_len = struct.unpack(">H", stream.read(2))[0]
            uuid = stream.read(uuid_len)
            print(f"uuid = {UUID(bytes=uuid)}")
            
            param2 = stream.read(2)
            if param2 != PARAM_DIRNAME:
                print(f"wrong param in COMMAND_UPLOAD (should be DIRNAME): {x(param2)}")
                return
            dirname_len = struct.unpack(">H", stream.read(2))[0]
            dirname = stream.read(dirname_len).decode()
            print(f"dirname = \"{dirname}\"")

            param2 = stream.read(2)
            if param2 != PARAM_FILENAME:
                print(f"wrong param in COMMAND_UPLOAD (should be FILENAME): {x(param2)}")
                return
            filename_len = struct.unpack(">H", stream.read(2))[0]
            filename = stream.read(filename_len).decode()
            print(f"filename = \"{filename}\"")
            
            param2 = stream.read(2)
            if param2 != PARAM_CONTENTS:
                print(f"wrong param in COMMAND_UPLOAD (should be CONTENTS): {x(param2)}")
                return
            contents_len = struct.unpack(">H", stream.read(2))[0]
            contents = stream.read(contents_len).decode()

            if contents_len > 100:
                contents = contents[:100] + "<truncated ...>"
            print(f"contents = \"{contents}\" (len: {contents_len})")

            param2 = stream.read(2)
            if param2 != PARAM_MORE:
                print(f"wrong param in COMMAND_UPLOAD (should be MORE): {x(param2)}")
                return
            more_len = struct.unpack(">H", stream.read(2))[0]
            more = stream.read(more_len)
            print(f"more = {x(more)}")
        elif command == COMMAND_FIN:
            print("fin")
        elif command == COMMAND_GET_TASKING_PATH:
            print("COMMAND_GET_TASKING_PATH")
            param2 = stream.read(2)
            if param2 != PARAM_UUID:
                print(f"wrong param in COMMAND_GET_TASKING_PATH (should be UUID): {x(param2)}")
                return
            uuid_len = struct.unpack(">H", stream.read(2))[0]
            uuid = stream.read(uuid_len)
            print(f"uuid = {UUID(bytes=uuid)}")
        elif command == COMMAND_GET_TASK_ID:
            print("COMMAND_GET_TASK_ID")
            param2 = stream.read(2)
            if param2 != PARAM_UUID:
                print(f"wrong param in COMMAND_GET_TASK_ID (should be UUID): {x(param2)}")
                return
            uuid_len = struct.unpack(">H", stream.read(2))[0]
            uuid = stream.read(uuid_len)
            print(f"uuid = {UUID(bytes=uuid)}")

            param2 = stream.read(2)
            if param2 != PARAM_DIRNAME:
                print(f"wrong param in COMMAND_GET_TASK_ID (should be DIRNAME): {x(param2)}")
                return
            dirname_len = struct.unpack(">H", stream.read(2))[0]
            dirname = stream.read(dirname_len).decode()
            print(f"dirname = \"{dirname}\"")
        elif command == COMMAND_GET_TASK:
            print("COMMAND_GET_TASK")
            param2 = stream.read(2)
            if param2 != PARAM_UUID:
                print(f"wrong param in COMMAND_GET_TASK (should be UUID): {x(param2)}")
                return
            uuid_len = struct.unpack(">H", stream.read(2))[0]
            uuid = stream.read(uuid_len)
            print(f"uuid = {UUID(bytes=uuid)}")

            param2 = stream.read(2)
            if param2 != PARAM_DIRNAME:
                print(f"wrong param in COMMAND_GET_TASK (should be DIRNAME): {x(param2)}")
                return
            dirname_len = struct.unpack(">H", stream.read(2))[0]
            dirname = stream.read(dirname_len).decode()
            print(f"dirname = \"{dirname}\"")

            param2 = stream.read(2)
            if param2 != PARAM_FILENAME:
                print(f"wrong param in COMMAND_GET_TASK (should be FILENAME): {x(param2)}")
                return
            filename_len = struct.unpack(">H", stream.read(2))[0]
            filename = stream.read(filename_len).decode()
            print(f"filename = \"{filename}\"")
        else:
            print(f"unknown command: {x(command)}")
            print(data)
            return
    elif param == PARAM_CODE:
        print("PARAM_CODE")
        code_length = struct.unpack(">H", stream.read(2))[0]
        if code_length != RESPONSE_CODE_LENGTH:
            print(f"bad response code length: {code_length}")
            return
        
        code = struct.unpack("<I", stream.read(code_length))[0] # might need to be >I, not sure
        print(f"response code: {code}")
    elif param == PARAM_CONTENTS:
        print("PARAM_CONTENTS")
        cmd_length = struct.unpack(">H", stream.read(2))[0]
        cmd = stream.read(cmd_length)
        print(f"cmd str from server: {cmd}")
    elif param == PARAM_DIRNAME:
        print("PARAM_DIRNAME")
        dirname_len = struct.unpack(">H", stream.read(2))[0]
        dirname = stream.read(dirname_len).decode()
        print(f"dirname = \"{dirname}\"")
    elif param == PARAM_TASK_ID:
        print("PARAM_TASK_ID")
        id_len = struct.unpack(">H", stream.read(2))[0]
        id = stream.read(id_len).decode()
        print(f"task id = \"{id}\"")

        # this is especially stupid, but keeps with the theme
        try:
            # print("extra")
            stream.read(2)
            id_len = struct.unpack(">H", stream.read(2))[0]
            # print(id_len)
            id = stream.read(id_len).decode()
            # print(id)
            print(f"task id = \"{id}\"")

            return
        except:
            pass
    else:
        print(f"unhandled param: {x(param)}")
        print(data)
        return
    
    end = stream.read(4)
    if end != MAGIC_END:
        print(f"extra data left in packet: {x(end + stream.read())}")    

def analyze_session(packets, session_key):
    session_key = binascii.unhexlify(session_key)

    if packets[0][TCP].sport != 6666 and packets[0][TCP].dport != 6666:
        return

    data_packets = []
    victim_ip = packets[0][IP].src

    for p in packets:
        if Raw in p:
            data_packets.append(p)
    
    print(f"analyzing session from {packets[0][IP].src} ({len(packets)} packets, {len(data_packets)} with data)")

    client_pubkey = data_packets[0][Raw].load
    print("client pubkey: " + binascii.hexlify(client_pubkey).decode())

    length_bytes = data_packets[1][Raw].load[:4]
    body_length = get_length(length_bytes)

    nonce = data_packets[1][Raw].load[4:0x18+4]
    ciphertext = data_packets[1][Raw].load[0x18+4:]
    assert(len(ciphertext+nonce) == body_length)

    for p in data_packets[2:]:
        print(f"=== {p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport} ({len(p[Raw].load)} bytes)")

        dec_data = decrypt_pkt_with_session_key(p, session_key)
        parse_packet(dec_data)
        print()

        # length header + nonce + ciphertext
        if p[TCP].dport == 6666:
            # client->server packet
            pass
        else:
            # server->client packet
            pass

def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} [path to pcap] [session key]")
        return 1

    pcap = rdpcap(argv[1])
    sessions = pcap.sessions(full_duplex)

    for s in sessions.values():
        analyze_session(s, argv[2])

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))