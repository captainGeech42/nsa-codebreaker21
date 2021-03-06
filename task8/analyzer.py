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

def brute_force_session_key(pkt):

    def _gen_version_short():
        for item in itertools.product(string.digits, repeat=4):
            yield ".".join(item)

    # possible_usernames = ["unknown", "dockerbot", "builder04", "landerbot", "builder05", "tester_10"]
    # possible_usernames = ["unknown", "dockerbot", "landerbot", "root", "user"]
    # with open("usernames", "r") as f:
    #     possible_usernames.extend([x.strip() for x in f.readlines()])

    # with open("just_names", "r") as f:
    #     names = [x.strip().lower() for x in f.readlines()]

    # names=["Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"]
    # names.extend([f"OOPS-WORKSTATION_{x}$" for x in range(1,11)])
    # names.append("OOPS-RESERVED$")

    possible_usernames = []
    # possible_usernames.extend(["NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\LOCAL SERVICE"])
    # for n in names:
    #     possible_usernames.append(n)
    #     possible_usernames.append(n + "@OOPS.NET")
    #     possible_usernames.append("OOPS\\" + n)
    #     possible_usernames.append("OOPS.NET\\" + n)
    #     possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #     possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")

        # try:
        #     a = n.split(".")
        #     possible_usernames.append(a[0])
        #     possible_usernames.append(a[1])
            
    #         n = a[1] + "." + a[0] # asdf.zxcv -> zxcv.asdf
    #         possible_usernames.append(n + "@OOPS.NET")
    #         possible_usernames.append("OOPS\\" + n)
    #         possible_usernames.append("OOPS.NET\\" + n)
    #         possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #         possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")

    #         n = a[0][0] + "." + a[1] # asdf.zxcv -> a.zxcv
    #         possible_usernames.append(n + "@OOPS.NET")
    #         possible_usernames.append("OOPS\\" + n)
    #         possible_usernames.append("OOPS.NET\\" + n)
    #         possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #         possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")
        
    #         n = a[0][0] + a[1] # asdf.zxcv -> azxcv
    #         possible_usernames.append(n + "@OOPS.NET")
    #         possible_usernames.append("OOPS\\" + n)
    #         possible_usernames.append("OOPS.NET\\" + n)
    #         possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #         possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")
            
    #         n = a[1][0] + "." + a[0] # asdf.zxcv -> z.asdf
    #         possible_usernames.append(n + "@OOPS.NET")
    #         possible_usernames.append("OOPS\\" + n)
    #         possible_usernames.append("OOPS.NET\\" + n)
    #         possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #         possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")
        
    #         n = a[1][0] + a[0] # asdf.zxcv -> zasdf
    #         possible_usernames.append(n + "@OOPS.NET")
    #         possible_usernames.append("OOPS\\" + n)
    #         possible_usernames.append("OOPS.NET\\" + n)
    #         possible_usernames.append("OOPS\\" + n + "@OOPS.NET")
    #         possible_usernames.append("OOPS.NET\\" + n + "@OOPS.NET")
        # except:
        #     pass
    
    # with open("centos_users", "r") as f:
    #     possible_usernames.extend([x.strip().lower() for x in f.readlines()])
    
    # with open("macos_users", "r") as f:
    #     possible_usernames.extend([x.strip().lower() for x in f.readlines()])
    
    # with open("freebsd_users", "r") as f:
    #     possible_usernames.extend([x.strip().lower() for x in f.readlines()])

    # possible_usernames.extend(["rkt", "hyper-v", "hyperv", "coreos", "docker"])


    # possible_usernames = ["white.ocie", "white.ocie@panic.invalid", "panic\\white.ocie"]

    # for x in range(100):
    #     possible_usernames.append(f"dkr_prd{str(x).zfill(2)}")
    #     possible_usernames.append(f"dkr_prd{x}")
    #     possible_usernames.append(f"dkr_tst{str(x).zfill(2)}")
    #     possible_usernames.append(f"dkr_tst{x}")

    # with open("SecLists/Usernames/cirt-default-usernames.txt", "r") as f:
    #     possible_usernames = [x.strip() for x in f.readlines()]
    
    # with open("SecLists/Usernames/Names/malenames-usa-top1000.txt", "r") as f:
    #     possible_usernames = [x.strip() for x in f.readlines()]
    
    # with open("SecLists/Usernames/Names/femalenames-usa-top1000.txt", "r") as f:
    #     possible_usernames = [x.strip() for x in f.readlines()]
    
    # with open("SecLists/Usernames/Names/familynames-usa-top1000.txt", "r") as f:
    #     possible_usernames = [x.strip() for x in f.readlines()]
    
    with open("SecLists/Usernames/Names/.txt", "r") as f:
        possible_usernames = [x.strip() for x in f.readlines()]

    # dedup list
    # https://www.w3schools.com/python/python_howto_remove_duplicates.asp
    possible_usernames = [x.lower() for x in list(dict.fromkeys(possible_usernames))]

    ts_start = int(pkt.time)

    for i in range(6):
        ts = ts_start - i
        for v in _gen_version_short():
        # for v in ["1.0.4.3"]:
            for u in possible_usernames:
                key = generate_session_key(u, v, ts)
                if test_session_key(pkt, key):
                    print(f"key data: {u}+{v}+{ts}")
                    return key

            # for k in range(100):
            #     u = "builder" + str(k).zfill(2)
            #     key = generate_session_key(u, v, ts)
            #     if test_session_key(pkt, key):
            #         print(f"key data: {u}+{v}+{ts}")
            #         return key
                
            #     u = "tester_" + str(k).zfill(2)
            #     key = generate_session_key(u, v, ts)
            #     if test_session_key(pkt, key):
            #         print(f"key data: {u}+{v}+{ts}")
            #         return key

    return None

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

    print(x(data))

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

def analyze_session(packets):
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

    cached_session_keys = {
        # 1210bd56-86f4-44c8-816a-b8d5d9c40c78
        # root+1.0.4.3+1615896614 (ts delta = -1)
        "192.168.178.179": binascii.unhexlify("23d69aa19fcbc4af6476897230122f73c709bc098f5b3fb7c4fde4116f784e74"),

        # c8f5fb1b-87cb-4e14-9d01-8efef9c7502b
        # mohammed+0.4.7.5+1615896594 (ts delta = -1)
        "192.168.174.131": binascii.unhexlify("fb43d897b3abae0c0246dadca89a2dde01912c917f78c688a9be04f48a13ad66"),

        # 870b0ed9-5288-4f17-9d84-e7a9bc028189
        # phillips+3.0.8.4+1615896623 (ts delta = -3)
        "192.168.151.216": binascii.unhexlify("e6b80686881d83e9e5cbbd6aef4d2208ab43b4a7c38ef593f8da33a00877f70b"),

        # d071a2d6-a44e-41fe-af49-8b7df6587bad
        # gipsy+1.5.7.2+1615896515 (ts delta = -1)
        "172.23.56.185": binascii.unhexlify("88faa85f19baec8902ab4b7faff2ff84e35ebcef2901994f5b3b275dc7780dd0"),

        # d1a5f6df-ab4a-42e8-ae9c-435d3ef68ff9
        # ange+0.0.2.4+1615896617 (ts delta = -1)
        "192.168.147.12": binascii.unhexlify("99034f685191c99f04d1b95829de6c3c80b461c601ef12b22166091c3148ba7f"),

        # 8b21b2a7-5b65-43c8-870b-7471fd21bcec
        # kishore+2.3.7.8+1615896571 (ts delta = -1)
        "198.18.108.159": binascii.unhexlify("80420daedd7524372b0329b18d98fa46a4f4742c0ea80d5bd9cbf0c84cedabe3")
    }

    if victim_ip in cached_session_keys.keys():
        print("using cached session key")
        session_key = cached_session_keys[victim_ip]
    else:
        print("bruteforcing session key")
        session_key = brute_force_session_key(data_packets[2])
        if session_key is None:
            print("failed to bruteforce session key, skipping analysis")
            return
        
        print(f"bruteforced session key for {victim_ip}: {x(session_key)}")

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

def main():
    pcap = rdpcap("../task1/capture.pcap")
    sessions = pcap.sessions(full_duplex)

    # with Pool(len(sessions.values())) as p:
    #     p.map(analyze_session, sessions.values())

    for s in sessions.values():
        # if s[0][IP].src == "192.168.174.131":
        if s[0][TCP].sport == 6666 or s[0][TCP].dport == 6666:
            analyze_session(s)
            print("\n####################################################################################################\n")

if __name__ == "__main__":
    main()