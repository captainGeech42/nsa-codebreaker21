#!/usr/bin/env python3

import base64
import binascii
import hashlib
import io
from re import A
import struct
import sys
import time
import uuid

import nacl.exceptions
import nacl.secret
import nacl.public
import nacl.utils
import pwn

log = pwn.log

SERVER_IP = "18.207.225.202"
SERVER_PORT = 6666
SERVER_PUBKEY = nacl.public.PublicKey(binascii.unhexlify("b8e84cc9cded282df1f9fd129c8140202b78dafed2f6038800e4d004f03dc11d"))
        
MAGIC_START = b"\x16\x16\xbf\x7d"
MAGIC_END = b"\xef\x3b\x1b\xbf"

pwn.context.endian = "big"

x = lambda d: binascii.hexlify(d).decode()

# used for C2Param.cmd()
class C2Command():
    COMMAND_INIT = b"\x00\x02"
    COMMAND_UPLOAD = b"\x00\x06"
    COMMAND_FIN = b"\x00\x07"

    def init(uuid):
        param = C2Param.uuid(uuid)

        payload = b""
        payload += C2Command.COMMAND_INIT
        payload += param

        return payload

class C2Param():
    PARAM_CMD = b"\x69\x00"
    PARAM_UUID = b"\x69\x08"
    PARAM_DIRNAME = b"\x69\x14"
    PARAM_FILENAME = b"\x69\x1c"
    PARAM_CONTENTS = b"\x69\x20"
    PARAM_MORE = b"\x69\x24"
    PARAM_CODE = b"\x69\x28"

    def cmd(val: bytes):
        payload = b""
        payload += C2Param.PARAM_CMD
        payload += pwn.p16(2) # length of command
        payload += val

        return payload

    def uuid(val: bytes):
        payload = b""
        payload += C2Param.PARAM_UUID
        payload += pwn.p16(len(val))
        payload += val

        return payload
    
    def parse(val: bytes):
        stream = io.BytesIO(val)
        
        assert(stream.read(4) == MAGIC_START)

        param = stream.read(2)
        if param == C2Param.PARAM_CODE:
            RESPONSE_CODE_LENGTH = 4

            code_length = pwn.u16(stream.read(2))
            if code_length != RESPONSE_CODE_LENGTH:
                log.error(f"bad response code length: {code_length}")
                return
        
            code = pwn.u32(stream.read(code_length))
            log.debug(f"response code: {code}")

            return code
        else:
            log.error(f"unexpected param in parse(): {x(param)}")
            return

class Bot():
    def __init__(self, server):
        # generate fingerprint data
        self.username = "root"
        self.version = "1.2.3.4-XYZ"
        self.version_short = self.version.split("-")[0]
        self.ts = int(time.time())
        self.uuid = uuid.uuid4()

        # generate crypto keys
        self.client_privkey = nacl.public.PrivateKey.generate()
        self.client_pubkey = self.client_privkey.public_key
        self.session_key = hashlib.sha256(f"{self.username}+{self.version_short}+{self.ts}".encode()).digest()

        # remote
        self.server = server

    # asymmetric encryption
    # returns ctxt (which has nonce prepended)
    def _box_encrypt(self, buf):
        box = nacl.public.Box(self.client_privkey, SERVER_PUBKEY)

        ctxt = box.encrypt(buf)
        return ctxt

    # symmetric encryption
    # returns ctxt (which has nonce prepended)
    def _secretbox_encrypt(self, buf):
        box = nacl.secret.SecretBox(self.session_key)

        ctxt = box.encrypt(buf)
        return ctxt

    # symmetric decryption
    # returns ptxt
    def _secretbox_decrypt(self, buf):
        box = nacl.secret.SecretBox(self.session_key)

        ptxt = box.decrypt(buf)

        return ptxt

    # build fingerprint string
    # b64("username=$username") + "," + b64("version=$version") + "," + b64("os=$os") + "," + b64("timestamp=$timestamp")
    def _gen_fingerprint_str(self):
        payload = b""
        payload += base64.b64encode(f"username={self.username}".encode())
        payload += b","
        payload += base64.b64encode(f"version={self.version}".encode())
        payload += b","
        payload += base64.b64encode(f"os=Linux".encode())
        payload += b","
        payload += base64.b64encode(f"timestamp={self.ts}".encode())

        return payload

    # add magic and encrypt packet
    def _build_session_pkt(self, buf):
        buf = MAGIC_START + buf + MAGIC_END

        ctxt = self._secretbox_encrypt(buf)

        l = self._encode_length(len(ctxt))

        return l + ctxt

    def _build_handshake_pkt(self, buf):
        ctxt = self._box_encrypt(buf)

        l = self._encode_length(len(ctxt))

        return l + ctxt

    # encode length in their stupid way
    def _encode_length(self, length):
        random_bytes = 0x4242 # chosen by fair dice roll
        body_length = length - random_bytes + 0x10000
        return struct.pack(">HH", random_bytes, body_length)

    # decode 1length in their stupid way
    def _decode_length(self, length):
        assert(len(length) == 4)

        random_bytes, encoded_len = struct.unpack(">HH", length)
        body_length = encoded_len + random_bytes - 0x10000
        return body_length

    # pull packet from the wire and parse out response code
    def _get_response_code(self):
        length = self._decode_length(self.server.recv(4))

        pkt = self.server.recv(length)

        ptxt = self._secretbox_decrypt(pkt)

        code = C2Param.parse(ptxt)

        return code

    # send pubkey, fingerprint, and uuid init
    def register(self):
        # send public key
        self.server.send(bytes(self.client_pubkey))

        # send encrypted fingerprint str
        self.server.send(self._build_handshake_pkt(self._gen_fingerprint_str()))

        time.sleep(0.5)

        # send init
        self.server.send(self._build_session_pkt(C2Param.cmd(C2Command.init(self.uuid.bytes))))

        return self._get_response_code()

def main(argv):
    server = pwn.remote(SERVER_IP, SERVER_PORT)

    bot = Bot(server)
    log.info(f"bot uuid: {bot.uuid}")
    log.info(f"session key: {x(bot.session_key)}")

    log.info(f"registering bot")
    resp_code = bot.register()

    if resp_code == 0:
        log.success("successfully registered bot")
    else:
        log.error(f"failed to register bot (resp code: {resp_code})")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))