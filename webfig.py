
from base64 import encode
from Crypto.Cipher import DES
import donna25519
from nacl.public import PrivateKey
import requests
import hashlib


def web_encode(data: bytes) -> bytes:
    return data.decode('latin-1').replace(chr(0), chr(256)).encode('utf-8')


def web_decode(data: bytes) -> bytes:
    return data.decode('utf-8').replace(chr(256), chr(0)).encode('latin-1')


def md4(data):
    h = hashlib.new('md4')
    h.update(data)
    return h.digest()


def des(inp, key):
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00'*8)
    
    pz = (8 - (len(inp) % 8)) % 8
    inp = inp + (b'\x00' * pz)
    
    return cipher.encrypt(inp)


class RC4():
    def __init__(self):
        self.S =[]
        self.i = 0
        self.j = 0

    def gen(self):
        S = self.S
        i = (self.i + 1) & 255
        self.i = i
        j = (self.j + S[i]) & 255
        self.j = j
        t = S[i]
        S[i] = S[j]
        S[j] = t
        return S[(S[i] + S[j]) & 255]

    def set_key(self, cryptkey: list):
        key_lenth = len(cryptkey)

        self.S = list(range(256))
        K = []
        for i in range(0, 256):
            K.append(cryptkey[i % key_lenth])

        for i in range(0, 256):
            self.j = (self.j + K[i] + self.S[i]) % 256
            t = self.S[i]
            self.S[i] = self.S[self.j]
            self.S[self.j] = t

        self.i = 0
        self.j = 0
        for _ in range(0, 768):
            self.gen()

    def encrypt(self, msg: bytes):
        new_msg = []
        i = 0
        for i in range(0, len(msg)):
            new_msg.append(self.gen() ^ msg[i])
        return bytes(new_msg)


class Tracker(object):
    def __init__(self):
        self.id = 0
        self.seq = 1

    def pack(self, data: bytes) -> bytes:
        out = b''
        out += self.id.to_bytes(4, 'big')
        out += self.seq.to_bytes(4, 'big')
        out += data

        self.seq += len(data)
        return out


class WebFig(object):
    def __init__(self, host, username, password):
        self.host = host
        self.endpoint = '/jsproxy'

        self.tracker = Tracker()
        self.tx = RC4()
        self.rx = RC4()

        self.handshake(username, password)

    def handshake(self, username, password):
        # Try to fingerprint version.
        r = requests.post(f'http://{self.host}{self.endpoint}')
        resp = web_decode(r.content)

        if len(resp) == 24:
            self.handshake_v1(username, password)
        elif r.status_code == 500:
            self.handshake_v2()
            self.login(username, password)
        else:
            raise Exception(f"Unknown handshake type.")

    def handshake_v1(self, username, password):
        username = username.encode('ascii')
        password = password.encode('ascii')

        r = requests.post(f'http://{self.host}{self.endpoint}').content
        resp = web_decode(r)

        self.tracker.id = int.from_bytes(resp[:4], 'big')
        rchal = resp[8:]

        lchal = bytes([0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E])

        chlgHash = hashlib.sha1(lchal + rchal + username).digest()[:8]
        pwdHash = md4(password)
        pwdHashHash = md4(pwdHash)

        # pad because MikroTik code is broken
        pwdHash += b'\x00' * 8

        response = b''
        for j in range(0, 3*56, 56):
            key = []
            for i in range(j, j+56, 7):
                w = pwdHash[i >> 3] << 8 | (pwdHash[(i>>3)+1])
                key.append((w >> (8 - (i & 7))) & 0xfe)
            response += des(chlgHash, bytes(key))
            
        magic = b'This is the MPPE Master Key'
        masterKey = hashlib.sha1(pwdHashHash + response + magic).digest()[:16]

        self.set_keys(masterKey)

        msg = b'\x00\x00' + lchal + (b'\x00' * 8) + response
        out = rchal + msg + username

        r = requests.post(f'http://{self.host}{self.endpoint}', data=web_encode(
            self.tracker.id.to_bytes(4, 'big')
            + (0).to_bytes(4, 'big')
            + out
        ))
        resp = web_decode(r.content)
        dec = self.rx.encrypt(resp[8:])

    def handshake_v2(self):
        self.private = [174,119,158,240,196,104,82,173,235,48,65,51,104,30,21,241,112,192,181,215,220,133,9,206,55,88,98,134,47,198,120,65]
        self.pubkey = self.gen_public_key()

        self.server = self.get_server_key(self.pubkey)
        self.tracker.id = self.server[0]
        
        shared = self.gen_shared_secret(bytes(self.private)[::-1], self.server[1][::-1])[::-1]
        self.set_keys(shared)

    def gen_public_key(self):
        priv_key_bytes = bytes(bytearray(self.private))[::-1]
        self.public = list(PrivateKey(priv_key_bytes).public_key.encode()[::-1])
        return bytes(self.public)

    def gen_shared_secret(self, private_key: bytes, server_public: bytes):
        return donna25519.PrivateKey(private_key).do_exchange(donna25519.PublicKey(server_public))

    def get_server_key(self, public: bytes):
        packed = web_encode((b'\x00' * 8) + public)

        r = requests.post(url = "http://" + self.host + self.endpoint, data=packed)
        resp = web_decode(r.content)

        s_id = int.from_bytes(resp[:4], 'big')
        s_key = resp[8:]

        return (s_id, s_key)

    def set_keys(self, shared):
        rxEnc, txEnc = self.compute_stream_keys(shared)
        self.tx.set_key(txEnc)
        self.rx.set_key(rxEnc)

    def compute_stream_keys(self, shared: bytes):
        magic2 = b"On the client side, this is the send key; on the server side, it is the receive key."
        magic3 = b"On the client side, this is the receive key; on the server side, it is the send key."

        rxEnc = shared + b'\00' * 40 + magic3 + b'\xf2' * 40
        txEnc = shared + b'\00' * 40 + magic2 + b'\xf2' * 40

        rxEnc = hashlib.sha1(rxEnc).digest()[:16]
        txEnc = hashlib.sha1(txEnc).digest()[:16]

        return rxEnc, txEnc

    def _send(self, data: bytes, content_type: str, encoded: bool, ignore_response: bool = False, timeout = None):
        enc = self.tx.encrypt(data) + self.tx.encrypt(b'\x20' * 8)
        packed = self.tracker.pack(enc)

        if encoded:
            packed = web_encode(packed)

        r = None
        try:
            r = requests.post(
                "http://" + self.host + self.endpoint,
                headers={
                    'Host': self.host,
                    'Content-Type': content_type
                },
                data=packed,
                timeout=timeout
            )
        except requests.Timeout:
            return 'timeout'
        except:
            return 'bad'

        if not ignore_response and r is not None:
            if r.status_code != 200:
                print(r.content)
                raise ValueError(f'Status code: {r.status_code}')

            resp = r.content
            if encoded:
                resp = web_decode(resp)

            dec = self.rx.encrypt(resp[8:])
            assert dec[-8:] == b'\x20' * 8, 'Padding failure'
            return dec[:-8]
        else:
            return None

    def send_raw(self, data: bytes, ignore_response: bool = False, timeout = None):
        return self._send(data, content_type='msg', encoded=False, ignore_response=ignore_response, timeout=timeout)

    def send_json(self, data: bytes, ignore_response: bool = False, timeout = None):
        return self._send(data, content_type='text/plain', encoded=True, ignore_response=ignore_response, timeout=timeout)

    def login(self, username: str, password: str):
        data = b'M2'
        data += bytes.fromhex('01000021')
        data += len(username).to_bytes(1, 'little')
        data += username.encode('ascii')
        data += bytes.fromhex('03000021')
        data += len(password).to_bytes(1, 'little')
        data += password.encode('ascii')
        self.send_raw(data)
