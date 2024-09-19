import hmac

import PyKCS11
from PyKCS11 import AES_GCM_Mechanism
from PyKCS11.LowLevel import CKF_SERIAL_SESSION, CKF_RW_SESSION

from app.services.crypto.crypto_service import CryptoService, CryptoAlgorithm

AAD = "plaintext aad"

class HsmCryptoService(CryptoService):
    """
    A cryptographic service that uses a Hardware Security Module (HSM) to perform encryption, decryption, signing, and
    verification.
    """
    def __init__(self, module_path: str, slot: int, slot_pin: str):
        self.slot = slot
        self.slot_pin = ""

        self.session = None

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(module_path)

        # Check if slot actually exists
        for s in self.pkcs11.getSlotList():
            if s == slot:
                self.slot = s
                self.slot_pin = slot_pin
                break

        if self.slot is None:
            raise Exception(f"Slot {slot} not found. Please configure the slot first")

    def encrypt_and_digest(self, plaintext: bytes, key_id: str, iv: bytes) -> (bytes, bytes):
        ciphertext = self.encrypt(plaintext, key_id, iv)

        digest_data = AAD.encode() + iv + ciphertext + len(AAD).to_bytes(8, byteorder='big')
        digest_hmac = self.sign(CryptoAlgorithm.SHA256, digest_data, key_id)

        return ciphertext, digest_hmac[:16]

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, key_id: str, iv: bytes) -> bytes:
        digest_data = AAD.encode() + iv + ciphertext + len(AAD).to_bytes(8, byteorder='big')
        digest_hmac = self.sign(CryptoAlgorithm.SHA256, digest_data, key_id)

        if not hmac.compare_digest(digest_hmac[:16], tag):
            raise Exception("Invalid authentication tag")

        return self.decrypt(ciphertext, key_id, iv)

    def encrypt(self, plaintext: bytes, key_id: str, iv: bytes) -> bytes:
        sess = self._open_session()

        gcm_mecha = AES_GCM_Mechanism(iv, AAD, 16 * 8)

        obj = sess.findObjects([(PyKCS11.LowLevel.CKA_LABEL, key_id + "-aes")])
        if not obj:
            raise Exception(f"Key with label {key_id} not found")
        ciphertext = sess.encrypt(obj[0], plaintext, mecha=gcm_mecha)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key_id: str, iv: bytes) -> bytes:
        sess = self._open_session()

        gcm_mecha = AES_GCM_Mechanism(iv, AAD, 16 * 8)

        obj = sess.findObjects([(PyKCS11.LowLevel.CKA_LABEL, key_id + "-aes")])
        if not obj:
            raise Exception(f"Key with label '{key_id}-aes' not found")
        plaintext = sess.decrypt(obj[0], ciphertext, mecha=gcm_mecha)

        return bytes(plaintext)

    def sign(self, alg: CryptoAlgorithm, data: bytes, key_id: str) -> bytes:
        sess = self._open_session()

        obj = sess.findObjects([(PyKCS11.LowLevel.CKA_LABEL, key_id + "-hmac")])
        if not obj:
            raise Exception(f"Key with label '{key_id}-hmac' not found")

        sig = sess.sign(obj[0], data, mecha=self.get_mechanism(alg))
        return bytes(sig)

    def verify(self, alg: CryptoAlgorithm, data: bytes, signature: bytes, key_id: str) -> bool:
        sess = self._open_session()

        obj = sess.findObjects([(PyKCS11.LowLevel.CKA_LABEL, key_id + "-hmac")])
        if not obj:
            raise Exception(f"Key with label '{key_id}-hmac' not found")

        verified = sess.verify(obj[0], data, signature, mecha=self.get_mechanism(alg))

        return verified

    def generate_key(self, key_id: str):
        sess = self._open_session()

        template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_SECRET_KEY),
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_AES),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, key_id + "-aes"),
            (PyKCS11.LowLevel.CKA_ENCRYPT, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_VALUE_LEN, 32),
        ]
        sess.generateKey(template=template, mecha=PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_AES_KEY_GEN))

        template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_SECRET_KEY),
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_GENERIC_SECRET),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, key_id + "-hmac"),
            (PyKCS11.LowLevel.CKA_SIGN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_VALUE_LEN, 32),
        ]
        sess.generateKey(template=template, mecha=PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_GENERIC_SECRET_KEY_GEN))

    def _open_session(self) -> PyKCS11.Session:
        if self.session is None:
            try:
                self.session = self.pkcs11.openSession(self.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
                self.session.login(self.slot_pin)
            except Exception as e:
                print(e)
                raise Exception(f"Could not open HSM session")

        return self.session

    @staticmethod
    def get_mechanism(alg: CryptoAlgorithm) -> PyKCS11.Mechanism:
        if alg == CryptoAlgorithm.SHA256:
            return PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA256_HMAC)

        raise ValueError(f"Unsupported algorithm {alg}")


"""
----------------------------------------------------------
sudo apt install opensc
softhsm2-util --init-token --slot 0 --label "REK-1" --pin 1234 --so-pin 1234
./pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234 --token "REK-1" --keygen --key-type AES:32 --label "aes"
./pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234 --token "REK-1" --keygen --key-type GENERIC:32 --label "hmac"

echo "this is something secret" | ./pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234  --token "REK-1" --label "aes" --encrypt --mechanism AES-GCM --iv "00000000000000000000000000000000" --aad "feedfacedeadbeeffeedfacedeadbeefabaddad2" --tag-bits-len 128 --output-file enc.dat
./pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234 --decrypt --mechanism AES-GCM --token "REK-1" --label "aes" --iv "00000000000000000000000000000000" --aad "feedfacedeadbeeffeedfacedeadbeefabaddad2" --tag-bits-len 128 --input-file enc.dat

echo "this is a remix" | ./pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -m SHA256-HMAC -l --pin 1234 --label "hmac" --sign --output-file hmac.enc
"""