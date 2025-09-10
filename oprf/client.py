from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import requests
import json
import base64
import pyoprf
import sys

PRS_URL = "http://localhost:8000"
RECEIVER_URL = "http://localhost:8001"


def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, data, None)  # no AAD


def decrypt(enc_data: bytes, key: bytes, iv: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, enc_data, None)


def send_blinded_request(data):
    response = requests.post(f"{PRS_URL}/", json=data)
    response.raise_for_status()
    return response.text


def send_to_receiver(blind_factor: str, jwe: str):
    response = requests.post(f"{RECEIVER_URL}/", json={"bf": blind_factor, "jwe": jwe})
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    bsn = sys.argv[1] if len(sys.argv) > 1 else "980000012"
    recv_org = sys.argv[2] if len(sys.argv) > 2 else "ura:12345678"
    recv_scope = sys.argv[3] if len(sys.argv) > 3 else "nvi"

    # Create hashed bsn that is dedicated for the givn receiver
    info = f"{recv_org}|{recv_scope}|v1".encode('utf-8')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info = info)
    pid = json.dumps({"landCode": "NL", "type": "BSN", "value": bsn});
    pseudonym = hkdf.derive(pid.encode('utf-8'))

    # Create blinded input. This will mask the BSN so we can send it directly to the PRS
    print(" * Creating blinded input from (hashed) BSN")
    blind_factor, blinded_input = pyoprf.blind(pseudonym)

    bf = base64.urlsafe_b64encode(blind_factor).decode('utf-8')
    bi = base64.urlsafe_b64encode(blinded_input).decode('utf-8')
    print(" * Blinded input:", bi)

    # Send data over the PRS
    print(" * Sending request over to the PRS...")
    blind_request_data = {
        "encryptedPersonalId": bi,
        "recipientOrganization": str(recv_org),
        "recipientScope": str(recv_scope)
    }
    jwe = send_blinded_request(blind_request_data)
    print(" * Received JWE:", jwe[:30] + "...")

    print(" * Sending JWE over to the receiver")
    res = send_to_receiver(bf, jwe)
    print(" * Receiver response:", res)
