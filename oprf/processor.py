from models import BlindRequest
import pyoprf
import base64
from jwtoken import build_jwe

_sk: bytes|None = None

def get_server_key() -> bytes:
    global _sk

    if _sk is None:
        with open("prs.key", "rb") as f:
            _sk = bytes.fromhex(f.read().decode('utf-8'))

    return _sk


def process_blind(req: BlindRequest) -> str:
    bi = base64.urlsafe_b64decode(req.encryptedPersonalId)
    eval = pyoprf.evaluate(get_server_key(), bi)

    subject = "eval:" + base64.urlsafe_b64encode(eval).decode('utf-8')
    jwe = build_jwe(
        aud=req.recipientOrganization,
        scope=req.recipientScope,
        subject=subject
    )

    return jwe
