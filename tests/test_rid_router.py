import json
from typing import List, Tuple, Dict, Any
from Crypto.PublicKey import RSA
from jwcrypto import jwe, jwk

from starlette.testclient import TestClient
from app.services.key_resolver import KeyResolver


MOCK_ORGS = {
    "ura:12345678": (["nvi"], "irp", "", ""),
    "ura:87654321": (["nvi"], "rp", "", ""),
    "ura:11223344": (["brp"], "bsn", "", ""),
}

def generate_org(key_resolver: KeyResolver, org_id: str, scope: List[str], max_usage_level: str, pub_key: str) -> None:
    print(f"Generating org {org_id} with scope {scope} and max usage {max_usage_level}")
    entries = key_resolver.get_by_org(org_id)
    if entries is not None:
        for entry in entries:
            key_resolver.delete(str(entry.entry_id))
    key_resolver.create(org_id, scope, pub_key, max_usage_level)

def gen_rsa_key(bits: int = 1024) -> Tuple[str, str]:
    key = RSA.generate(bits)

    priv_key = key.export_key().decode('utf-8')
    pub_key = key.publickey().export_key().decode('utf-8')
    return priv_key, pub_key

def create_mock_orgs(key_resolver: KeyResolver, mock_orgs: Dict[str, Any]) -> None:
    for ura, org in mock_orgs.items():
        (priv_key, pub_key) = gen_rsa_key(1024)
        generate_org(key_resolver, ura, org[0], org[1], pub_key)
        mock_orgs[ura] = (org[0], org[1], priv_key, pub_key)

def decode_jwe(jwe_token: str, priv_key_pem: str) -> Tuple[dict[str, Any], dict[str, Any]]:
    token = jwe.JWE()
    token.deserialize(jwe_token)
    headers = token.jose_header
    try:
        priv_key = jwk.JWK.from_pem(priv_key_pem.encode('ascii'))
        token.decrypt(priv_key)
        plaintext = token.payload.decode('utf-8')
        data = json.loads(plaintext)
    except Exception as e:
        raise RuntimeError(f"Could not decrypt JWE: {e}")

    return headers, data

def test_create_happy_path(client: TestClient, key_resolver: KeyResolver) -> None:
    create_mock_orgs(key_resolver, MOCK_ORGS)
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })
    assert response.status_code == 201
    assert response.content is not None
    assert response.headers["Content-Type"] == "Multipart/Encrypted"
    assert response.content.startswith(b"eyJra")

def test_invalid_scope(client: TestClient, key_resolver: KeyResolver) -> None:
    create_mock_orgs(key_resolver, MOCK_ORGS)
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "invalid-scope",
        "ridUsage": "bsn",
    })

    assert response.status_code == 404
    assert response.json() == {"error": "No public key found for this organization and/or scope"}
    assert response.headers["Content-Type"] == "application/json"

    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:1234567823751735703297509312759013275097125",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })

    assert response.status_code == 404
    assert response.json() == {"error": "No public key found for this organization and/or scope"}
    assert response.headers["Content-Type"] == "application/json"


def test_decode_as_receiver(client: TestClient) -> None:
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })
    jwe = response.content.decode("utf-8")
    (headers, data) = decode_jwe(jwe, MOCK_ORGS["ura:12345678"][2])

    assert headers['enc'] == 'A256GCM'
    assert headers['alg'] == 'RSA-OAEP-256'
    assert headers['kid'] is not None

    assert data['subject'].startswith("rid:")
    assert data['aud'] == "ura:12345678"
    assert data['scope'] == "nvi"
    assert data['ridUsage'] == 'bsn'


    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })
    jwe = response.content.decode("utf-8")
    (headers2, data2) = decode_jwe(jwe, MOCK_ORGS["ura:12345678"][2])

    # Make sure a new RID is generated each time
    assert data['subject'] != data2['subject']


def test_receive_rids(client: TestClient) -> None:
    response = client.post("/receive", json={
        "rid": "foobar",
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "rp"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid RID format"}


    response = client.post("/receive", json={
        "rid": "rid:foobar",
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "rp"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Failed to decrypt RID"}


def test_receive_incorrect_org(client: TestClient) -> None:
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })
    jwe = response.content.decode("utf-8")
    (headers, data) = decode_jwe(jwe, MOCK_ORGS["ura:12345678"][2])
    rid = data['subject']

    # We should not be able to decrypt to incorrect organization
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:32535632532512512",
        "recipientScope": "nvi",
        "pseudonymType": "rp"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "RID not intended for this organization and/or scope"}

    # We should not be able to decrypt to incorrect scope
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:12345678",
        "recipientScope": "incorrect-scope",
        "pseudonymType": "rp"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "RID not intended for this organization and/or scope"}

    # We should not be able to decrypt to BSN
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "bsn"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Organization / scope is not allowed to exchange BSNs"}

def test_receive_incorrect_usage(client: TestClient) -> None:
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "ridUsage": "irp",      # Can only be used to exchange for an IRP, not an RP or BSN
    })
    jwe = response.content.decode("utf-8")
    (headers, data) = decode_jwe(jwe, MOCK_ORGS["ura:12345678"][2])
    rid = data['subject']

    # We should not be able to decrypt to RP, even if we are allowed as an organisation
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "rp"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Requested pseudonym type not allowed for this RID"}

    # We should not be able to decrypt to BSN, even if we are allowed as an organisation
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "bsn"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Requested pseudonym type not allowed for this RID"}

    # But we should be able to decrypt to IRP
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:12345678",
        "recipientScope": "nvi",
        "pseudonymType": "irp"
    })
    assert response.status_code == 200
    assert response.json()['type'] == 'irp'


def test_min_usage_level(client: TestClient) -> None:
    response = client.post("/exchange/rid", json={
        "personalId": { "landCode": "NL", "type": "bsn", "value": "9500009012" },
        "recipientOrganization": "ura:87654321",
        "recipientScope": "nvi",
        "ridUsage": "bsn",
    })
    jwe = response.content.decode("utf-8")
    (headers, data) = decode_jwe(jwe, MOCK_ORGS["ura:87654321"][2])
    rid = data['subject']

    # Organization is allowed to retrieve an IRP
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:87654321",
        "recipientScope": "nvi",
        "pseudonymType": "irp"
    })
    assert response.status_code == 200
    assert response.json()['type'] == 'irp'

    # Organization is allowed to retrieve an RP
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:87654321",
        "recipientScope": "nvi",
        "pseudonymType": "rp"
    })
    assert response.status_code == 200
    assert response.json()['type'] == 'rp'

    # Organization is NOT allowed to retrieve a BSN
    response = client.post("/receive", json={
        "rid": rid,
        "recipientOrganization": "ura:87654321",
        "recipientScope": "nvi",
        "pseudonymType": "bsn"
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Organization / scope is not allowed to exchange BSNs"}
