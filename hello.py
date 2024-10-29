import base64
import datetime
import hashlib
import json
import os
import struct
from pathlib import Path

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

from pypush_gsa_icloud import AppleHeaders

load_dotenv()
TRUSTED_DEVICE = bool(os.environ.get("TRUSTED_DEVICE"))
APPLE_USERNAME = os.environ["APPLE_USERNAME"]
APPLE_PASSWORD = os.environ["APPLE_PASSWORD"]
ANISETTE_URL = os.environ.get("ANISETTE_URL")


def getAuth(regenerate=False, second_factor="sms", apple_headers=None):
    CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/data/auth.json"
    if os.path.exists(CONFIG_PATH) and not regenerate:
        with open(CONFIG_PATH, "r") as f:
            j = json.load(f)
    else:
        mobileme = apple_headers.icloud_login_mobileme(
            username=APPLE_USERNAME,
            password=APPLE_PASSWORD,
            second_factor=second_factor,
        )
        j = {
            "dsid": mobileme["dsid"],
            "searchPartyToken": mobileme.get("delegates")
            .get("com.apple.mobileme")
            .get("service-data")
            .get("tokens")
            .get("searchPartyToken"),
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(j, f)
    return j["dsid"], j["searchPartyToken"]


def download_reports(tag_ids, days=7):
    unixEpoch = int(datetime.datetime.now().timestamp())
    startdate = unixEpoch - (60 * 60 * 24 * days)
    data = {
        "search": [
            {"startDate": startdate * 1000, "endDate": unixEpoch * 1000, "ids": tag_ids}
        ]
    }

    ah = AppleHeaders(ANISETTE_URL)
    auth = getAuth(
        second_factor="trusted_device" if TRUSTED_DEVICE else "sms",
        apple_headers=ah,
    )
    headers = ah.generate_anisette_headers()

    print("making request to FindMy Network")
    r = requests.post(
        "https://gateway.icloud.com/acsnservice/fetch",
        auth=auth,
        headers=headers,
        json=data,
    )
    if r.status_code != requests.codes.ok:
        raise Exception(f"Status {r.status_code}: {r.text}")
    res = r.json()["results"]
    print(f"got {len(res)} results")
    return res


def load_keys(
    key_folder: Path,
) -> tuple[dict[str, ec.EllipticCurvePrivateKey], dict[str, str]]:
    print(f"loading keys from {key_folder}")
    names = {}
    keys = {}
    for tag_file in key_folder.glob("*.txt"):
        for tag in tag_file.read_text(encoding="utf-8").strip().split("\n"):
            priv_key = tag.strip()

            keypair = ec.derive_private_key(
                int.from_bytes(base64.b64decode(priv_key), byteorder="big"),
                ec.SECP224R1(),
                default_backend(),
            )
            pubkey_bytes = (
                keypair.public_key().public_numbers().x.to_bytes(28, byteorder="big")
            )
            public_key_hash = hashes.Hash(hashes.SHA256())
            public_key_hash.update(pubkey_bytes)
            s256_b64 = base64.b64encode(public_key_hash.finalize()).decode()
            keys[s256_b64] = keypair
            names[s256_b64] = tag_file.stem
    return keys, names


def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()


def decrypt_report(payload: str, key: ec.EllipticCurvePrivateKey) -> dict:
    data = base64.b64decode(payload)
    adj = len(data) - 88  # check if NULL bytes are present in the data

    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP224R1(), data[5 + adj : 62 + adj]
    )
    shared_key = key.exchange(ec.ECDH(), eph_key)
    symmetric_key = sha256(shared_key + b"\x00\x00\x00\x01" + data[5 + adj : 62 + adj])
    decryption_key = symmetric_key[:16]
    iv = symmetric_key[16:]
    enc_data = data[62 + adj : 72 + adj]
    auth_tag = data[72 + adj :]

    decryptor = Cipher(
        algorithms.AES(decryption_key), modes.GCM(iv, auth_tag), default_backend()
    ).decryptor()
    decrypted = decryptor.update(enc_data) + decryptor.finalize()

    tag = {
        "lat": struct.unpack(">i", decrypted[0:4])[0] / 10000000.0,
        "lon": struct.unpack(">i", decrypted[4:8])[0] / 10000000.0,
        "acc": int.from_bytes(decrypted[8:9], "big"),
        # "status": int.from_bytes(decrypted[9:10], "big"),
        "tst": int.from_bytes(data[0:4], "big") + 978307200,
    }
    return tag


def main():
    keys, names = load_keys((Path(__file__).parent / "data/tags"))
    enc_reports = download_reports(list(keys.keys()))
    reports = [
        (
            names[r["id"]],
            decrypt_report(r["payload"], keys[r["id"]])
            | {"created_at": r["datePublished"] // 1000},
        )
        for r in enc_reports
    ]
    reports.sort(key=lambda r: r[1]["tst"])
    print(reports)


if __name__ == "__main__":
    main()
