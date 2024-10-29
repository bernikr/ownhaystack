import base64
import datetime
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
TRUSTED_DEVICE = bool(os.environ.get("TRUSTED_DEVICE", False))
APPLE_USERNAME = os.environ["APPLE_USERNAME"]
APPLE_PASSWORD = os.environ["APPLE_PASSWORD"]
ANISETTE_URL = os.environ["ANISETTE_URL"]


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
            anisette_url=ANISETTE_URL,
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


def download_tag_data(tag_ids, days=7):
    unixEpoch = int(datetime.datetime.now().timestamp())
    startdate = unixEpoch - (60 * 60 * 24 * days)
    data = {
        "search": [
            {"startDate": startdate * 1000, "endDate": unixEpoch * 1000, "ids": tag_ids}
        ]
    }

    ah = AppleHeaders(ANISETTE_URL)

    r = requests.post(
        "https://gateway.icloud.com/acsnservice/fetch",
        auth=getAuth(
            second_factor="trusted_device" if TRUSTED_DEVICE else "sms",
            apple_headers=ah,
        ),
        headers=ah.generate_anisette_headers(),
        json=data,
    )
    return r.json()


def decrypt(enc_data, algorithm_dkey, mode):
    decryptor = Cipher(algorithm_dkey, mode, default_backend()).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()


def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], "big")
    status = int.from_bytes(data[9:10], "big")
    return {"lat": latitude, "lon": longitude, "conf": confidence, "status": status}


def main():
    id_tag_names = {}
    id_keys = {}
    for tag_file in (Path(__file__).parent / "data/tags").glob("*.txt"):
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
            id_keys[s256_b64] = keypair
            id_tag_names[s256_b64] = tag_file.stem
            pass

    res = download_tag_data(list(id_keys.keys()))
    print(res)
    pass


if __name__ == "__main__":
    main()
