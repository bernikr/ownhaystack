import base64
import datetime as dt
import functools
import hashlib
import json
import os
import struct
import time
import traceback
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Literal

import paho.mqtt.client as mqtt
import requests
import urllib3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from paho.mqtt.enums import CallbackAPIVersion
from paho.mqtt.properties import Properties
from paho.mqtt.reasoncodes import ReasonCode

from findmy_reports import FINDMY_FETCH_URL, build_fetch_request, parse_fetch_response
from pypush_gsa_icloud import AppleHeaders

VERSION = "0.1.3"

load_dotenv()
TRUSTED_DEVICE = bool(os.environ.get("TRUSTED_DEVICE"))
APPLE_USERNAME = os.environ["APPLE_USERNAME"]
APPLE_PASSWORD = os.environ["APPLE_PASSWORD"]
ANISETTE_URL = os.environ.get("ANISETTE_URL")
MQTT_TOPIC_PREFIX = os.environ.get("MQTT_TOPIC", "owntracks/haystack/")
MQTT_SERVER = os.environ["MQTT_SERVER"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD")
MQTT_TLS = os.environ.get("MQTT_TLS", "FALSE").upper()
REFRESH_INTERVAL = int(os.environ.get("REFRESH_INTERVAL", "5")) * 60
AUTH_FILE = Path(os.environ.get("AUTH_FILE", Path(__file__).parent / "data/auth.json"))
KEY_FOLDER = Path(os.environ.get("KEY_FOLDER", Path(__file__).parent / "data/keys"))


def get_auth(
    apple_headers: AppleHeaders,
    *,
    regenerate: bool = False,
    second_factor: Literal["sms", "trusted_device"] = "sms",
) -> tuple[str, str]:
    if AUTH_FILE.exists() and not regenerate:
        with AUTH_FILE.open("r", encoding="utf-8") as f:
            j = json.load(f)
    else:
        mobileme = apple_headers.icloud_login_mobileme(
            username=APPLE_USERNAME,
            password=APPLE_PASSWORD,
            second_factor=second_factor,
        )
        if mobileme["status"] != 0:
            msg = f"Error logging in Apppe Account: {mobileme['status-message']}"
            raise Exception(msg)
        j = {
            "dsid": mobileme["dsid"],
            "searchPartyToken": mobileme["delegates"]["com.apple.mobileme"]["service-data"]["tokens"][
                "searchPartyToken"
            ],
        }
        with AUTH_FILE.open("w", encoding="utf-8") as f:
            json.dump(j, f)
    return j["dsid"], j["searchPartyToken"]


def download_reports(tag_ids: list[str], days: int = 7) -> list[dict[str, Any]]:
    unix_epoch = int(dt.datetime.now(tz=dt.UTC).timestamp())
    startdate = unix_epoch - (60 * 60 * 24 * days)
    data = build_fetch_request(tag_ids, startdate * 1000, unix_epoch * 1000)

    ah = AppleHeaders(ANISETTE_URL)
    auth = get_auth(ah, second_factor="trusted_device" if TRUSTED_DEVICE else "sms")
    headers = ah.generate_anisette_headers()

    print(f"making request to FindMy Network for {len(tag_ids)} keys")
    r = requests.post(
        FINDMY_FETCH_URL,
        auth=auth,
        headers=headers,
        json=data,
        timeout=10,
    )
    if r.status_code == requests.codes.unauthorized:
        print("Got 401 Unauthorized from Server try logging in again (might require 2fa agian)")
        get_auth(ah, regenerate=True)
    if r.status_code != requests.codes.ok:
        msg = f"FindMy request failed with status {r.status_code}"
        raise Exception(msg)
    try:
        body = r.json()
    except ValueError as e:
        msg = f"Could not parse FindMy response: {e}"
        raise ValueError(msg) from e
    res = parse_fetch_response(body)
    print(f"got {len(res)} results")
    return res


def load_keys(
    key_folder: Path,
) -> tuple[dict[str, ec.EllipticCurvePrivateKey], dict[str, str]]:
    print(f"loading keys from {key_folder}")
    names = {}
    keys = {}
    for tag_file in key_folder.glob("*.priv_keys"):
        for tag in tag_file.read_text(encoding="utf-8").strip().split("\n"):
            priv_key = tag.strip()

            keypair = ec.derive_private_key(
                int.from_bytes(base64.b64decode(priv_key), byteorder="big"),
                ec.SECP224R1(),
                default_backend(),
            )
            pubkey_bytes = keypair.public_key().public_numbers().x.to_bytes(28, byteorder="big")
            public_key_hash = hashes.Hash(hashes.SHA256())
            public_key_hash.update(pubkey_bytes)
            s256_b64 = base64.b64encode(public_key_hash.finalize()).decode()
            keys[s256_b64] = keypair
            names[s256_b64] = tag_file.stem
    return keys, names


def sha256(data: bytes) -> bytes:
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()


def decrypt_report(payload: str, key: ec.EllipticCurvePrivateKey) -> dict:
    data = base64.b64decode(payload)
    adj = len(data) - 88  # check if NULL bytes are present in the data

    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5 + adj : 62 + adj])
    shared_key = key.exchange(ec.ECDH(), eph_key)
    symmetric_key = sha256(shared_key + b"\x00\x00\x00\x01" + data[5 + adj : 62 + adj])
    decryption_key = symmetric_key[:16]
    iv = symmetric_key[16:]
    enc_data = data[62 + adj : 72 + adj]
    auth_tag = data[72 + adj :]

    decryptor = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, auth_tag), default_backend()).decryptor()
    decrypted = decryptor.update(enc_data) + decryptor.finalize()

    return {
        "lat": struct.unpack(">i", decrypted[0:4])[0] / 10000000.0,
        "lon": struct.unpack(">i", decrypted[4:8])[0] / 10000000.0,
        "acc": int.from_bytes(decrypted[8:9], "big"),
        # "status": int.from_bytes(decrypted[9:10], "big"),  # ruff: ignore[commented-out-code]
        "tst": int.from_bytes(data[0:4], "big") + 978307200,
    }


def main() -> None:  # ruff: ignore[complex-structure]
    last_timestamps = {}

    def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:  # ruff: ignore[any-type, unused-function-argument]
        try:
            report = json.loads(msg.payload)
            name = msg.topic.split("/")[-1]
            last_timestamps[name] = int(report.get("tst", 0))
        except (JSONDecodeError, ValueError):
            return

    def on_connect(
        client: mqtt.Client,  # ruff: ignore[unused-function-argument]
        userdata: Any,  # ruff: ignore[any-type, unused-function-argument]
        flags: dict[str, Any],  # ruff: ignore[unused-function-argument]
        reason_code: ReasonCode,
        properties: Properties | None,  # ruff: ignore[unused-function-argument]
    ) -> None:
        if reason_code != "Success":
            msg = f"MQTT Connection Error: {reason_code}"
            raise Exception(msg)
        print("Connected to MQTT server")

    mqttc = mqtt.Client(CallbackAPIVersion.VERSION2)
    mqttc.on_message = on_message
    mqttc.on_connect = on_connect
    mqttc.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    if MQTT_TLS == "TRUE":
        mqttc.tls_set()
    mqttc.connect(MQTT_SERVER, MQTT_PORT, 60)
    mqttc.subscribe(MQTT_TOPIC_PREFIX + "#")
    mqttc.loop_start()
    time.sleep(1)
    mqttc.unsubscribe(MQTT_TOPIC_PREFIX + "#")

    print(f"Stopped Listening to MQTT messages, got {len(last_timestamps)} last timestamps")

    keys, names = load_keys(KEY_FOLDER)
    enc_reports = download_reports(list(keys.keys()))
    reports = []
    for r in enc_reports:
        key = keys.get(r["id"])
        name = names.get(r["id"])
        if key is None or name is None:
            print("skipping report for an unknown advertisement key")
            continue
        try:
            report = decrypt_report(r["payload"], key)
        except Exception as e:  # ruff: ignore[blind-except]
            print(f"skipping undecryptable report for {name}: {e}")
            continue
        # v2 no longer returns datePublished, so use the report's own timestamp.
        report |= {"created_at": report["tst"], "_type": "location"}
        reports.append((name, report))
    reports.sort(key=lambda r: r[1]["tst"])
    for name, report in reports:
        if report["tst"] > last_timestamps.get(name, 0):
            msg = mqttc.publish(MQTT_TOPIC_PREFIX + name, json.dumps(report), 2, retain=True)
            msg.wait_for_publish()
            print(f"Published {name} with tst {report['tst']}")
    mqttc.disconnect()
    mqttc.loop_stop()
    print("Disconnected from MQTT server")


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print = functools.partial(print, flush=True)  # ruff: ignore[builtin-variable-shadowing]
    print(f"Ownhaystack {VERSION}")

    retries = 0
    RETRY_WAITS = [5] * 5 + [10] * 3 + [30] * 3 + [60] * 3 + [5 * 60] * 3 + [10 * 60] * 3
    while True:
        try:
            main()
            retries = 0
            print(f"Sleeping for {REFRESH_INTERVAL}s...")
            time.sleep(REFRESH_INTERVAL)
        except Exception as e:  # ruff: ignore[blind-except]
            print(f"Encountered exception: {e}")
            traceback.print_exc()
            retries += 1
            seconds = RETRY_WAITS[min(retries, len(RETRY_WAITS) - 1)]
            print(f"Retrying #{retries} after {seconds} seconds")
            time.sleep(seconds)
