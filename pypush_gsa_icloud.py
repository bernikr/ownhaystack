# This is a modified version of
# https://github.com/MatthewKuKanich/FindMyFlipper/blob/main/AirTagGeneration/cores/pypush_gsa_icloud.py
import base64
import hashlib
import hmac
import locale
import plistlib as plist
import uuid
from datetime import UTC, datetime
from getpass import getpass
from typing import Any, Literal, assert_never

import pbkdf2
import requests
import srp._pysrp as srp  # noqa: PLC2701
from Crypto.Hash import SHA256  # noqa: S413
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()


# Get a random public anisette server if none is specified
def get_anisette_url() -> str:
    print("getting random public anisette server")
    servers = requests.get("https://servers.sidestore.io/servers.json", timeout=5).json()["servers"]
    for server in servers:
        url = server["address"]
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == requests.codes.ok and r.json():
                return url
        except:  # noqa: E722, S110
            pass
    msg = "No anisette servers found"
    raise Exception(msg)


class AppleHeaders:
    def __init__(self, anisette_url: str | None) -> None:
        self.USER_ID = uuid.uuid4()
        self.DEVICE_ID = uuid.uuid4()
        if anisette_url:
            self.ANISETTE_URL = anisette_url
        else:
            self.ANISETTE_URL = get_anisette_url()

    def icloud_login_mobileme(
        self,
        username: str = "",
        password: str = "",
        second_factor: Literal["sms", "trusted_device"] = "sms",
    ) -> dict[str, Any]:
        if not username:
            username = getpass("Apple ID: ")
        if not password:
            password = getpass("Password: ")

        g: Any = self.gsa_authenticate(username, password, second_factor)
        pet = g["t"]["com.apple.gs.idms.pet"]["token"]
        adsid = g["adsid"]

        data = {
            "apple-id": username,
            "delegates": {"com.apple.mobileme": {}},
            "password": pet,
            "client-id": str(self.USER_ID),
        }
        data = plist.dumps(data)

        headers = {
            "X-Apple-ADSID": adsid,
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",  # noqa: E501
        }
        headers.update(self.generate_anisette_headers())

        r = requests.post(
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
            auth=(username, pet),
            data=data,
            headers=headers,
            verify=False,  # noqa: S501
            timeout=10,
        )

        return plist.loads(r.content)

    def gsa_authenticate(  # noqa: C901
        self,
        username: str,
        password: str,
        second_factor: Literal["sms", "trusted_device"] = "sms",
    ) -> dict[str, Any] | None:
        # Password is None as we'll provide it later
        usr = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a = usr.start_authentication()

        r = self.gsa_authenticated_request({"A2k": a, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
        if "sp" not in r:
            print("Authentication Failed. Check your Apple ID and password.")
            msg = "AuthenticationError"
            raise Exception(msg)
        if r["sp"] != "s2k" and r["sp"] != "s2k_fo":
            print(f"This implementation only supports s2k and s2k_fo. Server returned {r['sp']}")
            return None

        # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
        usr.p = self.encrypt_password(password, r["s"], r["i"], hex=r["sp"] == "s2k_fo")

        m = usr.process_challenge(r["s"], r["B"])

        # Make sure we processed the challenge correctly
        if m is None:
            print("Failed to process challenge")
            return None

        r = self.gsa_authenticated_request({"c": r["c"], "M1": m, "u": username, "o": "complete"})

        # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
        usr.verify_session(r["M2"])
        if not usr.authenticated():
            print("Failed to verify session")
            return None

        spd = self.decrypt_cbc(usr, r["spd"])
        # For some reason plistlib doesn't accept it without the header...
        PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""  # noqa: N806
        spd = plist.loads(PLISTHEADER + spd)

        if "au" in r["Status"] and r["Status"]["au"] in {
            "trustedDeviceSecondaryAuth",
            "secondaryAuth",
        }:
            print("2FA required, requesting code")
            # Replace bytes with strings
            for k, v in spd.items():
                if isinstance(v, bytes):
                    spd[k] = base64.b64encode(v).decode()
            if second_factor == "sms":
                self.sms_second_factor(spd["adsid"], spd["GsIdmsToken"])
            elif second_factor == "trusted_device":
                self.trusted_second_factor(spd["adsid"], spd["GsIdmsToken"])
            else:
                assert_never(second_factor)
        if "au" in r["Status"]:
            print(f"Unknown auth value {r['Status']['au']}")
            return None
        return spd

    def gsa_authenticated_request(self, parameters: dict[str, Any]) -> dict[str, Any]:
        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": self.generate_cpd()},
        }
        body["Request"].update(parameters)

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",  # noqa: E501
        }

        resp = requests.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plist.dumps(body),
            verify=False,  # noqa: S501
            timeout=5,
        )

        return plist.loads(resp.content)["Response"]

    def generate_cpd(self) -> dict[str, Any]:
        cpd = {
            # Many of these values are not strictly necessary, but may be tracked by Apple
            "bootstrap": True,  # All implementations set this to true
            "icscrec": True,  # Only AltServer sets this to true
            "pbe": False,  # All implementations explicitly set this to false
            "prkgen": True,  # I've also seen ckgen
            "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
        }

        cpd.update(self.generate_anisette_headers())
        return cpd

    def generate_anisette_headers(self) -> dict[str, Any]:
        print(f"querying {self.ANISETTE_URL} for an anisette server")
        h = requests.get(self.ANISETTE_URL, timeout=5).json()
        a = {"X-Apple-I-MD": h["X-Apple-I-MD"], "X-Apple-I-MD-M": h["X-Apple-I-MD-M"]}
        a.update(self.generate_meta_headers())
        return a

    def generate_meta_headers(self, serial: str = "0") -> dict[str, str]:
        return {
            "X-Apple-I-Client-Time": datetime.now(tz=UTC).replace(microsecond=0).isoformat() + "Z",
            "X-Apple-I-TimeZone": str(datetime.now(tz=UTC).astimezone().tzinfo),
            "loc": locale.getdefaultlocale()[0] or "en_US",
            "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
            "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
            "X-Apple-I-MD-LU": base64.b64encode(str(self.USER_ID).upper().encode()).decode(),
            "X-Mme-Device-Id": str(self.DEVICE_ID).upper(),
            "X-Apple-I-SRL-NO": serial,  # Serial number
        }

    def encrypt_password(self, password: str, salt: Any, iterations: int, *, hex: bool = False) -> bytes:  # noqa: A002, ANN401, PLR6301
        hash = hashlib.sha256(password.encode("utf-8"))  # noqa: A001
        p = hash.hexdigest() if hex else hash.digest()
        return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)  # type: ignore

    def create_session_key(self, usr: srp.User, name: str) -> bytes:  # noqa: PLR6301
        k = usr.get_session_key()
        if k is None:
            msg = "No session key"
            raise Exception(msg)
        return hmac.new(k, name.encode(), hashlib.sha256).digest()

    def decrypt_cbc(self, usr: srp.User, data: bytes) -> bytes:
        extra_data_key = self.create_session_key(usr, "extra data key:")
        extra_data_iv = self.create_session_key(usr, "extra data iv:")
        # Get only the first 16 bytes of the iv
        extra_data_iv = extra_data_iv[:16]

        # Decrypt with AES CBC
        cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        # Remove PKCS#7 padding
        padder = padding.PKCS7(128).unpadder()
        return padder.update(data) + padder.finalize()

    def trusted_second_factor(self, dsid: str, idms_token: str) -> None:
        identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",  # noqa: E501
        }

        headers.update(self.generate_anisette_headers())

        # This will trigger the 2FA prompt on trusted devices
        # We don't care about the response, it's just some HTML with a form for entering the code
        # Easier to just use a text prompt
        requests.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=headers,
            verify=False,  # noqa: S501
            timeout=10,
        )

        # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
        code = getpass("Enter 2FA code: ")
        headers["security-code"] = code

        # Send the 2FA code to Apple
        resp = requests.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=headers,
            verify=False,  # noqa: S501
            timeout=10,
        )
        if resp.ok:
            print("2FA successful")

    def sms_second_factor(self, dsid: str, idms_token: str) -> None:
        identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()
        headers = {
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",  # noqa: E501
        }

        headers.update(self.generate_anisette_headers())

        body = {"phoneNumber": {"id": 1}, "mode": "sms"}

        # This will send the 2FA code to the user's phone over SMS
        # We don't care about the response, it's just some HTML with a form for entering the code
        # Easier to just use a text prompt
        t = requests.put(
            "https://gsa.apple.com/auth/verify/phone/",
            json=body,
            headers=headers,
            verify=False,  # noqa: S501
            timeout=5,
        )
        if not t.ok:
            msg = "Error when requesting 2FA code"
            raise Exception(msg)
        # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
        code = input("Enter 2FA code: ")

        body["securityCode"] = {"code": code}

        # Send the 2FA code to Apple
        resp = requests.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body,
            headers=headers,
            verify=False,  # noqa: S501
            timeout=5,
        )
        if resp.ok:
            print("2FA successful")
