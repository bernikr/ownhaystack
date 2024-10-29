import datetime
import json
import os

import requests
from dotenv import load_dotenv

from pypush_gsa_icloud import (
    AppleHeaders,
)

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


def main():
    res = download_tag_data([""])
    print(res)
    pass


if __name__ == "__main__":
    main()
