"""Request and response helpers for Apple's Find My v2 fetch API."""

from typing import Any

FINDMY_FETCH_URL = "https://gateway.icloud.com/findmyservice/v2/fetch"
FINDMY_CLIENT_BUNDLE_IDENTIFIER = "com.apple.icloud.searchpartyuseragent"

_STATUS_OK = "200"


def build_fetch_request(tag_ids: list[str], start_ms: int, end_ms: int) -> dict[str, Any]:
    """Build a v2 fetch request body with one fetch object per advertisement key.

    Returns:
        The JSON-serializable request body.
    """
    return {
        "clientContext": {
            "policy": "foregroundClient",
            "clientBundleIdentifier": FINDMY_CLIENT_BUNDLE_IDENTIFIER,
        },
        # One fetch object per key: Apple returns one locationPayload slot per fetch object.
        # Batching several keys into a single primaryIds array makes Apple return reports
        # for only one of them, so keep exactly one key in each object.
        "fetch": [
            {
                "primaryIds": [tag_id],
                "keyType": 1,
                "endDate": end_ms,
                "ownedDeviceIds": [],
                "startDateSecondary": start_ms,
                "startDatePrimary": start_ms,
                "startDate": start_ms,
            }
            for tag_id in tag_ids
        ],
    }


def parse_fetch_response(response: object) -> list[dict[str, str]]:
    """Normalize a v2 fetch response into the ``{"id", "payload"}`` records used by main.py.

    Returns:
        A flat list of records with the hashed advertisement key and encrypted payload.
    """
    acsn_locations = _get_acsn_locations(response)
    _raise_for_status(acsn_locations)
    location_payload = _get_location_payload(acsn_locations)

    reports: list[dict[str, str]] = []
    for entry in location_payload:
        reports.extend(_reports_from_entry(entry))
    return reports


def _get_acsn_locations(response: object) -> dict[str, Any]:
    if not isinstance(response, dict):
        msg = "Unexpected FindMy response: expected a JSON object"
        raise TypeError(msg)

    acsn_locations = response.get("acsnLocations")
    if acsn_locations is None:
        msg = "FindMy response is missing acsnLocations"
        raise ValueError(msg)
    if not isinstance(acsn_locations, dict):
        msg = "Unexpected FindMy response: acsnLocations is not an object"
        raise TypeError(msg)
    return acsn_locations


def _raise_for_status(acsn_locations: dict[str, Any]) -> None:
    status = acsn_locations.get("statusCode", _STATUS_OK)
    if str(status) != _STATUS_OK:
        msg = f"FindMy response reported status {status}"
        raise ValueError(msg)


def _get_location_payload(acsn_locations: dict[str, Any]) -> list[Any]:
    location_payload = acsn_locations.get("locationPayload", [])
    if not isinstance(location_payload, list):
        msg = "Unexpected FindMy response: locationPayload is not a list"
        raise TypeError(msg)
    return location_payload


def _reports_from_entry(entry: object) -> list[dict[str, str]]:
    if not isinstance(entry, dict):
        print("skipping malformed FindMy location payload entry")
        return []

    key_id = entry.get("id")
    if not isinstance(key_id, str) or not key_id:
        print("skipping FindMy location payload entry without a key id")
        return []

    location_info = entry.get("locationInfo", [])
    if not isinstance(location_info, list):
        print(f"skipping FindMy location info for key {key_id[:8]}: unexpected format")
        return []

    reports: list[dict[str, str]] = []
    for item in location_info:
        payload = _payload_from_location_info(item)
        if payload is None:
            print(f"skipping unreadable FindMy report for key {key_id[:8]}")
            continue
        reports.append({"id": key_id, "payload": payload})
    return reports


def _payload_from_location_info(location_info: object) -> str | None:
    # acsnLocations.locationInfo normally contains base64 payload strings. Be defensive
    # about the dict form used by ownedDeviceLocations, where the payload is under "location".
    if isinstance(location_info, str):
        return location_info or None
    if isinstance(location_info, dict):
        payload = location_info.get("location")
        if isinstance(payload, str) and payload:
            return payload
    return None
