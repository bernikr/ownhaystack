# ruff: noqa: PT009, PT027

import unittest

from findmy_reports import build_fetch_request, parse_fetch_response


class BuildFetchRequestTests(unittest.TestCase):
    def test_one_fetch_object_per_key(self) -> None:
        request = build_fetch_request(["key-a", "key-b"], 1_000, 2_000)

        self.assertEqual(request["clientContext"]["clientBundleIdentifier"], "com.apple.icloud.searchpartyuseragent")
        self.assertEqual(len(request["fetch"]), 2)
        self.assertEqual([item["primaryIds"] for item in request["fetch"]], [["key-a"], ["key-b"]])
        for item in request["fetch"]:
            self.assertEqual(item["startDatePrimary"], 1_000)
            self.assertEqual(item["startDateSecondary"], 1_000)
            self.assertEqual(item["startDate"], 1_000)
            self.assertEqual(item["endDate"], 2_000)
            self.assertEqual(item["ownedDeviceIds"], [])

    def test_empty_key_list(self) -> None:
        self.assertEqual(build_fetch_request([], 1_000, 2_000)["fetch"], [])


class ParseFetchResponseTests(unittest.TestCase):
    def test_string_location_info(self) -> None:
        response = {
            "acsnLocations": {
                "statusCode": "200",
                "locationPayload": [
                    {"id": "key-a", "locationInfo": ["payload-1", "payload-2"]},
                    {"id": "key-b", "locationInfo": ["payload-3"]},
                ],
            },
        }

        self.assertEqual(
            parse_fetch_response(response),
            [
                {"id": "key-a", "payload": "payload-1"},
                {"id": "key-a", "payload": "payload-2"},
                {"id": "key-b", "payload": "payload-3"},
            ],
        )

    def test_dict_location_info_uses_location_field(self) -> None:
        response = {
            "acsnLocations": {
                "statusCode": "200",
                "locationPayload": [
                    {"id": "key-a", "locationInfo": [{"location": "payload-1", "locationTs": 123}]},
                ],
            },
        }

        self.assertEqual(parse_fetch_response(response), [{"id": "key-a", "payload": "payload-1"}])

    def test_unreadable_location_info_is_skipped(self) -> None:
        response = {
            "acsnLocations": {
                "statusCode": "200",
                "locationPayload": [
                    {
                        "id": "key-a",
                        "locationInfo": [{"unexpected": "shape"}, "", "payload-1"],
                    },
                ],
            },
        }

        self.assertEqual(parse_fetch_response(response), [{"id": "key-a", "payload": "payload-1"}])

    def test_empty_location_payload(self) -> None:
        self.assertEqual(parse_fetch_response({"acsnLocations": {"statusCode": "200", "locationPayload": []}}), [])

    def test_integer_status_code_is_accepted(self) -> None:
        response = {"acsnLocations": {"statusCode": 200, "locationPayload": []}}

        self.assertEqual(parse_fetch_response(response), [])

    def test_missing_acsn_locations_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_fetch_response({"statusCode": "200"})

    def test_non_ok_status_raises(self) -> None:
        response = {"acsnLocations": {"statusCode": "401", "locationPayload": []}}

        with self.assertRaises(ValueError):
            parse_fetch_response(response)

    def test_missing_location_payload_is_empty(self) -> None:
        self.assertEqual(parse_fetch_response({"acsnLocations": {"statusCode": "200"}}), [])

    def test_non_object_response_raises(self) -> None:
        with self.assertRaises(TypeError):
            parse_fetch_response([])

    def test_non_object_acsn_locations_raises(self) -> None:
        with self.assertRaises(TypeError):
            parse_fetch_response({"acsnLocations": []})


if __name__ == "__main__":
    unittest.main()
