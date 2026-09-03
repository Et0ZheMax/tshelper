from __future__ import annotations

import json
import unittest

from pgpy import PGPMessage

from adhelper.services.yopass import YopassClient, YopassError


class _Response:
    def __init__(self, data: dict[str, str]) -> None:
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.data).encode("utf-8")


class YopassClientTests(unittest.TestCase):
    def test_secret_is_encrypted_before_request(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return _Response({"message": "safe-id"})

        result = YopassClient("https://yopass.example.test", opener=opener).create_secret(
            "Логин: TEST\\user\nПароль: Demonstration-password!"
        )

        self.assertNotIn("Demonstration-password!", captured["body"]["message"])
        self.assertTrue(captured["body"]["message"].startswith("-----BEGIN PGP MESSAGE-----"))
        self.assertEqual(captured["body"]["expiration"], 604800)
        self.assertTrue(captured["body"]["one_time"])
        self.assertTrue(result.url.startswith("https://yopass.example.test/#/s/safe-id/"))
        PGPMessage.from_blob(captured["body"]["message"])

    def test_http_is_rejected(self) -> None:
        with self.assertRaisesRegex(YopassError, "HTTPS"):
            YopassClient("http://example.test").create_secret("test")


if __name__ == "__main__":
    unittest.main()
