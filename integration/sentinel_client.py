#!/usr/bin/env python3
"""
Sentinel HSM Gateway - Switching Application Integration Client
================================================================

Reference client that a switching / payment application uses to drive the
Sentinel HSM Gateway REST API. The call path is:

        switching app  ->  Sentinel Gateway API  ->  Thales payShield HSM

The gateway terminates the REST request, builds the Thales host command on
the wire, dispatches it to a healthy HSM node from the pool, and returns the
parsed response as JSON.

Two API surfaces are exposed and both are wrapped here:

  * Semantic API  (/api/v1/crypto/**, /api/v1/keys/**)
        Typed request bodies (keyId, pan, pinBlock, ...). Recommended for
        application code - the gateway owns the wire layout.

  * Raw API       (/thales/command/{CMD})
        Generic passthrough for any Thales command code. The JSON body is a
        flat map of HSM-native parameters. Use when you need a command that
        has no semantic endpoint yet, or to reproduce an exact host trace.

Auth: POST /api/v1/auth/login -> { "token": "<jwt>" }. The token is sent as
a Bearer header on every subsequent call.

Requires: Python 3.8+ and `requests` (pip install requests).

Usage:
    from sentinel_client import SentinelClient

    sc = SentinelClient("http://gateway-host:8090", "admin", "sentinel123")
    sc.login()
    print(sc.hsm_status())
    print(sc.encrypt(key_id="...", plaintext_hex="0011...", mode="00"))
    print(sc.raw("M6", {"keyType": "008", "keyScheme": "U", ...}))

Run as a script for a self-test against a running gateway:
    python3 sentinel_client.py --base http://localhost:8090 \
        --user admin --password sentinel123 --selftest
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("This client needs the 'requests' package: pip install requests\n")
    raise


class SentinelError(RuntimeError):
    """Raised when the gateway returns a non-2xx HTTP status or an HSM error code."""

    def __init__(self, message: str, *, status: Optional[int] = None,
                 payload: Optional[Any] = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class SentinelClient:
    """Thin, dependency-light wrapper over the Sentinel HSM Gateway REST API."""

    def __init__(self, base_url: str, loginname: str, password: str,
                 *, timeout: float = 30.0, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.loginname = loginname
        self.password = password
        self.timeout = timeout
        self.token: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = verify_tls

    # ----------------------------------------------------------------- auth
    def login(self) -> str:
        """Authenticate and cache the bearer token. Returns the token."""
        resp = self._session.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"loginname": self.loginname, "password": self.password},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise SentinelError(f"login failed: HTTP {resp.status_code}",
                                status=resp.status_code, payload=_safe_json(resp))
        body = resp.json()
        if not body.get("success") or not body.get("token"):
            raise SentinelError(f"login rejected: {body.get('reason', 'unknown')}",
                                payload=body)
        self.token = body["token"]
        return self.token

    def _headers(self) -> Dict[str, str]:
        if not self.token:
            raise SentinelError("not authenticated - call login() first")
        return {"Authorization": f"Bearer {self.token}"}

    # -------------------------------------------------------------- transport
    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}{path}", json=body,
            headers=self._headers(), timeout=self.timeout,
        )
        return self._unwrap(resp, path)

    def _get(self, path: str) -> Dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}{path}",
            headers=self._headers(), timeout=self.timeout,
        )
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: "requests.Response", path: str) -> Dict[str, Any]:
        if resp.status_code == 404:
            raise SentinelError(f"{path}: not found (command/endpoint not registered)",
                                status=404)
        if resp.status_code == 401:
            raise SentinelError(f"{path}: unauthorized (token expired? re-login)",
                                status=401)
        if resp.status_code == 403:
            raise SentinelError(f"{path}: forbidden (missing operation authority)",
                                status=403)
        data = _safe_json(resp)
        if resp.status_code >= 400:
            raise SentinelError(f"{path}: HTTP {resp.status_code}",
                                status=resp.status_code, payload=data)
        # Thales error codes: "00" == success. Surface anything else.
        if isinstance(data, dict):
            err = data.get("errorCode") or data.get("errCode")
            if err not in (None, "00", "0", "0000"):
                raise SentinelError(
                    f"{path}: HSM error code {err} ({data.get('errorMessage', '')})".strip(),
                    status=resp.status_code, payload=data,
                )
        return data

    # --------------------------------------------------------------- raw API
    def raw(self, cmd: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute any Thales command by its 2-char code via /thales/command/{CMD}.
        `params` is a flat map of HSM-native fields - see docs/COMMAND_GUIDE.md.
        Requires the OP_RAW_CMD authority on the logged-in user.
        """
        return self._post(f"/thales/command/{cmd.upper()}", params or {})

    # ----------------------------------------------------------- semantic API
    # Keys
    def generate_symmetric_key(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/keys/symmetric", body)

    def generate_rsa_key(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/keys/rsa", body)

    def import_zmk_wrapped(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/keys/import-zmk-wrapped", body)

    def import_rsa_wrapped(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/keys/import-rsa-wrapped", body)

    def export_key(self, key_id: str, **body: Any) -> Dict[str, Any]:
        return self._post(f"/api/v1/keys/{key_id}/export", body)

    def list_keys(self) -> Dict[str, Any]:
        return self._get("/api/v1/keys")

    # Crypto - data
    def encrypt(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/encrypt", body)

    def decrypt(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/decrypt", body)

    def random(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/random", body)

    # Crypto - PIN
    def pin_translate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/translate", body)

    def pin_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/verify", body)

    def pin_generate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/generate", body)

    def pin_pvv(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/pvv", body)

    def pin_ibm_offset(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/ibm-offset", body)

    def pin_decrypt(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/decrypt", body)

    def pin_to_lmk(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/to-lmk", body)

    def pin_from_lmk(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/pin/from-lmk", body)

    # Crypto - card verification values
    def cvv_generate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/cvv/generate", body)

    def cvv_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/cvv/verify", body)

    def dcvv_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/dcvv/verify", body)

    def csc_calculate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/csc/calculate", body)

    def csc_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/csc/verify", body)

    # Crypto - EMV
    def arqc(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/arqc", body)

    def arqc_emv4(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/arqc/emv4", body)

    # Crypto - MAC / HMAC
    def mac_generate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/mac/generate", body)

    def mac_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/mac/verify", body)

    def hmac_generate(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/hmac/generate", body)

    def hmac_verify(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/hmac/verify", body)

    # Diagnostics
    def hsm_status(self) -> Dict[str, Any]:
        return self._get("/api/v1/crypto/hsm/status")

    def hsm_echo(self, **body: Any) -> Dict[str, Any]:
        return self._post("/api/v1/crypto/hsm/echo", body)


def _safe_json(resp: "requests.Response") -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


# --------------------------------------------------------------------- script
def _selftest(sc: SentinelClient) -> int:
    print("login ...")
    sc.login()
    print("  token acquired")
    print("hsm/status ...")
    print("  " + json.dumps(sc.hsm_status()))
    print("hsm/echo ...")
    print("  " + json.dumps(sc.hsm_echo(data="DEADBEEF")))
    print("OK")
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Sentinel HSM Gateway client")
    p.add_argument("--base", default="http://localhost:8090", help="gateway base URL")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="sentinel123")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--selftest", action="store_true", help="login + status + echo")
    p.add_argument("--raw", metavar="CMD", help="execute a raw Thales command code")
    p.add_argument("--params", metavar="JSON", default="{}",
                   help="JSON params for --raw")
    args = p.parse_args(argv)

    sc = SentinelClient(args.base, args.user, args.password,
                        verify_tls=not args.insecure)
    try:
        if args.selftest:
            return _selftest(sc)
        sc.login()
        if args.raw:
            params = json.loads(args.params)
            print(json.dumps(sc.raw(args.raw, params), indent=2))
            return 0
        p.print_help()
        return 0
    except SentinelError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        if e.payload is not None:
            sys.stderr.write(json.dumps(e.payload, indent=2) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
