"""Encrypted httpx transports for AI APIs.

Extends tng.Transport with Cohere-specific defaults (ITA passport and
builtin background-check attestation, header forwarding, and model-name
header promotion from JSON request bodies via TNG's body_field_headers
config).
"""

from __future__ import annotations

import copy
from typing import Optional

import cohere_tng as tng

_DEFAULT_DIRECT_FORWARD: list = [
    {"http_path": r"^/v1/models(?:/[^/]+)?$"},
]

_DEFAULT_FORWARD_HEADERS: list = ["authorization"]

_DEFAULT_BODY_FIELD_HEADERS: list = [
    {"field_name": "model", "header_name": "x-gateway-model-name"},
]

_DEFAULT_VERIFY: list = [
    {
        "model": "passport",
        "as_provider": "ita",
        "ita_jwks_addr": "https://portal.trustauthority.intel.com",
        "policy_ids": ["cbeedffa-e224-4664-b6b4-573fcd4133d3"],
    },
    {
        "model": "background_check",
        "as_provider": "coco_builtin",
        "policy_ids": ["trustee_policy"],
        "required_tee_classes": ["cpu", "gpu"],
        "policy_source": {
            "url": "https://github.com/cohere-ai/integritee/releases/latest/download",
            "provenance": {
                "repo": "cohere-ai/integritee",
                "signer_workflow": ".github/workflows/release-policy.yaml",
                "source_ref": "refs/heads/main",
                "predicate_type": "https://cohere.com/attestation-policy/v1",
                "environment": "release",
            },
        },
        "verifier_config": {"nvidia_verifier": {"type": "remote"}},
    },
]

_UNSET = object()


def _apply_ohttp_defaults(ohttp: Optional[dict]) -> dict:
    ohttp = dict(ohttp) if ohttp else {}
    ohttp.setdefault("direct_forward", copy.deepcopy(_DEFAULT_DIRECT_FORWARD))
    ohttp.setdefault("forward_headers", list(_DEFAULT_FORWARD_HEADERS))
    ohttp.setdefault("body_field_headers", copy.deepcopy(_DEFAULT_BODY_FIELD_HEADERS))
    return ohttp


class Transport(tng.Transport):
    def __init__(
        self,
        *,
        verify: Optional[tng.VerifyConfig] = _UNSET,
        ohttp: Optional[dict] = None,
    ):
        if verify is _UNSET:
            verify = copy.deepcopy(_DEFAULT_VERIFY)
        super().__init__(verify=verify, ohttp=_apply_ohttp_defaults(ohttp))


class AsyncTransport(tng.AsyncTransport):
    def __init__(
        self,
        *,
        verify: Optional[tng.VerifyConfig] = _UNSET,
        ohttp: Optional[dict] = None,
    ):
        if verify is _UNSET:
            verify = copy.deepcopy(_DEFAULT_VERIFY)
        super().__init__(verify=verify, ohttp=_apply_ohttp_defaults(ohttp))
