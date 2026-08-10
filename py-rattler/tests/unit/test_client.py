# type: ignore
from __future__ import annotations

import pytest

import rattler.networking.client as client_module
from rattler.networking import Client
from rattler.networking.middleware import (
    AuthenticationMiddleware,
    AzureMiddleware,
    GCSMiddleware,
    OciMiddleware,
    RetryMiddleware,
    S3Middleware,
)


def test_default_client_stack_includes_azure(monkeypatch) -> None:
    constructed: list[type] = []

    for name in (
        "RetryMiddleware",
        "AuthenticationMiddleware",
        "OciMiddleware",
        "GCSMiddleware",
        "AzureMiddleware",
        "S3Middleware",
    ):
        original = getattr(client_module, name)

        def record(*args, _original=original, **kwargs):
            constructed.append(_original)
            return _original(*args, **kwargs)

        monkeypatch.setattr(client_module, name, record)

    client = Client.default_client()

    assert isinstance(client, Client)
    for middleware in (
        RetryMiddleware,
        AuthenticationMiddleware,
        OciMiddleware,
        GCSMiddleware,
        AzureMiddleware,
        S3Middleware,
    ):
        assert middleware in constructed


def test_azure_before_authentication_is_rejected() -> None:
    # AzureMiddleware rewrites `az://` to `https://`, and AuthenticationMiddleware
    # skips anything that is not already http(s). Azure first would therefore hand
    # a stored blob-host credential to an ungranted container.
    with pytest.raises(ValueError, match="AzureMiddleware must come after AuthenticationMiddleware"):
        Client([AzureMiddleware(), AuthenticationMiddleware()])


def test_authentication_before_azure_is_accepted() -> None:
    assert isinstance(Client([AuthenticationMiddleware(), AzureMiddleware()]), Client)


def test_azure_alone_is_accepted() -> None:
    # Without AuthenticationMiddleware there is no credential to leak.
    assert isinstance(Client([AzureMiddleware()]), Client)
