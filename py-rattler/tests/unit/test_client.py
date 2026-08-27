# type: ignore
from __future__ import annotations

import pytest

from rattler.networking import Client
from rattler.networking.middleware import AuthenticationMiddleware, AzureMiddleware


def test_azure_before_authentication_is_rejected() -> None:
    with pytest.raises(ValueError, match="AzureMiddleware must come after AuthenticationMiddleware"):
        Client([AzureMiddleware(), AuthenticationMiddleware()])


def test_authentication_before_azure_is_accepted() -> None:
    assert isinstance(Client([AuthenticationMiddleware(), AzureMiddleware()]), Client)


def test_azure_alone_is_accepted() -> None:
    # Without AuthenticationMiddleware there is no credential to leak.
    assert isinstance(Client([AzureMiddleware()]), Client)
