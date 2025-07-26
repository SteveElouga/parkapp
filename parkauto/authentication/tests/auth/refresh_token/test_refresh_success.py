import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch
from rest_framework_simplejwt.exceptions import TokenError

REFRESH_URL = reverse("token_refresh")


@pytest.mark.django_db
def test_refresh_success(api_client, valid_refresh_token):
    """Test un refresh token valide retourne un nouveau access token et cookie."""
    # valid_refresh_token : fixture qui génère un refresh token valide

    # On simule le cookie avec refresh_token
    api_client.cookies["refresh_token"] = valid_refresh_token

    # On simule aussi le header CSRF (sinon Forbidden)
    response = api_client.post(
        REFRESH_URL,
        HTTP_X_CSRFTOKEN="valid-csrf-token"
    )

    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh_token" in response.cookies
    cookie = response.cookies["refresh_token"]
    assert cookie["httponly"] is True
    assert cookie["secure"] is True or cookie["secure"] == ""
    # selon ton environnement, secure peut être '' en dev