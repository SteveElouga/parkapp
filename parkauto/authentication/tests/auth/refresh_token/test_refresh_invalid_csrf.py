import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch
from rest_framework_simplejwt.exceptions import TokenError

REFRESH_URL = reverse("token_refresh")


@pytest.mark.django_db
def test_refresh_invalid_csrf(api_client, valid_refresh_token):
    api_client.cookies["refresh_token"] = 'dc'

    # Header CSRF invalide
    response = api_client.post(
        REFRESH_URL,
        HTTP_X_CSRFTOKEN="wrong-csrf-token"
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
