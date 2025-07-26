import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from unittest.mock import patch

LOGOUT_URL = reverse("logout")

@pytest.mark.django_db
def test_logout_no_refresh_token(api_client, active_user):
    api_client.force_authenticate(user=active_user)

    response = api_client.post(LOGOUT_URL)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["error"] == "No refresh token found."