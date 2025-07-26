import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch

LOGOUT_URL = reverse("logout")

@pytest.mark.django_db
def test_logout_unexpected_exception(api_client, active_user):

    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = str(RefreshToken.for_user(active_user))

    # Mock patch pour forcer une exception non prévue lors du blacklist
    with patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist", side_effect=Exception("Boom")):
        response = api_client.post(LOGOUT_URL)

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.data["error"] == "Internal server error."
