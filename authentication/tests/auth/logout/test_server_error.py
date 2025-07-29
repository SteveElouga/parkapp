import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch
from rest_framework_simplejwt.tokens import RefreshToken

@pytest.mark.django_db
def test_server_error(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = str(RefreshToken.for_user(active_user))

    # Mock patch pour forcer une exception non prévue lors du blacklist
    with patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist", side_effect=Exception("Boom")):
        response = api_client.post(reverse("logout"))

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.data["error"] == "Internal server error."