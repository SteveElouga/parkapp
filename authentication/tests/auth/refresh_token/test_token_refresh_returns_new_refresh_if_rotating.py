import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

@pytest.mark.django_db
def test_token_refresh_returns_new_refresh_if_rotating(api_client, active_user):
    url = reverse("token_refresh")
    refresh = str(RefreshToken.for_user(active_user))
    api_client.cookies["refresh_token"] = refresh
    response = api_client.post(url, {}, format="json")
    if "refresh" in response.data:
        assert response.data["refresh"] != refresh