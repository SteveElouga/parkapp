import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.mark.django_db
def test_blacklisted_after_use_if_rotating(api_client, active_user):
    url = reverse("token_refresh")
    refresh = str(RefreshToken.for_user(active_user))
    api_client.cookies["refresh_token"] = refresh
    api_client.post(url, {}, format="json")
    # Réutilise le même refresh token
    api_client.cookies["refresh_token"] = refresh
    response2 = api_client.post(url, {}, format="json")
    assert response2.status_code == status.HTTP_401_UNAUTHORIZED
