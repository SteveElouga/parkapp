import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.mark.django_db
def test_token_refresh_wrong_user_refresh_token(api_client, user):
    url = reverse("token_refresh")
    refresh = str(RefreshToken.for_user(user))
    api_client.cookies["refresh_token"] = refresh
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "refresh" in response.data or "detail" in response.data
