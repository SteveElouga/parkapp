import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta

@pytest.mark.django_db
def test_token_refresh_expired_token(api_client, active_user):
    url = reverse("token_refresh")
    refresh = RefreshToken.for_user(active_user)
    refresh.set_exp(lifetime=timedelta(seconds=-1))
    api_client.cookies["refresh_token"] = str(refresh)
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "refresh" in response.data or "detail" in response.data