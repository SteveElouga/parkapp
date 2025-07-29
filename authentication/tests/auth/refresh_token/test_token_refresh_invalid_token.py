import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_token_refresh_invalid_token(api_client):
    url = reverse("token_refresh")
    api_client.cookies["refresh_token"] = "not.a.jwt"
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "refresh" in response.data or "detail" in response.data
