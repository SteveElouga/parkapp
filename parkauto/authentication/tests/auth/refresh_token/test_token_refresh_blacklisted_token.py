import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_token_refresh_blacklisted_token(api_client, blacklisted_refresh_token):
    url = reverse("token_refresh")
    api_client.cookies["refresh_token"] = blacklisted_refresh_token
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "refresh" in response.data or "detail" in response.data