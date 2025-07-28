import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_token_refresh_missing_cookie(api_client):
    url = reverse("token_refresh")
    response = api_client.post(url, {}, format="json")
    assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
    assert "refresh" in response.data or "detail" in response.data