import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_expired_refresh_token(api_client, expired_refresh_token, active_user):
    url = reverse("logout")
    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = expired_refresh_token
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "error" in response.data or "detail" in response.data
