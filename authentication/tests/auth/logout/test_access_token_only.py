import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

@pytest.mark.django_db
def test_access_token_only(api_client, active_user):
    url = reverse("logout")
    api_client.force_authenticate(user=active_user)
    refresh_token = RefreshToken.for_user(active_user)
    refresh_token.access_token
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "error" in response.data or "detail" in response.data