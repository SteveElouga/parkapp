import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken

@pytest.mark.django_db
def test_token_refresh_with_access_token_instead(api_client, active_user):
    url = reverse("token_refresh")
    access = str(AccessToken.for_user(active_user))
    api_client.cookies["refresh_token"] = access
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "refresh" in response.data or "detail" in response.data