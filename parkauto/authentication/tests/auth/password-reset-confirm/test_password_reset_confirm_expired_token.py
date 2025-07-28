import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_password_reset_confirm_expired_token(api_client, expired_refresh_token, strong_password):
    url = reverse("password_reset_confirm")
    data = {
        "token": expired_refresh_token,
        "new_password": strong_password,
        "new_password_confirm": strong_password,
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
    assert "token" in response.data or "detail" in response.data