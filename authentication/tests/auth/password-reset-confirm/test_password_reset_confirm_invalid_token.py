import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_confirm_invalid_token(api_client, strong_password):
    url = reverse("password_reset_confirm")
    data = {
        "token": "invalid-token",
        "new_password": strong_password,
        "new_password_confirm": strong_password,
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "token" in response.data
