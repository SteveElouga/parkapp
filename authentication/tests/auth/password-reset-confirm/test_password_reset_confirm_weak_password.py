import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_password_reset_confirm_weak_password(api_client, password_reset_token):
    url = reverse("password_reset_confirm")
    weak_password = "123"
    data = {
        "token": password_reset_token.token,
        "new_password": weak_password,
        "new_password_confirm": weak_password,
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "new_password" in response.data or "detail" in response.data