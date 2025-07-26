import pytest
from rest_framework import status
from django.urls import reverse

CHANGE_PASSWORD_URL = reverse("change-password")

@pytest.mark.django_db
def test_change_password_unauthenticated(api_client):
    payload = {
        "old_password": "Password123!",
        "new_password": "NewPassword123!",
        "new_password_confirm": "NewPassword123!",
    }

    response = api_client.post(CHANGE_PASSWORD_URL, payload, format="json")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data