import pytest
from rest_framework import status
from django.urls import reverse

CHANGE_PASSWORD_URL = reverse("change-password")

@pytest.mark.django_db
def test_change_password_weak_password(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    payload = {
        "old_password": "Password123!",
        "new_password": "weak",
        "new_password_confirm": "weak",
    }

    response = api_client.post(CHANGE_PASSWORD_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "new_password" in response.data