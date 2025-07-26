import pytest
from rest_framework import status
from django.urls import reverse

CHANGE_PASSWORD_URL = reverse("change-password")

@pytest.mark.django_db
def test_change_password_incorrect_old_password(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    payload = {
        "old_password": "WrongPassword!",
        "new_password": "NewPassword123!",
        "confirm_new_password": "NewPassword123!",
    }

    response = api_client.post(CHANGE_PASSWORD_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "old_password" in response.data