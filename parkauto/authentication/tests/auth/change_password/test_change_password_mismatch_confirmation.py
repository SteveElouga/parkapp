import pytest
from rest_framework import status
from django.urls import reverse

CHANGE_PASSWORD_URL = reverse("change-password")

@pytest.mark.django_db
def test_change_password_mismatch_confirmation(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    payload = {
        "old_password": "AminaSecure456#",
        "new_password": "NewPassword123!",
        "confirm_new_password": "DifferentPassword123!",
    }

    response = api_client.post(CHANGE_PASSWORD_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["confirm_new_password"] == ["The passwords do not match."]