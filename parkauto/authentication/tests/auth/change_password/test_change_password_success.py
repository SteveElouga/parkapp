import pytest
from unittest.mock import patch
from rest_framework import status
from django.urls import reverse

CHANGE_PASSWORD_URL = reverse("change-password")


@pytest.mark.django_db
def test_change_password_success(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    payload = {
        "old_password": "AminaSecure456#",
        "new_password": "NewPassword123!",
        "confirm_new_password": "NewPassword123!",
    }

    with patch("authentication.views.send_password_change_email") as mocked_email:
        response = api_client.post(CHANGE_PASSWORD_URL, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert response.data["detail"] == "Password changed successfully."
    mocked_email.assert_called_once_with(active_user)
