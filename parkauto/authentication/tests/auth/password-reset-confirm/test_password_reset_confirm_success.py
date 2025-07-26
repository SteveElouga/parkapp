import pytest
from rest_framework import status
from django.utils import timezone
from unittest.mock import patch
from django.urls import reverse

PASSWORD_RESET_CONFIRM_URL = reverse("password_reset_confirm")

@pytest.mark.django_db
def test_password_reset_confirm_success(api_client, active_user, valid_reset_token):
    payload = {
        "token": str(valid_reset_token.token),
        "new_password": "StrongPass123!",
        "new_password_confirm": "StrongPass123!",
    }

    with patch("authentication.views.send_confirmation_reset_password_email") as mocked_email:
        response = api_client.post(PASSWORD_RESET_CONFIRM_URL, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert response.data["detail"] == "Password has been reset successfully."
    mocked_email.assert_called_once()
    active_user.refresh_from_db()
    assert active_user.check_password("StrongPass123!")
