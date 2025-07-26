import pytest
from rest_framework import status
from django.urls import reverse

PASSWORD_RESET_CONFIRM_URL = reverse("password_reset_confirm")

@pytest.mark.django_db
def test_password_reset_confirm_mismatch_password(api_client, valid_reset_token):
    payload = {
        "token": str(valid_reset_token.token),
        "new_password": "Password123!",
        "new_password_confirm": "DifferentPassword123!",
    }

    response = api_client.post(PASSWORD_RESET_CONFIRM_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "new_password_confirm" in response.data
