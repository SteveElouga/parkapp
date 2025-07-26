import pytest
from rest_framework import status
import uuid
from django.urls import reverse

PASSWORD_RESET_CONFIRM_URL = reverse("password_reset_confirm")

@pytest.mark.django_db
def test_password_reset_confirm_token_not_found(api_client):
    payload = {
        "token": str(uuid.uuid4()),
        "new_password": "StrongPassword123!",
        "new_password_confirm": "StrongPassword123!",
    }

    response = api_client.post(PASSWORD_RESET_CONFIRM_URL, payload, format="json")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.data["detail"] == "Reset token not found."
