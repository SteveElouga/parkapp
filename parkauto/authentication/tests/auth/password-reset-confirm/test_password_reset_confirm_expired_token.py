import pytest
from rest_framework import status
from django.utils import timezone
from django.urls import reverse

PASSWORD_RESET_CONFIRM_URL = reverse("password_reset_confirm")

@pytest.mark.django_db
def test_password_reset_confirm_expired_token(api_client, valid_reset_token):
    valid_reset_token.created_at = timezone.now() - timezone.timedelta(hours=2)
    valid_reset_token.save()

    payload = {
        "token": str(valid_reset_token.token),
        "new_password": "NewPassword123!",
        "new_password_confirm": "NewPassword123!",
    }

    response = api_client.post(PASSWORD_RESET_CONFIRM_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["detail"] == "Reset token has expired."
