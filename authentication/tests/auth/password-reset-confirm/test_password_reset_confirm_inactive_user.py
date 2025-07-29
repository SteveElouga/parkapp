import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_confirm_inactive_user(
    api_client, inactive_valid_uid_token, strong_password
):
    url = reverse("password_reset_confirm")
    data = {
        "token": inactive_valid_uid_token.token,
        "new_password": strong_password,
        "new_password_confirm": strong_password,
    }
    response = api_client.post(url, data, format="json")
    # Le comportement peut varier selon l'implémentation
    assert response.status_code == status.HTTP_400_BAD_REQUEST
