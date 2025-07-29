import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_confirm_passwords_do_not_match(
    api_client, password_reset_token
):
    url = reverse("password_reset_confirm")
    data = {
        "token": password_reset_token.token,
        "new_password": "StrongPassword123!",
        "new_password_confirm": "OtherPassword123!",
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        "new_password" in response.data
        or "new_password_confirm" in response.data
        or "detail" in response.data
    )
