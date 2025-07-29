import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_confirm_success(
    api_client, password_reset_token, strong_password, active_user
):
    url = reverse("password_reset_confirm")
    data = {
        "token": password_reset_token.token,
        "new_password": strong_password,
        "new_password_confirm": strong_password,
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_200_OK
    # Vérifie que le mot de passe a réellement changé
    active_user.refresh_from_db()
    assert active_user.check_password(strong_password)
