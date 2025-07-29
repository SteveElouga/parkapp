import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_confirm_reuse_token(
    api_client, password_reset_token, strong_password, active_user
):
    url = reverse("password_reset_confirm")
    data = {
        "token": password_reset_token.token,
        "new_password": strong_password,
        "new_password_confirm": strong_password,
    }
    # Premier reset : OK
    response1 = api_client.post(url, data, format="json")
    assert response1.status_code == status.HTTP_200_OK
    # Deuxième tentative avec le même token : doit échouer
    response2 = api_client.post(url, data, format="json")
    assert response2.status_code == status.HTTP_404_NOT_FOUND
