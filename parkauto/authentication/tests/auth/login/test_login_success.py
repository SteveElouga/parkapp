import pytest
from django.urls import reverse
from rest_framework import status

from authentication.models import User

@pytest.mark.django_db
def test_login_success(api_client, user_data):
    url = reverse("login")

    user_data_filtered = {
        key: value for key, value in user_data.items()
        if key != "password_confirm"
    }

    user = User.objects.create_user(**user_data_filtered)
    user.is_active = True
    user.save()

    response = api_client.post(url, user_data_filtered, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.data
    assert response.data["message"] == "Login successful."
    assert "user" in response.data

    # Vérifier que le cookie refresh est bien présent
    cookies = response.cookies
    assert "refresh_token" in cookies
    assert cookies["refresh_token"]["httponly"] is True
