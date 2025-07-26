import pytest
from django.urls import reverse
from rest_framework import status

from authentication.models import User

@pytest.mark.django_db
def test_login_inactive_account(api_client, user_data):
    url_login = reverse("login")

    user_data_filtered = {
        key: value for key, value in user_data.items()
        if key != "password_confirm"
    }

    user = User.objects.create_user(**user_data_filtered)
    user.is_active = False
    user.save()

    response_login = api_client.post(url_login, user_data_filtered, format="json")

    assert response_login.status_code == status.HTTP_401_UNAUTHORIZED
    assert response_login.data["detail"] == "No active account found with the given credentials"
