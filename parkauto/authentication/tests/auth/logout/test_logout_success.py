import pytest
from django.urls import reverse
from rest_framework import status

LOGOUT_URL = reverse("logout")

@pytest.mark.django_db
def test_logout_success(api_client, valid_refresh_token, active_user):

    # Authentification du client
    api_client.force_authenticate(user=active_user)
    # Injection du cookie refresh_token
    api_client.cookies["refresh_token"] = valid_refresh_token

    response = api_client.post(LOGOUT_URL)

    assert response.status_code == status.HTTP_205_RESET_CONTENT
    assert "refresh_token" not in response.cookies or response.cookies["refresh_token"].value == ""
    assert response.data["message"] == "Logout successful."
