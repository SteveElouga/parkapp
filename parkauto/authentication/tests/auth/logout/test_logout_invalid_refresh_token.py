import pytest
from django.urls import reverse
from rest_framework import status

LOGOUT_URL = reverse("logout")

@pytest.mark.django_db
def test_logout_invalid_refresh_token(api_client, active_user):

    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = "invalidtoken"

    response = api_client.post(LOGOUT_URL)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["error"] == "Invalid refresh token."
