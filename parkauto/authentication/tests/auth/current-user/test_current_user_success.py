import pytest
from rest_framework import status
from django.urls import reverse

USER_ME_URL = reverse("user-me")

@pytest.mark.django_db
def test_get_current_user_success(api_client, active_user):
    api_client.force_authenticate(user=active_user)

    response = api_client.get(USER_ME_URL)

    assert response.status_code == status.HTTP_200_OK
    assert "email" in response.data
    assert response.data["email"] == active_user.email
