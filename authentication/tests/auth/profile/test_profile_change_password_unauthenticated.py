import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_change_password_unauthenticated(api_client):
    url = reverse("change-password")
    data = {
        "old_password": "anything",
        "new_password": "Anything123!",
        "confirm_new_password": "Anything123!"
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED