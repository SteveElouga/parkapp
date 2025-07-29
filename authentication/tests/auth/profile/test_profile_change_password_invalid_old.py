import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_change_password_invalid_old(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("change-password")
    data = {
        "old_password": "wrongpassword",
        "new_password": "NewStrongPassword123!",
        "confirm_new_password": "NewStrongPassword123!"
    }
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "old_password" in response.data 