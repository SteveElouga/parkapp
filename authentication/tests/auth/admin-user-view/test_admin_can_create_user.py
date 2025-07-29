import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_admin_can_create_user(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-list")
    data = {
        "email": "newuser@example.com",
        "password": "Testpass123!",
        "password_confirm": "Testpass123!",
        "first_name": "New",
        "last_name": "User",
    }
    response = api_client.post(url, data)
    print("Response data:", response.data)  # Debugging line to check response content
    assert response.status_code == status.HTTP_201_CREATED
    assert "successfully" in response.data.get("message", "")
