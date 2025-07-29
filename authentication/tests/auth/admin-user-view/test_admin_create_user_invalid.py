import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_create_user_invalid(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-list")
    data = {
        "email": "invalid",  # Invalid email
        "password": "123",   # Too short/weak
        "password_confirm": "123",
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data or "password" in response.data