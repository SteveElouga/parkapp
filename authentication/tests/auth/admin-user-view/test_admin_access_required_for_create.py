import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_admin_access_required_for_create(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("users-list")
    data = {
        "email": "test2@example.com",
        "password": "Testpass123!",
        "first_name": "Test",
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_403_FORBIDDEN
