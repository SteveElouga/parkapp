import pytest
from django.urls import reverse
from rest_framework import status

from authentication.models import User

ADMIN_URL = reverse("users-list")


@pytest.mark.django_db
def test_create_user_invalid_data(api_client, admin_user):
    payload = {"email": "invalid"}  
    api_client.force_authenticate(user=admin_user)
    response = api_client.post(ADMIN_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
