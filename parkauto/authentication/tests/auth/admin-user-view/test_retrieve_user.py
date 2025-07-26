import pytest
from django.urls import reverse
from rest_framework import status

from authentication.models import User

ADMIN_URL = reverse("users-list")


@pytest.mark.django_db
def test_retrieve_user(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-detail", args=[admin_user.id])

    response = api_client.get(url)

    assert response.status_code == status.HTTP_200_OK
    assert response.data["email"] == admin_user.email
