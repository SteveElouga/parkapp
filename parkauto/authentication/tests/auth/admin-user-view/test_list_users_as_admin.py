import pytest
from django.urls import reverse
from rest_framework import status

ADMIN_URL = reverse("users-list")


@pytest.mark.django_db
def test_list_users_as_admin(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)

    response = api_client.get(ADMIN_URL)

    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.data, list)
    assert len(response.data) >= 1
