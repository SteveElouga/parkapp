import pytest
from django.urls import reverse
from rest_framework import status

ADMIN_URL = reverse("users-list")

@pytest.mark.django_db
def test_list_users_forbidden_for_non_admin(api_client, active_user):
        api_client.force_authenticate(user=active_user)
        response = api_client.get(ADMIN_URL)
        assert response.status_code == status.HTTP_403_FORBIDDEN