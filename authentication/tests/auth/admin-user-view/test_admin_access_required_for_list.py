import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_access_required_for_list(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("users-list")
    response = api_client.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN