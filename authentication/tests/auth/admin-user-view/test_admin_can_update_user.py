import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_admin_can_update_user(api_client, admin_user, user_factory):
    user = user_factory(email="changeme@example.com", first_name="Old")
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-detail", args=[user.pk])
    response = api_client.patch(url, {"first_name": "New"}, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["first_name"] == "New"
