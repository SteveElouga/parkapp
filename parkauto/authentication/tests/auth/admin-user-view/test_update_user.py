from venv import logger
import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_update_user(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-detail", args=[admin_user.id])
    logger.warning({"admin_id": admin_user.id})
    payload = {"first_name": "Updated"}

    response = api_client.put(
        url, payload, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert admin_user.first_name == "Updated"
