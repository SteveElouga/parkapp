import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_admin_can_search_users(api_client, admin_user, create_lambda_user):
    api_client.force_authenticate(user=admin_user)
    url = reverse("users-list")
    response = api_client.get(url, {"search": "Lambda"})
    assert response.status_code == status.HTTP_200_OK
    assert any("Lambda" in user["first_name"] for user in response.data.get("results", response.data))