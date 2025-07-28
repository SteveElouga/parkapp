import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_destroy_invalid_passphrase(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("user-profile")
    data = {"passphrase": "WRONG"}
    response = api_client.delete(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "passphrase" in response.data 