import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_update_invalid_data(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    url = reverse("user-profile")
    data = {"date_of_birth": "not-a-date"}
    response = api_client.put(url, data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "date_of_birth" in response.data