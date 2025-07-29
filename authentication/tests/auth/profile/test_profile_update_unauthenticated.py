import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_update_unauthenticated(api_client, active_user):
    url = reverse("user-profile")
    data = {"first_name": "Test"}
    response = api_client.put(url, data, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
