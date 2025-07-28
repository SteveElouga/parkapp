import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_profile_retrieve_unauthenticated(api_client):
    url = reverse("user-profile")
    response = api_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED