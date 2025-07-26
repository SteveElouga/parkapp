from django.urls import reverse
from rest_framework import status

PROFILE_URL = reverse("profile")

def test_profile_update_unauthenticated(api_client):
    payload = {"first_name": "Test"}
    response = api_client.put(PROFILE_URL, payload, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
