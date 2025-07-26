from rest_framework import status
from django.urls import reverse

LOGOUT_URL = reverse("logout")

def test_logout_requires_authentication(api_client):
    response = api_client.post(LOGOUT_URL)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
