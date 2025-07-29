import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_unauthenticated_user(api_client):
    url = reverse("logout")
    response = api_client.post(url, {}, format="json")
    # Ici, normalement, le logout ne nécessite pas d'être authentifié, mais à adapter selon ton endpoint
    assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]