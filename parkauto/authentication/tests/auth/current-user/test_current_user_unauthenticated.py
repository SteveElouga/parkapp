import pytest
from rest_framework import status
from django.urls import reverse

USER_ME_URL = reverse("user-me")

def test_get_current_user_unauthenticated(api_client):
    response = api_client.get(USER_ME_URL)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
