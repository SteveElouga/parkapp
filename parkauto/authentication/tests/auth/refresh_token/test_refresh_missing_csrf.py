import pytest
from django.urls import reverse
from rest_framework import status

REFRESH_URL = reverse("token_refresh")


@pytest.mark.django_db
def test_refresh_missing_csrf(api_client, valid_refresh_token):
    api_client.cookies["refresh_token"] = ''

    # Pas de header CSRF
    response = api_client.post(REFRESH_URL)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
