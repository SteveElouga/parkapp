import pytest
from rest_framework import status
from django.urls import reverse

PASSWORD_RESET_REQUEST_URL = reverse("password_reset_request")


def test_password_reset_request_invalid_payload(api_client):
    response = api_client.post(PASSWORD_RESET_REQUEST_URL, {}, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data
