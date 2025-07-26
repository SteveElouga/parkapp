import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_login_invalid_credentials(api_client):
    url = reverse("login")

    data = {
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    }

    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data["detail"] == "No active account found with the given credentials"
