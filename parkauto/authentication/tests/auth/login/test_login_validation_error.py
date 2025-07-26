import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_login_validation_error(api_client):
    url = reverse("login")

    # Par exemple, email vide ou password vide
    data = {
        "email": "",
        "password": ""
    }

    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data["error"] == "Invalid credentials."
