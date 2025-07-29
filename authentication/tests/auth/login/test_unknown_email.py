import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_wrong_password(api_client):
    url = reverse("login")
    creds = {"email": "unknown@example.com", "password": "AminaSecure456#"}
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
