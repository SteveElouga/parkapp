import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_invalid_email_format(api_client):
    creds = {
        "email": "invalid-email",
        "password": "AminaSecure456#"
    }
    url = reverse("login")
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data