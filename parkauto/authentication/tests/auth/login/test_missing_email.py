import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_missing_email(api_client, active_user):
    creds = {
        "email": active_user.email,
        "password": "AminaSecure456#"
    }
    creds.pop("email")
    url = reverse("login")
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data or "error" in response.data