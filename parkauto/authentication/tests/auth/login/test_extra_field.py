import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_extra_field(api_client, active_user):
    creds = {
        "email": active_user.email,
        "password": "AminaSecure456#",
        "extra": "field"
    }
    url = reverse("login")
    response = api_client.post(url, creds, format="json")
    assert response.status_code == status.HTTP_200_OK