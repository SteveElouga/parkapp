import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_activate_invalid_code(api_client):
    url = reverse("activate")
    response = api_client.post(url, {"code": "999999"}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid activation code" in response.data.get("detail", "").lower()