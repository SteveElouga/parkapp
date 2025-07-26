import pytest
from django.urls import reverse
from rest_framework import status


ACTIVATE_URL = reverse("activate")

@pytest.mark.django_db
def test_missing_code_field(api_client):
    response = api_client.post(ACTIVATE_URL, {}, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "code" in response.data
