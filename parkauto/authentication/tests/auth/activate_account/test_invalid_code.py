import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import User, ActivationCode
from django.utils import timezone

ACTIVATE_URL = reverse("activate")

@pytest.mark.django_db
def test_invalid_code(api_client):
    response = api_client.post(ACTIVATE_URL, {"code": "000000"}, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["detail"] == "Invalid activation code."
