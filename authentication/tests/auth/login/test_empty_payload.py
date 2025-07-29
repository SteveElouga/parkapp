import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_empty_payload(api_client):
    url = reverse("login")
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
