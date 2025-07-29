import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_blank_fields(api_client):
    url = reverse("register")
    response = api_client.post(url, {}, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    required_fields = {"email", "password", "password_confirm"}
    assert required_fields.issubset(set(response.data.keys()))
