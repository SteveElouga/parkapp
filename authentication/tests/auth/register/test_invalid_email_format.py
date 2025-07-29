import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_invalid_email_format(api_client, user_data):
    user_data["email"] = "invalid-email"
    url = reverse("register")
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data
