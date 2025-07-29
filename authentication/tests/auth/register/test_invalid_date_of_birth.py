import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_invalid_date_of_birth(api_client, user_data):
    user_data["date_of_birth"] = "not-a-date"
    url = reverse("register")
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "date_of_birth" in response.data