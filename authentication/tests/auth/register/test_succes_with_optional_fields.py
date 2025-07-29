import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_register_success_with_optional_fields(api_client, user_data):
    url = reverse("register")
    user_data.update(
        {
            "first_name": "John",
            "last_name": "Doe",
            "role": "client",
            "phone_number": "+123456789",
            "address": "123 Street",
            "city": "Paris",
            "country": "France",
            "date_of_birth": "1990-01-01",
        }
    )
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_201_CREATED
