import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_email_with_spaces_and_case(api_client, user_data):
    user_data["email"] = "  NewUser@Example.COM "
    url = reverse("register")
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_201_CREATED
    assert "activation code" in response.data["message"].lower()
