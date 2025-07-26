import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import User

@pytest.mark.django_db
def test_register_duplicate_username(api_client, user_data):
    User.objects.create_user(
        email="other@example.com",
        password="StrongPass789!",
        username=user_data["username"]
    )

    url = reverse("register")
    response = api_client.post(url, user_data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "username" in response.data
