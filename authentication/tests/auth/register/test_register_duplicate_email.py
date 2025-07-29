import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import User


@pytest.mark.django_db
def test_register_duplicate_email(api_client, user_data):
    # Crée un utilisateur avec le même email
    User.objects.create_user(email=user_data["email"], password="SomePass456!")

    url = reverse("register")
    response = api_client.post(url, user_data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data
