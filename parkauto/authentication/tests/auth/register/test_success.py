import pytest
from django.urls import reverse
from rest_framework import status
from django.core import mail
from authentication.models import ActivationCode

@pytest.mark.django_db
def test_register_success(api_client, user_data):
    url = reverse("register")
    response = api_client.post(url, user_data, format="json")
    assert response.status_code == status.HTTP_201_CREATED
    assert "activation code" in response.data["message"].lower()
    assert ActivationCode.objects.filter(user__email=user_data["email"]).exists()
    assert len(mail.outbox) == 1
    assert user_data["email"] in mail.outbox[0].to