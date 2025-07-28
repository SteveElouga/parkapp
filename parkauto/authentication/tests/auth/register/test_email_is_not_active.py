import pytest
from django.urls import reverse
from rest_framework import status
from authentication.models import ActivationCode

@pytest.mark.django_db
def test_email_is_not_active(api_client, user_data):
    url = reverse("register")
    api_client.post(url, user_data, format="json")
    email = user_data["email"]
    activation = ActivationCode.objects.get(user__email=email)
    user = activation.user
    assert not user.is_active