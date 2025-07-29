import pytest
from django.urls import reverse
from authentication.models import ActivationCode


@pytest.mark.django_db
def test_activation_code_created(api_client, user_data):
    url = reverse("register")
    api_client.post(url, user_data, format="json")
    assert ActivationCode.objects.filter(user__email=user_data["email"]).exists()
