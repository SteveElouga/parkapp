import pytest
from django.urls import reverse
from authentication.models import ActivationCode


@pytest.mark.django_db
def test_activation_code_marked_used(api_client, user):
    activation = ActivationCode.objects.create(user=user, code="123460")
    url = reverse("activate")
    api_client.post(url, {"code": "123460"}, format="json")
    activation.refresh_from_db()
    assert activation.is_used
