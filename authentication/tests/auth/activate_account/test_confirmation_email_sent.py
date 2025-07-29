import pytest
from django.urls import reverse
from authentication.models import ActivationCode
from django.core import mail


@pytest.mark.django_db
def test_confirmation_email_sent(api_client, user):
    ActivationCode.objects.create(user=user, code="123461")
    url = reverse("activate")
    api_client.post(url, {"code": "123461"}, format="json")
    assert len(mail.outbox) >= 1
    assert user.email in mail.outbox[-1].to
