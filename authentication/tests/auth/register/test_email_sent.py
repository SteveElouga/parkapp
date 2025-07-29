import pytest
from django.urls import reverse
from django.core import mail

@pytest.mark.django_db
def test_email_sent(api_client, user_data):
    url = reverse("register")
    api_client.post(url, user_data, format="json")
    assert len(mail.outbox) == 1
    assert user_data["email"] in mail.outbox[0].to