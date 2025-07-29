import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_password_reset_request_email_case_insensitive(api_client, active_user, mailoutbox):
    url = reverse("password_reset_request")
    data = {"email": active_user.email.upper()}
    response = api_client.post(url, data, format="json")
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]
    assert len(mailoutbox) == 1
    assert active_user.email.lower() in [addr.lower() for addr in mailoutbox[0].to]