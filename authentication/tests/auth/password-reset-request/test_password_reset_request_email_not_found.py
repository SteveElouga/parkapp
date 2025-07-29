import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_request_email_not_found(api_client, mailoutbox):
    url = reverse("password_reset_request")
    data = {"email": "unknown@example.com"}
    response = api_client.post(url, data, format="json")
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]
    assert len(mailoutbox) == 0
