import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_password_reset_request_success(api_client, active_user, mailoutbox):
    url = reverse("password_reset_request")
    data = {"email": active_user.email}
    response = api_client.post(url, data, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert len(mailoutbox) == 1
    assert active_user.email in mailoutbox[0].to
