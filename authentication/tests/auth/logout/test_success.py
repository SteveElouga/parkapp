import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_logout_success(api_client, active_user, valid_refresh_token):
    url = reverse("logout")
    api_client.force_authenticate(user=active_user)
    api_client.cookies["refresh_token"] = valid_refresh_token
    response = api_client.post(url, {}, format="json")
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_205_RESET_CONTENT]
    assert (
        response.cookies.get("refresh_token", None) is None
        or response.cookies["refresh_token"].value == ""
    )
