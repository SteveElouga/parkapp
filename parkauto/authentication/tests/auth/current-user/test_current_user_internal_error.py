import pytest
from rest_framework import status
from django.urls import reverse
from unittest.mock import patch

USER_ME_URL = reverse("user-me")

@pytest.mark.django_db
def test_get_current_user_internal_error(api_client, active_user):
    api_client.force_authenticate(user=active_user)

    with patch("authentication.serializers.UserSerializer.__init__", side_effect=Exception("Boom")):
        response = api_client.get(USER_ME_URL)

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "error" in response.data
    assert response.data["error"] == "Internal server error."
