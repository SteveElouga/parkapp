import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch


@pytest.mark.django_db
def test_db_integrity_error(api_client, user_data):
    url = reverse("register")
    with patch(
        "authentication.serializers.User.save", side_effect=Exception("DB Error")
    ):
        response = api_client.post(url, user_data, format="json")
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "error" in response.data
