import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_register_unexpected_exception(api_client, user_data, monkeypatch):
    url = reverse("register")

    def raise_exception(*args, **kwargs):
        raise Exception("Unexpected failure")

    monkeypatch.setattr("authentication.views.RegisterView.perform_create", raise_exception)

    response = api_client.post(url, user_data, format="json")

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.data["error"] == "Internal server error."
