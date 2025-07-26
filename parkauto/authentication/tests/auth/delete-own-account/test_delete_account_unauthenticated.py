import pytest
from rest_framework import status
from django.urls import reverse

DELETE_ACCOUNT_URL = reverse("delete-account")

@pytest.mark.django_db
def test_delete_account_unauthenticated(api_client):
    payload = {"passphrase": "somepass"}
    response = api_client.post(DELETE_ACCOUNT_URL, payload, format="json")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED