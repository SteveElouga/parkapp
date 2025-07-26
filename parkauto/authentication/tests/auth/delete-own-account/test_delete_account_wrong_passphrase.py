import pytest
from rest_framework import status
from django.urls import reverse

DELETE_ACCOUNT_URL = reverse("delete-account")

@pytest.mark.django_db
def test_delete_account_wrong_passphrase(api_client, active_user):
    api_client.force_authenticate(user=active_user)
    
    payload = {"passphrase": "wrong_passphrase"}
    response = api_client.post(DELETE_ACCOUNT_URL, payload, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "passphrase" in response.data