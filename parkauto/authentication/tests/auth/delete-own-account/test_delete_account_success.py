import pytest
from rest_framework import status
from django.urls import reverse

DELETE_ACCOUNT_URL = reverse("delete-account")

@pytest.mark.django_db
def test_delete_account_success(api_client, active_user):

    api_client.force_authenticate(user=active_user)
    payload = {"passphrase": f"{active_user.email}_delete"}
    response = api_client.post(DELETE_ACCOUNT_URL, payload, format="json")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.data["detail"] == "Account successfully deleted."

    # Vérifie que l'utilisateur est supprimé
    from django.contrib.auth import get_user_model
    User = get_user_model()
    assert not User.objects.filter(id=active_user.id).exists()