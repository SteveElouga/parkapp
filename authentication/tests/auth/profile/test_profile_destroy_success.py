import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
def test_profile_destroy_success(api_client, active_user, django_user_model):
    api_client.force_authenticate(user=active_user)
    url = reverse("user-profile")
    # Passphrase correcte (à adapter selon AccountDeleteSerializer)
    data = {
        "passphrase": f"{active_user.email}_delete"
    }  # remplacer par la valeur attendue si besoin
    response = api_client.delete(url, data, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert "message" in response.data
    assert not django_user_model.objects.filter(email=active_user.email).exists()
