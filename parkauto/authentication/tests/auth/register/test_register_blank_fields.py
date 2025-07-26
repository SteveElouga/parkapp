import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
def test_register_required_fields_validation(api_client):
    url = reverse("register")
    response = api_client.post(url, {}, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # Seuls les champs obligatoires attendus
    required_fields = {"email", "username", "password", "password_confirm"}
    returned_fields = set(response.data.keys())

    missing_errors = required_fields - returned_fields
    unexpected_errors = returned_fields - required_fields

    assert not missing_errors, f"Champs requis manquants dans la réponse : {missing_errors}"
    # Optionnel : vérifier qu'il n'y a pas d'erreurs inattendues
    assert not unexpected_errors, f"Champs avec erreur non attendue : {unexpected_errors}"
