from django.urls import reverse
import pytest
from unittest import mock
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestGoogleSSOLoginView:
    url = reverse("google-sso-login")

    def setup_method(self):
        self.client = APIClient()

    def test_no_token_provided(self):
        """POST sans id_token doit retourner 400"""
        response = self.client.post(self.url, {})
        assert response.status_code == 400
        assert response.data["error"] == "No token provided"

    @mock.patch("authentication.views.id_token.verify_oauth2_token")
    def test_invalid_token(self, mock_verify):
        """POST avec id_token invalide (raise ValueError)"""
        mock_verify.side_effect = ValueError("Token invalid")
        response = self.client.post(self.url, {"id_token": "invalid"})
        assert response.status_code == 400
        assert response.data["error"] == "Invalid token"

    @mock.patch("authentication.views.RefreshToken.for_user")
    @mock.patch("authentication.views.MyTokenObtainPairSerializer")
    @mock.patch("authentication.views.id_token.verify_oauth2_token")
    def test_successful_login(self, mock_verify, mock_serializer, mock_refresh):
        """POST avec id_token valide => user créé/MAJ et tokens générés"""
        mock_verify.return_value = {
            "email": "testuser@google.com",
            "given_name": "Test",
            "family_name": "User",
        }
        mock_refresh.return_value.access_token = "tok"
        mock_serializer.return_value.data = {"user": "data"}

        response = self.client.post(self.url, {"id_token": "valid"})
        assert response.status_code == 200
        assert response.data["access"] == "tok"
        assert response.data["user"] == {"user": "data"}

    @mock.patch("authentication.views.RefreshToken.for_user")
    @mock.patch("authentication.views.MyTokenObtainPairSerializer")
    @mock.patch("authentication.views.id_token.verify_oauth2_token")
    def test_existing_inactive_user_reactivated(
        self, mock_verify, mock_serializer, mock_refresh, django_user_model
    ):
        """User déjà existant et inactif : il doit être réactivé"""
        user = django_user_model.objects.create(
            email="inactive@google.com", is_active=False
        )
        mock_verify.return_value = {
            "email": "inactive@google.com",
            "given_name": "Inactive",
            "family_name": "Guy",
        }
        mock_refresh.return_value.access_token = "tok"
        mock_serializer.return_value.data = {"user": "data"}

        response = self.client.post(self.url, {"id_token": "valid"})
        user.refresh_from_db()
        assert response.status_code == 200
        assert user.is_active is True
