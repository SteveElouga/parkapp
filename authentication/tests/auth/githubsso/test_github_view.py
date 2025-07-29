from django.urls import reverse
import pytest
from unittest import mock
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestGithubSSOLoginView:
    url = reverse("github-sso-login")  # Adapte selon ton routing réel

    def setup_method(self):
        self.client = APIClient()

    def test_no_code_provided(self):
        """POST sans code doit retourner 400"""
        response = self.client.post(self.url, {})
        print("Response:", response.data)  # Debugging line
        assert response.status_code == 400
        assert response.data["error"] == "No code provided"

    @mock.patch("requests.post")
    def test_invalid_github_code(self, mock_post):
        """POST avec code mais pas d'access_token"""
        mock_post.return_value.json.return_value = {}
        response = self.client.post(self.url, {"code": "bad-code"})
        assert response.status_code == 400
        assert response.data["error"] == "Invalid code"

    @mock.patch("requests.get")
    @mock.patch("requests.post")
    def test_no_email_and_no_emails_endpoint(self, mock_post, mock_get):
        """POST avec access_token valide mais pas d'email dans /user, ni dans /user/emails"""
        # Mock /login/oauth/access_token
        mock_post.return_value.json.return_value = {"access_token": "token123"}
        # 1er appel GET: /user → pas d'email
        mock_get.side_effect = [
            mock.Mock(json=lambda: {"email": None}),
            mock.Mock(json=lambda: []),  # /user/emails → vide
        ]
        response = self.client.post(self.url, {"code": "good-code"})
        assert response.status_code == 400
        assert response.data["error"] == "Unable to retrieve email from GitHub"

    @mock.patch("authentication.views.RefreshToken.for_user")
    @mock.patch("authentication.views.MyTokenObtainPairSerializer")
    @mock.patch("requests.get")
    @mock.patch("requests.post")
    def test_email_from_user_emails(
        self, mock_post, mock_get, mock_serializer, mock_refresh
    ):
        """POST avec email trouvé dans /user/emails"""
        mock_post.return_value.json.return_value = {"access_token": "token123"}
        # /user without email, then /user/emails returns a primary email
        mock_get.side_effect = [
            mock.Mock(json=lambda: {"email": None}),
            mock.Mock(json=lambda: [{"email": "primary@example.com", "primary": True}]),
        ]
        mock_refresh.return_value.access_token = "access"
        mock_serializer.return_value.data = {"user": "data"}

        response = self.client.post(self.url, {"code": "good-code"})
        assert response.status_code == 200
        assert response.data["access"] == "access"

    @mock.patch("authentication.views.RefreshToken.for_user")
    @mock.patch("authentication.views.MyTokenObtainPairSerializer")
    @mock.patch("requests.get")
    @mock.patch("requests.post")
    def test_existing_inactive_user_reactivated(
        self, mock_post, mock_get, mock_serializer, mock_refresh, django_user_model
    ):
        """User déjà existant et inactif : il doit être réactivé"""
        # Crée un user inactif
        user = django_user_model.objects.create(
            email="test@inactive.com", is_active=False
        )
        mock_post.return_value.json.return_value = {"access_token": "token123"}
        mock_get.return_value.json.return_value = {
            "email": "test@inactive.com",
            "name": "Inactive Guy",
        }
        mock_refresh.return_value.access_token = "tk"
        mock_serializer.return_value.data = {"user": "data"}

        response = self.client.post(self.url, {"code": "good-code"})
        user.refresh_from_db()
        assert response.status_code == 200
        assert user.is_active is True
