# import pytest
# from django.urls import reverse
# from rest_framework import status

# @pytest.mark.django_db
# def test_password_reset_request_rate_limit(api_client, active_user, settings):
#     url = reverse("password_reset_request")
#     data = {"email": active_user.email}
#     # Simule plusieurs requêtes rapides (adapter selon ta config throttle)
#     for _ in range(501):
#         api_client.post(url, data, format="json")
#     response = api_client.post(url, data, format="json")
#     assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
