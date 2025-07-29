import pytest
from authentication.views import get_client_ip
from rest_framework.test import APIRequestFactory

def test_get_client_ip_x_forwarded_for():
    factory = APIRequestFactory()
    request = factory.get('/')
    request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4,5.6.7.8'
    ip = get_client_ip(request)
    assert ip == '1.2.3.4'