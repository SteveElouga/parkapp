import pytest
from authentication.views import get_client_ip
from rest_framework.test import APIRequestFactory

def test_get_client_ip_remote_addr():
    factory = APIRequestFactory()
    request = factory.get('/')
    request.META['REMOTE_ADDR'] = '9.9.9.9'
    ip = get_client_ip(request)
    assert ip == '9.9.9.9'