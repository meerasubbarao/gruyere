import json
import os
import pickle
from dataclasses import dataclass
import base64

from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe

from security.models import User


def unsafe_users(request, user_id):
    """SQL injection"""

    users = User.objects.raw(f'SELECT * FROM security_user WHERE id = {user_id}')

    return HttpResponse(users)


# http://127.0.0.1:8000/security/safe/users/1
def safe_users(request, user_id):
    """Uses parameterised query so it's fine"""

    users = User.objects.raw('SELECT * FROM security_user WHERE id = %s', (user_id,))

    return HttpResponse(users)


def read_file(request, filename):
    with open(filename) as f:
        return HttpResponse(f.read())


def copy_file(request, filename):
    """Copy a file in a very dangerous way"""

    cmd = f'cp {filename} new_{filename}'

    os.system(cmd)

    return HttpResponse("All good, don't worry about a thing :>")


@dataclass
class TestUser:
    """Dummy user data"""

    perms: int = 0


pickled_user = pickle.dumps(TestUser())
print(pickled_user)
encoded_user = base64.b64encode(pickled_user)
print(encoded_user)


# No access token:
# b'\x80\x03csecurity.views\nTestUser\nq\x00)\x81q\x01}q\x02X\x05\x00\x00\x00permsq\x03K\x00sb.'
# b'gANjc2VjdXJpdHkudmlld3MKVGVzdFVzZXIKcQApgXEBfXECWAUAAABwZXJtc3EDSwBzYi4='


# Admin token:
# b'\x80\x03csecurity.views\nTestUser\nq\x00)\x81q\x01}q\x02X\x05\x00\x00\x00permsq\x03K\x01sb.'
# b'gANjc2VjdXJpdHkudmlld3MKVGVzdFVzZXIKcQApgXEBfXECWAUAAABwZXJtc3EDSwFzYi4='
