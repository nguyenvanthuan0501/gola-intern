from rest_framework.response import Response
from rest_framework import status
from api_project.models import Blacklist


def check_blacklist_token(request):
    token = str(request.META.get('HTTP_AUTHORIZED'))

    if token.startswith('Bearer '):
        token = token.replace('Bearer ', '')

        if Blacklist.objects.filter(token=token).exists():
            return True
    return False
