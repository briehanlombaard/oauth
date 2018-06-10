import json

from django.http import HttpResponse
from oauth2_provider.views.generic import ProtectedResourceView


class ApiEndpoint(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return HttpResponse(json.dumps({
            'id': request.resource_owner.pk,
            'username': request.resource_owner.username,
            'email': request.resource_owner.email,
        }))


def index(request):
    print(request.user)
