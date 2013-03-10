
from pyramid.view import view_defaults
from pyramid.view import view_config
import sys
from pyramid.response import Response


@view_config(route_name='check', request_method='POST')
def my_view(request):
	myfile = request.POST.get('fileID')
	
	return Response('query string: %s' % myfile)


