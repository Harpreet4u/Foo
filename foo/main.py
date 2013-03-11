

__author__ = 'Harpeet Singh'
from pyramid.view import view_defaults
from pyramid.view import view_config
from oauth2client.client import flow_from_clientsecrets
import sys
import httplib2
from apiclient.discovery import build
from apiclient import errors
import logging
from pyramid.httpexceptions import HTTPFound
import urllib
import json
import urllib2
from oauth2client.client import FlowExchangeError


ALL_SCOPES = ('https://www.googleapis.com/auth/drive.file '
              'https://www.googleapis.com/auth/userinfo.email '
              'https://www.googleapis.com/auth/userinfo.profile '
              'https://www.googleapis.com/auth/drive.install '
              'https://www.googleapis.com/auth/drive.metadata.readonly '
              'https://www.googleapis.com/auth/drive.readonly')




def CreateService(service, version, creds):
  """Create a Google API service.

  Load an API service from a discovery document and authorize it with the
  provided credentials.

  Args:
    service: Service name (e.g 'drive', 'oauth2').
    version: Service version (e.g 'v1').
    creds: Credentials used to authorize service.
  Returns:
    Authorized Google API service.
  """
  # Instantiate an Http instance
  http = httplib2.Http()

  # Authorize the Http instance with the passed credentials
  creds.authorize(http)

  # Build a service from the passed discovery document path
  return build(service, version, http=http)




class BaseDriveHandler(object):
  """Base request handler for drive applications.

  Adds Authorization support for Drive.
  """

  def CreateOAuthFlow(self):
    """Create OAuth2.0 flow controller

    This controller can be used to perform all parts of the OAuth 2.0 dance
    including exchanging an Authorization code.

    Args:
      request: HTTP request to create OAuth2.0 flow for
    Returns:
      OAuth2.0 Flow instance suitable for performing OAuth2.0.
    """
    flow = flow_from_clientsecrets('client_secrets.json', scope='')
    # Dynamically set the redirect_uri based on the request URL. This is extremely
    # convenient for debugging to an alternative host without manually setting the
    # redirect URI.
    flow.redirect_uri = self.request.url.split('?', 1)[0].rsplit('/', 1)[0]
    #flow.redirect_uri = "http://awsm-hapie.appspot.com"
    return flow

  def GetCodeCredentials(self):
    """Create OAuth 2.0 credentials by extracting a code and performing OAuth2.0.

    The authorization code is extracted form the URI parameters. If it is absent,
    None is returned immediately. Otherwise, if it is present, it is used to
    perform step 2 of the OAuth 2.0 web server flow.

    Once a token is received, the user information is fetched from the userinfo
    service and stored in the session. The token is saved in the datastore against
    the user ID received from the userinfo service.

    Args:
      request: HTTP request used for extracting an authorization code and the
               session information.
    Returns:
      OAuth2.0 credentials suitable for authorizing clients or None if
      Authorization could not take place.
    """
    # Other frameworks use different API to get a query parameter.
    code = self.request.GET
    if 'code' in code.keys():
			code = code['code']
    else:
			code = 0
			print "No code here"

    if not code:
      # returns None to indicate that no code was passed from Google Drive.
      return None

    print "Starting step-2 verification"
    # Auth flow is a controller that is loaded with the client information,
    # including client_id, client_secret, redirect_uri etc
    oauth_flow = self.CreateOAuthFlow()

    # Perform the exchange of the code. If there is a failure with exchanging
    # the code, return None.
    try:
      creds = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
      return None



    # Create an API service that can use the userinfo API. Authorize it with our
    # credentials that we gained from the code exchange.
    users_service = CreateService('oauth2', 'v2', creds)

    # Make a call against the userinfo service to retrieve the user's information.
    # In this case we are interested in the user's "id" field.
    userid = users_service.userinfo().get().execute().get('id')

    print userid

    # Store the user id in the user's cookie-based session.
    #session = self.request.session.LilCookies(self, SESSION_SECRET)
    #session.set_secure_cookie(name='userid', value=userid)
    session = self.request.session
    session['userid'] = creds
		
    # Store the credentials in the data store using the userid as the key.
    #StorageByKeyName(Credentials, userid, 'credentials').put(creds)
    return creds

  def GetSessionCredentials(self):
    """Get OAuth 2.0 credentials for an HTTP session.

    If the user has a user id stored in their cookie session, extract that value
    and use it to load that user's credentials from the data store.

    Args:
      request: HTTP request to use session from.
    Returns:
      OAuth2.0 credentials suitable for authorizing clients.
    """
    # Try to load  the user id from the session
    session = request.session.LilCookies(self, SESSION_SECRET)
    userid = session.get_secure_cookie(name='userid')
    if not userid:
      # return None to indicate that no credentials could be loaded from the
      # session.
      return None

    # Load the credentials from the data store, using the userid as a key.
    creds = StorageByKeyName(Credentials, userid, 'credentials').get()

    # if the credentials are invalid, return None to indicate that the credentials
    # cannot be used.
    if creds and creds.invalid:
      return None

    return creds

  def RedirectAuth(self):
    """Redirect a handler to an authorization page.

    Used when a handler fails to fetch credentials suitable for making Drive API
    requests. The request is redirected to an OAuth 2.0 authorization approval
    page and on approval, are returned to application.

    Args:
      handler: webapp.RequestHandler to redirect.
    """
    flow = self.CreateOAuthFlow()

    # Manually add the required scopes. Since this redirect does not originate
    # from the Google Drive UI, which authomatically sets the scopes that are
    # listed in the API Console.
    flow.scope = ALL_SCOPES

    # Create the redirect URI by performing step 1 of the OAuth 2.0 web server
    # flow.
    uri = flow.step1_get_authorize_url(flow.redirect_uri)

    # Perform the redirect.
    #self.redirect(uri)
    return HTTPFound(location=uri)

  def RespondJSON(self, data):
    """Generate a JSON response and return it to the client.

    Args:
      data: The data that will be converted to JSON to return.
    """
    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(data))

  def CreateAuthorizedService(self, service, version):
    """Create an authorize service instance.

    The service can only ever retrieve the credentials from the session.

    Args:
      service: Service name (e.g 'drive', 'oauth2').
      version: Service version (e.g 'v1').
    Returns:
      Authorized service or redirect to authorization flow if no credentials.
    """
    # For the service, the session holds the credentials
    #creds = self.GetSessionCredentials()
    creds = self.request.session['userid']
    if creds:
      # If the session contains credentials, use them to create a Drive service
      # instance.
      return CreateService(service, version, creds)
    else:
      # If no credentials could be loaded from the session, redirect the user to
      # the authorization page.
      self.RedirectAuth()

  def CreateDrive(self):
    """Create a drive client instance."""
    return self.CreateAuthorizedService('drive', 'v2')

  def CreateUserInfo(self):
    """Create a user info client instance."""
    return self.CreateAuthorizedService('oauth2', 'v2')


def print_file(service, file_id):
	"""Print a file's metadata.

	Args:
	service: Drive API service instance.
	file_id: ID of the file to print metadata for.
	"""

	try:
		file = service.files().get(fileId=file_id).execute()

		print 'Title: %s' % file['title']
		print 'file', file
		print 'MIME type: %s' % file['mimeType']	
		download_url = file['exportLinks']['text/plain']
		#jsonFile = json.dumps(download_url)
		#jsonDict = json.loads(jsonFile)
		#download_url = jsonDict['text/plain']
		print download_url
		#download_url = download_url.encode('ascii', 'ignore')
		if download_url:
			resp, content = service._http.request(download_url)
			#content = urllib2.urlopen(download_url).read()
			#return content
			
			if resp.status == 200:
				print 'Status: %s' % resp
				return content
			else:
				print 'An error occurred: %s' % resp
				return None
		else:
			# The file doesn't have any content stored on Drive.
			return None

 	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return error


@view_defaults(route_name='main', renderer='templates/index.pt') 
class MainPage(BaseDriveHandler):

	def __init__(self, request):
		self.request = request
	
	@view_config(request_method='GET')
	def get(self):
		
		code = self.request.GET.get('code')
		creds = self.GetCodeCredentials()
		if not creds:
			return self.RedirectAuth()

#		print creds.client_secret
#		print creds.client_id
		return {'name':'Its working...', 'code': code}

	@view_config(request_method='POST')
	def post(self):
		creds = self.request.session['userid']
		users_service = self.CreateDrive()
		myfile = self.request.POST.get('fileID')
		content = print_file(users_service, myfile)
		print "-------"
		print content
		#content = json.dumps(content) #python to json
		#dict = json.loads(content)		#json to python
		content = content.decode('utf-8')
		return {'name':'post request','code':content}


