import ssl
from requests_oauthlib import OAuth2Session
from flask import Flask, render_template, redirect, url_for, request, session
import json

import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

with open("../client_secret.json", 'r') as f:
	oauth2_params = json.loads(f.read())

GOOGLE_CLIENT_ID = oauth2_params["web"]["client_id"]
GOOGLE_CLIENT_SECRET = oauth2_params["web"]["client_secret"]
REDIRECT_URI = oauth2_params["web"]["redirect_uris"][0]  # one of the Redirect URIs from Google APIs console
AUTHORIZE_URI = oauth2_params["web"]["auth_uri"]
TOKEN_URI = oauth2_params["web"]["token_uri"]
SCOPE = "https://www.googleapis.com/auth/userinfo.email"
 
SECRET_KEY = 'development key'

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.route('/')
def index():

	access_token = session.get('access_token')
	if access_token is None:
		return redirect(url_for('login'))

	access_token = access_token[0]
	from requests import get, RequestException

	headers = {'Authorization': 'OAuth '+access_token}

	try:
		res = requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers=headers)
	except HTTPError as e:
		if e.code == 401:
			# Unauthorized - bad token
			session.pop('access_token', None)
			return redirect(url_for('login'))
		return res.content
 
	return res.content


@app.route("/welcome")
def welcome():
	return render_template("welcome.html")

#@app.route("/login", methods=["GET","POST"])
@app.route("/login", methods=["GET","POST"])
def login():

	"""Step 1: User Authorization.

	Redirect the user/resource owner to the OAuth provider (i.e. Github)
	using an URL with a few key OAuth parameters.
	"""

	if session.get('access_token') is None:
		return render_template("login.html")

	google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
	authorization_url, state = google.authorization_url(AUTHORIZE_URI)

	# State is used to prevent CSRF, keep this for later.
	session['oauth_state'] = state
	return redirect(authorization_url)


@app.route("/oauth2callback", methods=["GET"])
def callback():
  """ Step 3: Retrieving an access token.

  The user has been redirected back from the provider to your registered
  callback URL. With this redirection comes an authorization code included
  in the redirect URL. We will use that to obtain an access token.
  """

  google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
  token = google.fetch_token(TOKEN_URI, client_secret=GOOGLE_CLIENT_SECRET,
                               authorization_response=request.url)

  # At this point you can fetch protected resources but lets save
  # the token and show how this is done from a persisted token
  # in /welcome.
  session['oauth_token'] = token

  return redirect(url_for('welcome'))

