import ssl
import datetime
from requests_oauthlib import OAuth2Session
from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from config import config, Auth
from requests import HTTPError

app = Flask(__name__)

app.config.from_object(config["dev"])

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
#    name = db.Column(db.String(100), nullable=True)
#    avatar = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=False)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())


login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth

@app.route('/')
@login_required
def index():
	return render_template("index.html")


@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)

@app.route('/oauth2callback')
def callback():
    # Redirect user to home page if already logged in.
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        # Execution reaches here when user has
        # successfully authenticated our app.
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
#            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
#            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'

if __name__ == "__main__":

	app.run(debug=True, ssl_context=("./ssl.crt", "./ssl.key"))

#import json
#
#import os
#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
#
#with open("../client_secret.json", 'r') as f:
#	oauth2_params = json.loads(f.read())
#
#GOOGLE_CLIENT_ID = oauth2_params["web"]["client_id"]
#GOOGLE_CLIENT_SECRET = oauth2_params["web"]["client_secret"]
#REDIRECT_URI = oauth2_params["web"]["redirect_uris"][0]  # one of the Redirect URIs from Google APIs console
#AUTHORIZE_URI = oauth2_params["web"]["auth_uri"]
#TOKEN_URI = oauth2_params["web"]["token_uri"]
#SCOPE = "https://www.googleapis.com/auth/userinfo.email"
# 
#SECRET_KEY = 'development key'
#
#app = Flask(__name__)
#app.secret_key = SECRET_KEY
#
#
#@app.route('/')
#def index():
#
#	access_token = session.get('access_token')
#	if access_token is None:
#		return redirect(url_for('login'))
#
#	access_token = access_token[0]
#	from requests import get, RequestException
#
#	headers = {'Authorization': 'OAuth '+access_token}
#
#	try:
#		res = requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers=headers)
#	except HTTPError as e:
#		if e.code == 401:
#			# Unauthorized - bad token
#			session.pop('access_token', None)
#			return redirect(url_for('login'))
#		return res.content
# 
#	return res.content
#
#
#@app.route("/welcome")
#def welcome():
#	return render_template("welcome.html")
#
##@app.route("/login", methods=["GET","POST"])
#@app.route("/login", methods=["GET","POST"])
#def login():
#
#	"""Step 1: User Authorization.
#
#	Redirect the user/resource owner to the OAuth provider (i.e. Github)
#	using an URL with a few key OAuth parameters.
#	"""
#	print(session.get('access_token'))
#	if session.get('access_token') is None:
#		return render_template("login.html")
#
#	google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
#	authorization_url, state = google.authorization_url(AUTHORIZE_URI)
#
#	# State is used to prevent CSRF, keep this for later.
#	session['oauth_state'] = state
#	return redirect(authorization_url)
#
#
#@app.route("/oauth2callback", methods=["GET"])
#def callback():
#  """ Step 3: Retrieving an access token.
#
#  The user has been redirected back from the provider to your registered
#  callback URL. With this redirection comes an authorization code included
#  in the redirect URL. We will use that to obtain an access token.
#  """
#
#  google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
#  token = google.fetch_token(TOKEN_URI, client_secret=GOOGLE_CLIENT_SECRET,
#                               authorization_response=request.url)
#
#  # At this point you can fetch protected resources but lets save
#  # the token and show how this is done from a persisted token
#  # in /welcome.
#  session['oauth_token'] = token
#
#  return redirect(url_for('welcome'))

