import datetime, arrow, json, os, base64
from ssl import SSLContext, PROTOCOL_TLSv1_1, create_default_context
from requests_oauthlib import OAuth2Session
from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, login_required, current_user, login_user, UserMixin, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_hashing import Hashing
from config import config, Auth
from requests.exceptions import HTTPError

app = Flask(__name__)

app.config.from_object(config["dev"])

hashing = Hashing(app)

db = SQLAlchemy(app, session_options={"autoflush": False})

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=False)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())

class Uploads(db.Model):
    __tablename = "uploads"
    userID = db.Column(db.Integer, db.ForeignKey(User.id), primary_key=True)
    timestamp = db.Column(db.Float, primary_key=True, default=arrow.utcnow().float_timestamp)
    data = db.Column(db.Text, unique=True)

    def __init__(self, userID, timestamp, data):
      self.userID = userID
      self.timestamp = timestamp
      self.data = data


login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
		return User.query.get(int(user_id))

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
    # Remember me option is checked
    #remember = "remember-me" in request.args
    #print(remember)
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
                      authorization_response=request.url
                    )
        except HTTPError:
            return 'HTTPError occurred.'
        #remember = "remember-me" in request.args
        #print(remember)
        #print(list(request.form.items()))
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            #login_user(user, remember=remember)
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/upload")
def upload():
    return render_template("upload.html")

def validateExtension(filename):
  return '.' in filename and filename.split('.')[-1] in ["jpeg", "jpg", "png", "bmp", "tiff", "svg", "txt"]

def validateFileSize(fileContent):
  print(app.config["MAX_CONTENT_LENGTH"])
  print(len(fileContent))
  #file.seek(0, 2)
  #print(file.tell())
  #if file.tell() < app.config["MAX_CONTENT_LENGTH"]:
  return len(fileContent) < app.config["MAX_CONTENT_LENGTH"]

def encrypt(content, algorithm="base64"):
  if algorithm == "base64":
    return base64.b64encode(content)
  

@app.route('/postFileToDatabase', methods=['GET','POST'])
def postFileToDatabase():
    images = request.files.getlist('images')
    #images = request.files['images']
    print(images)
    success = False

    #verify the file exists, has an allowed extension, and is under our max file size
    for file in images:
      if file and validateExtension(file.filename):
        #search the database via SQLAlchemy for an upload associated with our user
        timestamp = arrow.utcnow().float_timestamp
        upload = Uploads.query.filter_by(userID=current_user.get_id(), timestamp=timestamp).first()
        #print(upload)
        #print(current_user.get_id())
        print(timestamp)
        #if the user already has an upload, find and overwrite in database
        content = file.read()
        if validateFileSize(content):
          if upload is not None:
            upload.data = encrypt(content)
            #print(upload.data)
          #otherwise, create a new upload database object
          else:
            upload = Uploads(userID=current_user.get_id(), timestamp=timestamp, data=encrypt(content))
          #add our users upload to the database
          print((upload.userID, upload.timestamp, upload.data[:100]))
        #print(dir(file))
          db.session.add(upload)
    
    db.session.commit()
    success = True
        
    print(json.dumps({"Success" : success}))

    return redirect(url_for('index'))



if __name__ == "__main__":

	app.run(debug=True, ssl_context=('./ssl.crt', './ssl.key'))

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

