import datetime, arrow, json, os, base64, string, random
from ssl import SSLContext, PROTOCOL_TLSv1_1, create_default_context
from requests_oauthlib import OAuth2Session
from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, login_required, current_user, login_user, UserMixin, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_hashing import Hashing
from config import config, Auth
from requests.exceptions import HTTPError
from cryptography.fernet import Fernet
from Crypto import Random
from Crypto.PublicKey import DSA, RSA
from Crypto.Hash import SHA
from Crypto.Cipher import AES

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
    data = db.Column(db.Text)

    def __init__(self, userID, timestamp, data):
      self.userID = userID
      self.timestamp = timestamp
      self.data = data

class AESCipher():

  def __init__(self, key, block_size=16):
    self.key = key
    self.block_size = block_size

  def encrypt(self, message):
    if message is None or len(message) == 0:
      return ''
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(self.key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(message))

  def decrypt(self, message):
    if message is None or len(message) == 0:
      return ''
    message = base64.b64decode(message)
    iv = message[:AES.block_size]
    cipher = AES.new(self.key, AES.MODE_CFB, iv)
    return cipher.decrypt(message[AES.block_size:])

key = Random.new().read(32)
aes = AESCipher(key)

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
  
  uploads = Uploads.query.filter_by(userID=current_user.get_id()).with_entities(Uploads.data).all()
  images = []
  for upload in uploads:
    images.append(aes.decrypt(upload[0]))
  
  return render_template("index.html", images=images)


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
  return '.' in filename and filename.split('.')[-1] in app.config["ALLOWED_FILE_TYPES"]

def validateFileSize(fileContent):
  return len(fileContent) < app.config["MAX_CONTENT_LENGTH"]

def randomString(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join((random.choice(chars)) for i in range(length))

def encrypt(content, algorithm="base64"):
  if algorithm == "base64":
    return base64.b64encode(content)
  if algorithm == "fernet":
    key = Fernet.generate_key()
    f = Fernet(key)
    return f.encrypt(content)
  if algorithm == "aes":
    key = Random.new().read(32)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(content)
  

@app.route('/postFileToDatabase', methods=['GET','POST'])
def postFileToDatabase():
    images = request.files.getlist('images')
    success = False

    #verify the file exists, has an allowed extension, and is under our max file size
    for file in images:
      if file and validateExtension(file.filename):
        #search the database via SQLAlchemy for an upload associated with our user
        timestamp = arrow.utcnow().float_timestamp
        upload = Uploads.query.filter_by(userID=current_user.get_id(), timestamp=timestamp).first()
        #if the user already has an upload, find and overwrite in database
        content = file.read()
        if validateFileSize(content):
          if upload is not None:
            upload.data = aes.encrypt(content)
          #otherwise, create a new upload database object
          else:
            upload = Uploads(userID=current_user.get_id(), timestamp=timestamp, data=aes.encrypt(content))
          #add our users upload to the database
          db.session.add(upload)
    
    db.session.commit()
    success = True
        
    print(json.dumps({"Success" : success}))

    return redirect(url_for('index'))



if __name__ == "__main__":

	app.run(debug=True, ssl_context=('./ssl.crt', './ssl.key'))

