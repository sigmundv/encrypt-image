import os, json

# This file is used for configuration options that are used in the main app

basedir = os.path.abspath(os.path.dirname(__file__))

class Auth:
		with open("../client_secret.json", 'r') as f:
				oauth2_params = json.loads(f.read())
	
		CLIENT_ID = oauth2_params["web"]["client_id"]
		CLIENT_SECRET = oauth2_params["web"]["client_secret"]
		REDIRECT_URI = 'https://localhost:5000/oauth2callback'
		AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
		TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
		USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
		SCOPE = ['profile', 'email']


class Config:
    APP_NAME = "ImCrypt"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "imcrypt-dev"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # Max filesize of 5MB
    ALLOWED_FILE_TYPES = ["jpeg", "jpg", "png", "bmp", "tiff", "svg", "txt"]


class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "test.db")


class ProdConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "prod.db")


config = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "default": DevConfig
}
