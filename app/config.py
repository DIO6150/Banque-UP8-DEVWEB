import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev"
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../app/instance/bank.db")
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../app/uploads")
    ALLOWED_EXTENSIONS = {'pdf'}

class DevelopmentConfig(Config):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True

class ProductionConfig(Config):
    DEBUG = False
