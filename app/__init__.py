from flask import Flask
from .db import init_db
from .utils import setup_login

def create_app():
    app = Flask(__name__)
    app.config.from_object("app.config.DevelopmentConfig")

    init_db(app)
    setup_login(app)

    # Enregistre les blueprints
    from .routes.auth import auth_bp
    from .routes.home import home_bp
    from .routes.user import user_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    """
    from .routes.admin import admin_bp
    from .routes.user import user_bp
    from .routes.loan import loan_bp

    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(loan_bp)
    """

    return app
