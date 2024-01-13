from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = 'login.db'
DB_PATH = path.join(path.dirname(__file__), DB_NAME)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'Aseh eraSXG AEXZEX RE'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)
    from .models import Users
    with app.app_context():
        create_database()
        login_manager = LoginManager()
        login_manager.login_view = 'auth.login'
        login_manager.init_app(app)

        @login_manager.user_loader
        def login_user(id):
            return Users.query.get(int(id))

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/auth')
    return app


def create_database():
    if not path.exists(DB_PATH):
        db.create_all()
        print(f'Datbase created at {DB_PATH}')
