from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from .routes import main

db = SQLAlchemy()
csrf = CSRFProtect()

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db.init_app(app)
csrf.init_app(app)

# Register blueprints
app.register_blueprint(main)
