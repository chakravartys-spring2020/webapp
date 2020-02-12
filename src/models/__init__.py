#src/models/__init__.py

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

# from .UserModel import UserModel, UserSchema

# initialize sql-alchemy for our db orm
db = SQLAlchemy()
bcrypt = Bcrypt()

from .UserModel import UserModel, UserSchema
