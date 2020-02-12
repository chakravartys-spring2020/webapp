#src/app.py
from flask_api import FlaskAPI  # Flask API is a drop-in replacement for Flask that provides an implementation of browsable APIs similar to what Django REST framework provides
from flask_talisman import Talisman # Wraps Flask app with a Talisman
from flask_seasurf import SeaSurf # Flask extension for preventing cross-site request forgery
from .config import app_configurations
from .models import db, bcrypt
from .views.UserView import user_api as user_blueprint  # import user_api blueprint
from .views.BillView import bill_api as bill_blueprint  # import bill_api blueprint

def create_app(environment_selected):
  """
  Create app
  """
  app = FlaskAPI(__name__) # app initiliazation
  app.config['SQLALCHEMY_ECHO'] = True                              # Configure the SQLAlchemy part of the app instance
  app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
  app.config.from_object(app_configurations[environment_selected])

  SELF = "'self'"

  talisman = Talisman(    # Forces all prod connects to https, enables HSTS, session cooke to httponly
    app,
    content_security_policy={
        'default-src': SELF,
        'img-src': '*',
        'script-src': [
            SELF,
            'some.cdn.com',
        ],
        'style-src': [
            SELF,
            'another.cdn.com',
        ],
    },
    content_security_policy_nonce_in=['script-src'],
    feature_policy={
        'geolocation': '\'none\'',
    }
  )

  bcrypt.init_app(app) # initializing bcrypt
  db.init_app(app)

  app.register_blueprint(user_blueprint, url_prefix='/v1/user')
  app.register_blueprint(bill_blueprint, url_prefix='/v1/bill')

  @app.route('/', methods=['GET'])
  def index():
    """
    example endpoint
    """
    return 'Congratulations! Your first endpoint is working!'

  return app
