# /run.py
import os
from src.app import create_app

if __name__ == '__main__':
  environment_selected = os.getenv('FLASK_ENV') # $export FLASK_ENV=development
  app = create_app(environment_selected)
  app.run()  # run app
