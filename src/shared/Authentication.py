#src/shared/Authentication
import os
import datetime
from flask import json, Response, request, g
from functools import wraps
from ..models.UserModel import UserModel

class Auth():
  """
  Auth Class
  """
  
  # decorator
  @staticmethod
  def auth_required(func):
    """
    Auth decorator
    """
    @wraps(func)
    def decorated_auth(*args, **kwargs):
      if 'api-token' not in request.headers:
        return Response(
          mimetype = "application/json",
          response = json.dumps({'error': 'Authentication token is not available, please login to get one'}),
          status = 400
        )
      token = request.headers.get('api-token')
      data = Auth.decode_token(token)
      if data['error']:
        return Response(
          mimetype = "application/json",
          response = json.dumps(data['error']),
          status = 400
        )

      user_id = data['data']['user_id']
      check_user = UserModel.get_one_user(user_id)
      if not check_user:
        return Response(
          mimetype = "application/json",
          response = json.dumps({'error': 'user does not exist, invalid token'}),
          status = 400
        )
      g.user = {'id': user_id}
      return func(*args, **kwargs)
    return decorated_auth
