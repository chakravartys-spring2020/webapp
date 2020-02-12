#/src/views/UserView
from flask import request, json, Response, Blueprint, g
from flask_httpauth import HTTPBasicAuth
from ..models.UserModel import UserModel, UserSchema
from ..shared.Authentication import Auth
import re, uuid
from flask_bcrypt import Bcrypt

user_api = Blueprint('user_api', __name__)
user_schema = UserSchema()
auth = HTTPBasicAuth()
bcrypt = Bcrypt()

@user_api.route('/', methods = ['POST'])
def create():
  """
  Create User Function
  """
  req_data = request.get_json(force = True)
  valid_email = True    # Verify non-email username cannot be used for account creation
  email_error = ''
  attempted_email = req_data.get('email_address')
  if len(attempted_email) < 7:
    valid_email = False
    email_error = 'email shorter than 7 characters'
  elif re.match("^.+@(\[?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", attempted_email) == None:
    valid_email = False
    email_error = 'please use a standard email convention'
  if valid_email:
      if UserModel.get_user_by_email(attempted_email):
        message = {'error': 'User already exist, please supply another email address'}          # check if user already exist in the db
        return custom_response(message, 400)
      attempted_password = req_data.get('password') # Verify that weak passwords cannot be used to create account
      SpecialSym =['$', '@', '#', '%', '!', '^', '&', '*', '(', ')']
      password_error = ''
      valid_password = True
      if len(attempted_password) < 9:
          valid_password = False
          password_error = 'password shorter than 9 characters'
      elif not any(char.isdigit() for char in attempted_password):
          password_error = 'Password should have at least one numeral'
          valid_password = False
      elif not any(char.isupper() for char in attempted_password):
          password_error = 'Password should have at least one uppercase letter'
          valid_password = False
      elif not any(char.islower() for char in attempted_password):
          password_error = 'Password should have at least one lowercase letter'
          valid_password = False
      elif not any(char in SpecialSym for char in attempted_password):
          password_error = 'Password should have at least one of the symbols $ @ # % ! ^ & * ( )'
          valid_password = False
      if valid_password:
          data = user_schema.load(req_data)
          new_uuid = uuid.uuid4()
          data.update({'id': str(new_uuid)})
          user = UserModel(data)
          user.save()
          ser_data = user_schema.dump(user)
          return custom_response(ser_data, 201)
      else:
          return custom_response({'Bad Request': password_error}, 400)
  else:
      return custom_response({'Bad Request': email_error}, 400)

@user_api.route('/all', methods = ['GET'])
# @auth.login_required
def get_all():
  """
  Get all users
  """
  users = UserModel.get_all_users()
  ser_users = user_schema.dump(users, many = True)
  return custom_response(ser_users, 200)

@user_api.route('/self', methods = ['GET'])
@auth.login_required
def get_self():
  """
  Get self
  """
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  ser_user = user_schema.dump(user_object)
  return custom_response(ser_user, 200)

@user_api.route('/self', methods = ['PUT'])
@auth.login_required
def update():
  """
  Update self
  """
  req_data = request.get_json(force = True)
  update_attempt_list = list(req_data.keys())
  if ("account_updated" in update_attempt_list):
      return custom_response({'Bad Request [400]': 'cannot tamper read-only account_updated timestamp'}, 400)
  elif("email_address" in update_attempt_list):
      return custom_response({'Bad Request [400]': 'cannot tamper read-only email_address'}, 400)
  elif("account_created" in update_attempt_list):
      return custom_response({'Bad Request [400]': 'cannot tamper read-only account_created timestamp'}, 400)
  data = user_schema.load(req_data, partial = True)
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_object.update(data)
  ser_user = user_schema.dump(user_object)
  return custom_response(ser_user, 204)

@user_api.route('/self', methods = ['DELETE'])
@auth.login_required
def delete():
  """
  Delete a user
  """
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_object.delete()
  return custom_response({'message': 'deleted'}, 204)

@user_api.route('/login', methods = ['POST'])
def login():
  """
  User Login Function
  """
  req_data = request.get_json(force = True)
  data = user_schema.load(req_data, partial = True)
  if not data.get('email_address') or not data.get('password'):
      return custom_response({'error': 'you need email and password to sign in'}, 400)
  user = UserModel.get_user_by_email(data.get('email_address'))
  if not user:
      return custom_response({'error': 'user does not exist for given email address'}, 400)
  if not user.check_hash(data.get('password')):
      return custom_response({'error': 'invalid credentials: password does not match'}, 400)
  ser_data = user_schema.dump(user)
  token = Auth.generate_token(ser_data.get('id'))
  return custom_response({'jwt_token': token}, 200)

def custom_response(res, status_code):
  """
  Custom Response Function
  """
  return Response(
    mimetype = "application/json",
    response = json.dumps(res),
    status = status_code
  )

@auth.verify_password
def authenticate(username, password):
    if username and password:
        user_object = UserModel.get_user_by_email(username)
        authorized_boolean = user_object.check_hash(password)
        if not authorized_boolean:
            return False
        else:
            ser_user = user_schema.dump(user_object)
            return custom_response(ser_user, 200)
    return False
