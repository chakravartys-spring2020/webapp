#/src/views/BillView.py
from datetime import date
from flask import request, Blueprint, json, Response
from haikunator import Haikunator
from werkzeug.utils import secure_filename
from ..models.BillModel import BillModel, BillSchema
from ..models.UserModel import UserModel, UserSchema
from ..models.FileModel import FileModel, FileSchema
from flask import jsonify
from flask_httpauth import HTTPBasicAuth
import boto3, datetime, hashlib, os, urllib.request, uuid, shutil

ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

bill_api = Blueprint('bill_api', __name__)
user_schema = UserSchema()
bill_schema = BillSchema()
file_schema = FileSchema()
auth = HTTPBasicAuth()

@bill_api.route('/', methods=['POST'])
@auth.login_required
def create():
  """
  Create Bill Function
  """
  req_data = request.get_json(force = True)
  bill_data = bill_schema.load(req_data)
  new_uuid = uuid.uuid4()
  bill_data.update({'id': str(new_uuid)})
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_id = user_object.id
  bill_data.update({'owner_id': user_id})
  bill_object = BillModel(bill_data)
  bill_object.save()
  ser_data = bill_schema.dump(bill_object)
  return custom_response(ser_data, 201)

@bill_api.route('/<string:bill_id>/file/<string:file_id>', methods=['GET'])
@auth.login_required
def get_file(bill_id, file_id):
  """
  Get One File
  """
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  target_bill = BillModel.get_one_bill(bill_id)
  if (target_bill.owner_id == user_object.id):
    requested_file = FileModel.select_file_by_bill_id(bill_id)
    if requested_file is None:
      return custom_response('Unacceptable bill and file id mismatch', 406)
    else:
      if (requested_file.id == file_id):
        file_object = file_schema.dump(requested_file)
        return custom_response(file_object, 200)
      else:
        return custom_response('Expected file not found in specified bill', 404)
  else:
    return custom_response('Current user unauthorized to view specified bill', 401)

@bill_api.route('/<string:bill_id>/file/<string:file_id>/', methods=['DELETE'])
@auth.login_required
def delete_file(bill_id, file_id):
  """
  Delete One File
  """
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  target_bill = BillModel.get_one_bill(bill_id)
  if (target_bill.owner_id == user_object.id):
    requested_file = FileModel.select_file_by_bill_id(bill_id)
    if requested_file is None:
      return custom_response('Unacceptable bill and file id mismatch', 406)
    else:
      if (requested_file.id == file_id):
        print("STARTTTT monitorng")
        directory_to_delete = os.path.abspath(os.getcwd()) + "/attachments/" + bill_id + "/" + file_id
        print("CURRENT DIRRRR")  
        print(os.getcwd())
        print("DIRRRR 2 DELETEEEEE")
        print(directory_to_delete)
        # os.chdir("attachments")
        # print(os.getcwd())
        print("ENDDDDD garen monitorng")  
        # os.chdir(directory_to_delete)
        try:
            shutil.rmtree(os.getcwd())
        except OSError as e:
            print("Error: %s : %s" % (os.getcwd(), e.strerror))
        requested_file.delete()
        return custom_response({'message': 'Specified file deleted successfully'}, 204)
      else:
        return custom_response('Expected file not found in specified bill', 404)
  else:
    return custom_response('Current user unauthorized to delete specified bill', 401)

# @bill_api.route('/<string:bill_id>/file/', methods=['POST'])
# @auth.login_required
# def upload_file(bill_id):
#   """
#   Create File Function
#   """
#   # First check if bill id attempted to be attached to exists and belongs to user
#   bill = BillModel.get_one_bill(bill_id)
#   if not bill:
#       return custom_response({'error': 'Bill Not Found'}, 404)
#   email_address_in_auth_header = request.authorization.username
#   user_object = UserModel.get_user_by_email(email_address_in_auth_header)
#   user_id = user_object.id
#   if (user_id != bill.owner_id):
#       return custom_response({'error': 'Unauthorized Access to Bill'}, 401)
#   bill_data = bill_schema.dump(bill)  # bill exists and belongs to user attempting to post file
#   if 'file' not in request.files:   # check if the post request has an attached file
#       custom_response({'error': 'No file part in the request'}, 400)
#   file = request.files['file']
#   if file.filename == '':
#       custom_response({'error': 'No file selected for uploading'}, 400)
#   if file and allowed_file(file.filename):  # check if destination bill already exists in the file models
#       bill_in_question = FileModel.select_file_by_bill_id(bill_id)  # since each bill can only have 1 attachment, don't proceed if bill already exists     
#       if bill_in_question:  # if bill in question exists, can't add another file attachment
#           return custom_response("bill already has file attached, please delete attachment!", 400)
#       file_id = str(uuid.uuid4()) # bill does not contain an attachment so continue to build file metadata 
#       filename = secure_filename(file.filename)  

#       location_to_save = os.path.abspath(os.getcwd()) + "/attachments/" + bill_id + "/" + file_id + "/"
#       try:
#         os.makedirs(location_to_save)
#       except OSError:
#         print ("Creation of the directory %s failed")
#       else:
#         print ("Successfully created the directory %s")
      
#       os.chdir(location_to_save)
#       file.save(os.path.join(location_to_save, filename))
#       file.seek(0, os.SEEK_END)
#       file_size = file.tell()
#       url = Haikunator().haikunate(delimiter = '.', token_hex = True, token_length = 6)

#       hash_digest = hashlib.md5(file.stream.read()).hexdigest() 
#       upload_date = str(datetime.datetime.utcnow())
#       file_origin = str(os.path.abspath(filename))

#       file_dict = {'id': file_id, 'url': url, 'hash_digest': hash_digest, 'file_size': file_size, 'upload_date': upload_date, 'file_name': filename, 'file_origin': file_origin, 'file_owner': user_id, 'bill_attached_to': bill_id}
#       file_data = file_schema.load(file_dict)
#       file_object = FileModel(file_data)  # save file object to postgresql file table
#       file_object.save()
#       file_http_response = file_schema.dump(file_object)
#       return custom_response(file_http_response, 201)
#   else:
#       return custom_response('Allowed file types are pdf, png, jpg, jpeg', 400)

@bill_api.route('/<string:bill_id>/file/', methods=['POST'])
@auth.login_required
def upload_file(bill_id):
    """
    Upload File to S3 Bucket
    """
    # First check if bill id attempted to be attached to exists and belongs to user
    bill = BillModel.get_one_bill(bill_id)
    if not bill:
        return custom_response({'error': 'Bill Not Found'}, 404)
    email_address_in_auth_header = request.authorization.username
    user_object = UserModel.get_user_by_email(email_address_in_auth_header)
    user_id = user_object.id
    if (user_id != bill.owner_id):
        return custom_response({'error': 'Unauthorized Access to Bill'}, 401)
    bill_data = bill_schema.dump(bill)  # bill exists and belongs to user attempting to post file
    if 'file' not in request.files:   # check if the post request has an attached file
        custom_response({'error': 'No file part in the request'}, 400)

    file = request.files['file']

    if file.filename == '':
        custom_response({'error': 'No file selected for uploading'}, 400)

    if file and allowed_file(file.filename):  # check if destination bill already exists in the file models
        bill_in_question = FileModel.select_file_by_bill_id(bill_id)  # since each bill can only have 1 attachment, don't proceed if bill already exists

        if bill_in_question:  # if bill in question exists, can't add another file attachment
            return custom_response("bill already has file attached, please delete attachment!", 400)

        s3_resource = boto3.resource('s3')
        bucketname = ""
        for bucket in s3_resource.buckets.all():
            bucketname = bucket.name
        content_type = request.mimetype

        s3_client = boto3.client('s3',
                              region_name='us-east-2',
                              aws_access_key_id=os.environ['ACCESS_KEY'],
                              aws_secret_access_key=os.environ['SECRET_KEY'])

        file_id = str(uuid.uuid4()) # bill does not contain an attachment so continue to build file metadata
        filename = secure_filename(file.filename)  # This is convenient to validate your filename, otherwise just use file.filename

        s3_client.put_object(Body=file,
                          Bucket=bucketname,
                          Key=filename,
                          ContentType=content_type)

        file_size = s3_client.head_object(Bucket=bucketname, Key=filename).get('ContentLength')
        url = Haikunator().haikunate(delimiter = '.', token_hex = True, token_length = 6)
        upload_date = str(s3_client.head_object(Bucket=bucketname, Key=filename).get('LastModified'))
        hash_digest = s3_client.head_object(Bucket=bucketname, Key='test.pdf').get('ETag')

        file_dict = {'id': file_id, 'url': url, 'hash_digest': hash_digest, 'file_size': file_size, 'upload_date': upload_date, 'file_name': filename, 'file_owner': user_id, 'bill_attached_to': bill_id}
        file_data = file_schema.load(file_dict)
        file_object = FileModel(file_data)  # save file object to postgresql file table
        file_object.save()
        file_http_response = file_schema.dump(file_object)
        return custom_response(file_http_response, 201)
    else:
        return custom_response('Allowed file types are pdf, png, jpg, jpeg', 400)

@bill_api.route('/all/', methods=['GET'])
@auth.login_required
def get_all():
  """
  Get All Bills
  """
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_id = user_object.id
  bills = BillModel.get_bills_by_owner_id(user_id)
  data = bill_schema.dump(bills, many = True)
  return custom_response(data, 200)

@bill_api.route('/<string:bill_id>', methods=['GET'])
@auth.login_required
def get_one(bill_id):
  """
  Get Authorized Bill
  """
  bill = BillModel.get_one_bill(bill_id)
  if not bill:
    return custom_response({'error': 'Bill Not Found'}, 404)
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_id = user_object.id
  if (user_id != bill.owner_id):
      return custom_response({'error': 'Unauthorized Access to Bill'}, 401)
  data = bill_schema.dump(bill)
  return custom_response(data, 200)

@bill_api.route('/<string:bill_id>', methods=['PUT'])
@auth.login_required
def update(bill_id):
  """
  Update An Authorized Bill
  """
  req_data = request.get_json(force = True)
  bill = BillModel.get_one_bill(bill_id)
  if not bill:
    return custom_response({'error': 'Bill Not Found'}, 404)
  data = bill_schema.dump(bill)
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_id = user_object.id
  if (data.get('owner_id') != user_id):
    return custom_response({'error': 'Permission Denied'}, 400)
  data_to_be_updated = bill_schema.load(req_data, partial = True)
  bill.update(data_to_be_updated)
  updated_date = bill_schema.dump(bill)
  return custom_response(updated_date, 200)

@bill_api.route('/<string:bill_id>', methods=['DELETE'])
@auth.login_required
def delete(bill_id):
  """
  Delete An Authorized Bill
  """
  bill = BillModel.get_one_bill(bill_id)
  if not bill:
    return custom_response({'error': 'Bill Not Found'}, 404)
  data = bill_schema.dump(bill)
  email_address_in_auth_header = request.authorization.username
  user_object = UserModel.get_user_by_email(email_address_in_auth_header)
  user_id = user_object.id
  if (data.get('owner_id') != user_id):
    return custom_response({'error': 'Unauthorized to Delete Bill'}, 401)
  bill.delete()
  return custom_response({'message': 'Deleted Successfully'}, 204)

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
  """
  Verify Password
  """
  if username and password:
      user_object = UserModel.get_user_by_email(username)
      authorized_boolean = user_object.check_hash(password)
      if not authorized_boolean:
          return False
      else:
          ser_user = user_schema.dump(user_object)
          return custom_response(ser_user, 200)
  return False
