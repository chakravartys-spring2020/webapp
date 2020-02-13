#/src/views/FileView.py
from flask import request, Blueprint, json, Response
from ..models.BillModel import BillModel, BillSchema
from ..models.UserModel import UserModel, UserSchema
from ..models.FileModel import FileModel, FileSchema
from flask import jsonify
from flask_httpauth import HTTPBasicAuth
import uuid

file_api = Blueprint('file_api', __name__)
user_schema = UserSchema()
bill_schema = BillSchema()
file_schema = FileSchema()
auth = HTTPBasicAuth()

@file_api.route('/', methods=['POST'])
def create():
  """
  Create File Function
  """



@app.route('/v1/bill/<billid>/file/<fileid>', methods=['GET'])
def getfile(billid,fileid):
    bill_id=billid
    username = request.authorization.username
    passwordinfo = request.authorization.password
