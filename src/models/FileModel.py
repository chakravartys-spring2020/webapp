# src/models/FileModel.py
from . import db
from marshmallow import fields, Schema
from sqlalchemy.dialects import postgresql
from uuid import uuid4
import datetime
from sqlalchemy import Table, Column, Float, Integer, String, MetaData, ForeignKey
from haikunator import Haikunator

class FileModel(db.Model):
  """
  This class represents the file table
  """
  __tablename__ = 'files'
  id = db.Column(db.String(128), primary_key = True, default = uuid4, unique = True)
  file_name = db.Column(db.Text, nullable = False)
  url = db.Column(db.String(128), nullable = False)
  upload_date = db.Column(db.DateTime)
  file_size = db.Column(db.Float(precision = 1, asdecimal = True, decimal_return_scale = None), nullable = False)
  file_origin = db.Column(db.Text, nullable = True)
  hash_digest = db.Column(db.String(), nullable = True)
  file_owner = db.Column(db.String(128), nullable = False)
  bill_attached_to = db.Column(db.String(128), db.ForeignKey('bills.id'), nullable = False)

  # class constructor
  def __init__(self, data):
    self.id = data.get('id')
    self.file_name = data.get('file_name')
    self.url = Haikunator().haikunate(delimiter = '.', token_hex = True, token_length = 6)
    self.upload_date = datetime.datetime.utcnow()
    self.file_size = data.get('file_size')
    self.file_origin = data.get('file_origin')
    self.hash_digest = data.get('hash_digest')
    self.file_owner = data.get('file_owner')
    self.bill_attached_to = data.get('bill_attached_to')

  def save(self):
    db.session.add(self)
    db.session.commit()

  def update(self, data):
    for key, item in data.items():
      setattr(self, key, item)
    self.upload_date = datetime.datetime.utcnow()
    db.session.commit()

  def delete(self):
    db.session.delete(self)
    db.session.commit()

  @staticmethod
  def get_all_files():
    return FileModel.query.all()

  @staticmethod
  def get_files_by_owner_id(value):
    return FileModel.query.filter_by(file_owner = value).all()

  @staticmethod
  def select_file_by_bill_id(value):
      return FileModel.query.filter_by(bill_attached_to = value).first()

  @staticmethod
  def delete_file(value):
      FileModel.query.filter_by(id = value).delete()
      db.session.commit()



  @staticmethod
  def get_one_file(id):
    return FileModel.query.get(id)

  def __repr__(self):
    return '<id {}>'.format(self.id)

class FileSchema(Schema):
  """
  File Schema
  """
  id = fields.Str(dump_only = True)
  file_name = fields.Str(required = True)
  url = fields.Str(required = True, dump_only = True)
  upload_date = fields.DateTime(required = True, dump_only = True)
  file_size = fields.Float(required = True, dump_only = True)
  file_origin = fields.Str(required = False, dump_only = True)
  hash_digest = fields.Str(required = True, dump_only = True)
  file_owner = fields.Str(required = True, dump_only = True)
  bill_attached_to = fields.Str(required = True, dump_only = True)
