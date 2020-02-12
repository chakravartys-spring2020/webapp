# src/models/BillModel.py
from . import db
from marshmallow import fields, Schema
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects import postgresql
from uuid import uuid4
import datetime
from sqlalchemy import Table, Column, Float, Integer, String, MetaData, ForeignKey

class BillModel(db.Model):
  """
  This class represents the bill table
  """
  __tablename__ = 'bills'
  id = db.Column(db.String(128), primary_key = True, default = uuid4, unique = True)
  created_ts = db.Column(db.DateTime)
  updated_ts = db.Column(db.DateTime)
  owner_id = db.Column(db.String(128), db.ForeignKey('users.id'), nullable = False)
  vendor = db.Column(db.Text, nullable = False)
  bill_date = db.Column(db.Date(), nullable = False)
  due_date = db.Column(db.Date(), nullable = False)
  amount_due = db.Column(db.Float(precision = 2, asdecimal = True, decimal_return_scale = None), nullable = False)
  categories = db.Column(postgresql.ARRAY(String))
  payment_codes = ('paid', 'due', 'past_due', 'no_payment_required')
  payment_codes_enum = ENUM(*payment_codes, name = "payment_code")
  paymentStatus = db.Column(payment_codes_enum, nullable = False)

  # class constructor
  def __init__(self, data):
    self.id = data.get('id')
    self.vendor = data.get('vendor')
    self.bill_date = data.get('bill_date')
    self.due_date = data.get('due_date')
    self.amount_due = data.get('amount_due')
    self.categories = data.get('categories')
    self.paymentStatus = data.get('paymentStatus')
    self.owner_id = data.get('owner_id')
    self.created_ts = datetime.datetime.utcnow()
    self.updated_ts = datetime.datetime.utcnow()

  def save(self):
    db.session.add(self)
    db.session.commit()

  def update(self, data):
    for key, item in data.items():
      setattr(self, key, item)
    self.modified_at = datetime.datetime.utcnow()
    db.session.commit()

  def delete(self):
    db.session.delete(self)
    db.session.commit()

  @staticmethod
  def get_all_bills():
    return BillModel.query.all()

  @staticmethod
  def get_bills_by_owner_id(value):
    return BillModel.query.filter_by(owner_id = value).all()

  @staticmethod
  def get_one_bill(id):
    return BillModel.query.get(id)

  def __repr__(self):
    return '<id {}>'.format(self.id)

class BillSchema(Schema):
  """
  Bill Schema
  """
  id = fields.Str(dump_only = True)
  vendor = fields.Str(required = True)
  owner_id = fields.Str(required = True, dump_only = True)
  created_ts = fields.DateTime(dump_only = True)
  updated_ts = fields.DateTime(dump_only = True)
  bill_date = fields.Date(required = True)
  due_date = fields.Date(required = True)
  amount_due = fields.Float(required = True)
  categories = fields.List(fields.String(), required = True)
  paymentStatus = fields.Str(required = True)
