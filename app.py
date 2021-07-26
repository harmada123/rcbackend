
from flask import Flask, request, jsonify, make_response
from flask_bcrypt import Bcrypt
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy 
from flask_marshmallow import Marshmallow 
from flask_cors import CORS
from marshmallow import fields
import os
from functools import wraps
app = Flask(__name__)
bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'SECRET_KEY'

#init db
db = SQLAlchemy(app)
ma = Marshmallow(app)

cors = CORS(app, resources={r"*": {"origins": "*"}})
#ads Class/Model
class User(db.Model):
  __tablename__ = 'user'
  id = db.Column(db.Integer, primary_key=True)
  user = db.Column(db.String(255), unique=True)
  password = db.Column(db.String(255))

  def __init__(self, user, password):
    self.user = user
    self.password = bcrypt.generate_password_hash(password).decode('utf-8')

class UserSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = User

user_schema = UserSchema()
users_schema = UserSchema(many=True)

class Ads(db.Model):
  __tablename__ = 'ads'
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(255))
  description = db.Column(db.String(255))
  category = db.Column(db.String(255))
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  creator = db.relationship("User", backref="ads") 

  def __init__(self, user_id, title, description, category):
    self.title = title
    self.user_id = user_id
    self.description = description
    self.category = category

class AdsSchema(ma.SQLAlchemyAutoSchema):
  id = fields.Integer()
  title = fields.String()
  description = fields.String()
  category = fields.String()
  creator = fields.Nested(UserSchema, only=('id', 'user'))

ad_schema = AdsSchema()
ads_schema = AdsSchema(many=True)

#users Class/Model


@app.route('/ads', methods=['POST'])
def add_ads():
  user_id = request.json['user_id']
  title = request.json['title']
  description = request.json['description']
  category = request.json['category']

  new_ad = Ads(user_id, title, description, category)
  db.session.add(new_ad)
  db.session.commit()

  return ad_schema.jsonify(new_ad)

@app.route('/ads', methods=['GET'])
def get_ads():
  ads = Ads.query.all()
  ads_schema = AdsSchema(many=True)
  result = ads_schema.dump(ads)
  return jsonify(result), 200


@app.route('/ads/<id>', methods=['GET'])
def get_ads_by_id(id):
  ads = Ads.query.get(id)
  return ad_schema.jsonify(ads)

@app.route('/ads/<id>', methods=['PUT'])
def update_ads(id):
  ads = Ads.query.get(id)

  title = request.json['title']
  description = request.json['description']
  category = request.json['category']

  ads.title = title
  ads.description = description
  ads.category = category

  db.session.commit()

  return ads_schema.jsonify(ads)

# Delete ads
@app.route('/ads/<id>', methods=['DELETE'])
def delete_ads(id):
  ads = Ads.query.get(id)
  db.session.delete(ads)
  db.session.commit()

  return jsonify({ "message": "Deleted" })


@app.route('/category', methods=['POST'])
def ads_filter_by_category():
  ad = request.json['category']
  ads= Ads.query.filter_by(category=ad)
  return ads_schema.jsonify(ads)

def token_required(f):
  # @wraps(f)z
  def decorated(*args, **kwargs):
    token = request.args.get('token')

    if not token:
      return jsonify({'message' : 'Token is missing!'}), 403
    try: 
      data = jwt.decode(token, app.config['SECRET_KEY'])
    except:
      return jsonify({'message' : 'Token is invalid!'}), 403

    return f(*args, **kwargs), 200

  return decorated

@app.route('/protected', methods=['POST'])
@token_required
def protected():
  token = request.json['token']
  data = jwt.decode(token, app.config['SECRET_KEY'])
  return jsonify({'message' : 'This is only available for people with valid tokens.', 'token': data, 'status' : 200 })

@app.route('/login', methods=['POST'])
def login():
  user = request.json['user']
  password = request.json['password']

  users = User.query.filter_by(user=user).first()

  if users is None: return make_response(jsonify({'error' : 'Unauthorize', 'status': 401 })), 401
  
  if bcrypt.check_password_hash(users.password, password) :
    token = jwt.encode({ "user": { "user": user, "id": users.id }, 'exp':  datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token' : token.decode('UTF-8') }) , 200

  return make_response('Could Verify!', 401, { 'WWW-Authenticate': 'Basic realm="Login Required"' })

@app.route('/register', methods=['POST'])
def register():
  user = request.json['user']
  password = request.json['password']

  users = User.query.filter_by(user=user).first() 

  if users is None :
    user = request.json['user']
    password = request.json['password']

    user = User(user, password)
    db.session.add(user)
    db.session.commit()

    return user_schema.jsonify(user)


  return jsonify({ "Error": "User Exist" })

if __name__ == '__main__':
  app.run(debug=True)

