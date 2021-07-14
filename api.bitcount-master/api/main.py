import os
import jwt
import json
import jsonschema
import pprint
import uuid
from datetime import datetime, timedelta
from flask import Flask, abort, request, jsonify, request
from flask_restful import Resource, Api
from .utils import json_response
from flask_pymongo import PyMongo
from bson import Binary, Code
from bson.json_util import dumps
from cryptography.fernet import Fernet

# App
app = Flask(__name__)
# Database
app.config["MONGO_URI"] = "mongodb://localhost:27017/bitcount"
# App to api
api = Api(app)
mongo = PyMongo(app)
# Base path
app_base_path = "/api/v1"

###
#   Resources
###

# Account resource
class Accounts(Resource):
    # Handles get
    def get(self, process):
        return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    # Handles post
    def post(self, process):
        # Json form
        data = request.get_json()
        # Payload
        payload = {}
        # Status code
        code = 0
        # Check process
        if process == 'signup':
            # Local variable
            guid = str(uuid.uuid4())
            ak = sk = Fernet.generate_key()
            # Form object
            user_data = {
                'guid': guid,
                'firstname': str(data['first_name']),
                'middlename': str(data['middle_name']),
                'lastname': str(data['last_name']),
                'email': str(data['email']),
                'birthdate': str(data['birthdate']),
                'phone_number': str(data['phone_number']),
                'is_active': True,
                'created_at': str(datetime.now()),
                'updated_at': str(datetime.now()),
                'deleted_at': ''
            }
            account_data = {
                'guid': guid,
                'p': str(Fernet(ak).encrypt(str(data['p']))),
                'last_login': str(data['last_login']),
                'is_active': True,
                'created_at': str(datetime.now()),
                'updated_at': str(datetime.now()),
                'deleted_at': ''
            }
            key_data = {
                'guid': guid,
                'ak': ak,
                'sk': sk,
                'provider': 'bitcount',
                'is_deleted': False,
                'created_at': str(datetime.now()),
                'updated_at': str(datetime.now()),
                'deleted_at': ''
            }
            # Try insertion
            try:
                # Insert user data to collection, returns oid
                user_inserted_id = mongo.db.users.insert_one(user_data).inserted_id # 1st layer
                key_inserted_id = mongo.db.keys.insert_one(key_data).inserted_id # 2nd layer
                account_inserted_id = mongo.db.accounts.insert_one(account_data).inserted_id # 3rd layer
                # Check inserted id for each layers
                if not str(user_inserted_id) and str(account_inserted_id) and str(key_inserted_id):
                    payload['message'] = 'Signup failed'
                    payload['status'] = False
                    code = 200
                else:
                    payload['message'] = 'Signup success'
                    payload['status'] = True
                    code = 201
            except:
                pass
        elif process == 'signin':
            # Form object
            user_data = {
                'is_active': True,
                'email': str(data['e'])
            }
            # Try find
            try:
                # Find user
                user_data_result = mongo.db.users.find_one(user_data, {'guid': 1, '_id': 0})
                # Check user existence
                if not (user_data_result is None):
                    # Find user key
                    key_data_result = mongo.db.keys.find_one({'guid': str(user_data_result['guid']), 'is_deleted': False}, {'ak': 1, '_id': 0})
                    # Check user key existence
                    if (str(key_data_result['ak'])):
                        # Find user account
                        account_data_result = mongo.db.accounts.find_one({'guid': str(user_data_result['guid']), 'is_active': True})
                        # Check user account existence
                        if (str(account_data_result['p'])):
                            # Check correctness of password
                            if str(data['p']) == str(Fernet(str(key_data_result['ak'])).decrypt(str(account_data_result['p']))):
                                # Token body
                                token = {
                                    "guid": str(user_data_result['guid']),
                                    "iss": "bitcount",
                                    "iat": datetime.utcnow(),
                                    "exp": datetime.utcnow() + timedelta(hours=168)
                                }
                                # Send authorized access
                                payload['message'] = 'Authorized'
                                payload['status'] = True
                                payload['data'] = jwt.encode(token, 'secret')
                                code = 200
                            else:
                                # Send failed authentication
                                payload['message'] = 'Authentication failed'
                                payload['status'] = False
                                code = 401
                        else:
                            # User needs to be deleted because of layer signup failure
                            payload['message'] = 'Signup for new account'
                            payload['status'] = False
                            code = 500
                    else:
                        # User needs to be deleted because of layer signup failure
                        payload['message'] = 'Signup for new account'
                        payload['status'] = False
                        code = 500
                else:
                    payload['message'] = 'Signup for new account'
                    payload['status'] = False
                    code = 401
            except:
                pass
        payload['timestamp'] = str(datetime.now())
        return json_response(dumps(payload), code)

# User resource
class User(Resource):
    def get(self):
        # Local variable
        code = 0
        payload = {}
        # Check headers applied
        if request.headers.get('Authorization'):
            # Token
            token = request.headers.get('Authorization').replace('Bearer','').strip()
            # Try token decode
            try:
                # Token data
                data = jwt.decode(token, 'secret')
                # User guid
                guid = data['guid']
                # Retrieve user data
                user_data_result = mongo.db.users.find_one({'guid': guid, 'is_active': True}, {'guid': 0,'_id': 0})
                # Check user result
                if user_data_result:
                    payload['status'] = True
                    payload['message'] = 'Success'
                    payload['data'] = user_data_result
                    payload['timestamp'] = str(datetime.now())
                    return json_response(dumps(payload), code)
            except jwt.ExpiredSignatureError:
                # Token expired
                return json_response(json.dumps({'message': 'Token expired...'}), 401)
        else:
            return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    def post(self):
        return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    def put(self):
        # Local variable
        code = 0
        payload = {}
        request_data = request.get_json()
        # Check headers applied
        if request.headers.get('Authorization'):
            # Token
            token = request.headers.get('Authorization').replace('Bearer','').strip()
            # Try token decode
            try:
                # Token data
                data = jwt.decode(token, 'secret')
                # User guid
                guid = data['guid']
                # Find guid
                guid_result = mongo.db.users.find_one({'guid': guid, 'is_active': True}, {'guid': 0,'_id': 0})
                # Check guid is active
                if guid_result is None:
                    return json_response(json.dumps({'message': 'Token expired...'}), 401)
                # Add data to request data
                request_data['updated_at'] = str(datetime.now())
                # Update result
                update_result = mongo.db.users.find_and_modify({'guid': guid, 'is_active': True}, {"$set": request_data})
                # Check update result
                if update_result is not None:
                    # Success response
                    payload['message'] = 'Success'
                    payload['status'] = True
                    code = 200
                else:
                    # Failed response
                    payload['message'] = 'Failed'
                    payload['status'] = False
                    code = 400
                payload['timestamp'] = str(datetime.now())
                return json_response(dumps(payload), code)
            except jwt.ExpiredSignatureError:
                # Token expired
                return json_response(json.dumps({'message': 'Token expired...'}), 401)
        else:
            return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    def delete(self):
        # Local variable
        code = 0
        payload = {}
        request_data = request.get_json()
        # Check headers applied
        if request.headers.get('Authorization'):
            # Token
            token = request.headers.get('Authorization').replace('Bearer','').strip()
            # Try token decode
            try:
                # Token data
                data = jwt.decode(token, 'secret')
                # User guid
                guid = data['guid']
                # Find guid
                guid_result = mongo.db.users.find_one({'guid': guid, 'is_active': True}, {'guid': 0,'_id': 0})
                # Check guid is active
                if guid_result is None:
                    return json_response(json.dumps({'message': 'Token expired...'}), 401)
                # Delete user result
                delete_user_result = mongo.db.users.find_and_modify({'guid': guid}, {"$set": {"is_active": False, "updated_at": str(datetime.now()), "deleted_at": str(datetime.now())}})
                # Delete account result
                delete_account_result = mongo.db.accounts.find_and_modify({'guid': guid}, {"$set": {"is_active": False, "updated_at": str(datetime.now()), "deleted_at": str(datetime.now())}})
                # Delete keys result
                delete_keys_result = mongo.db.keys.find_and_modify({'guid': guid}, {"$set": {"is_deleted": True, "updated_at": str(datetime.now()), "deleted_at": str(datetime.now())}})
                # Check update result
                if delete_user_result and delete_account_result and delete_keys_result is not None:
                    # Success response
                    payload['message'] = 'Success'
                    payload['status'] = True
                    code = 200
                else:
                    # Failed response
                    payload['message'] = 'Failed'
                    payload['status'] = False
                    code = 400
                payload['timestamp'] = str(datetime.now())
                return json_response(dumps(payload), code)
            except jwt.ExpiredSignatureError:
                # Token expired
                return json_response(json.dumps({'message': 'Token expired...'}), 401)
        else:
            return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)

# Wallet resource
class Wallet(Resource):
    def get(self):
        # Local variable
        code = 0
        payload = {}
        # Check headers applied
        if request.headers.get('Authorization'):
            # Token
            token = request.headers.get('Authorization').replace('Bearer','').strip()
            # Try token decode
            try:
                # Token data
                data = jwt.decode(token, 'secret')
                # User guid
                guid = data['guid']
                # Retrieve wallet data
                wallet_data_result = mongo.db.wallets.find_one({'guid': guid, 'is_active': True}, {'guid': 0,'_id': 0})
                # Check user result
                if user_data_result:
                    payload['status'] = True
                    payload['message'] = 'Success'
                    payload['data'] = user_data_result
                    payload['timestamp'] = str(datetime.now())
                    return json_response(dumps(payload), code)
            except jwt.ExpiredSignatureError:
                # Token expired
                return json_response(json.dumps({'message': 'Token expired...'}), 401)
        else:
            return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    def post(self):
        # Local variable
        code = 0
        payload = {}
        # Check headers applied
        if request.headers.get('Authorization'):
            # Token
            token = request.headers.get('Authorization').replace('Bearer','').strip()
            # Try token decode
            try:
                # Token data
                data = jwt.decode(token, 'secret')
                # User guid
                guid = data['guid']
                # Find guid
                guid_result = mongo.db.users.find_one({'guid': guid, 'is_active': True}, {'guid': 0,'_id': 0})
                # Check guid is stll active in users, just to verify that the user account still exists/being used
                if guid_result is None:
                    return json_response(json.dumps({'message': 'Token expired...'}), 401)
                # Wallet data
                wallet_data = {
                    'guid': guid,
                    'created_at': str(datetime.now()),
                    'updated_at': '',
                    'is_deleted': False
                }
                # Create user wallet
                wallet_inserted_id = mongo.db.wallets.insert_one(user_data).inserted_id
                # Check wallet result
                if wallet_inserted_id:
                    payload['message'] = 'Wallet creation success'
                    payload['status'] = True
                    code = 201
                else:
                    payload['message'] = 'Wallet creation failed'
                    payload['status'] = False
                    code = 401
                payload['timestamp'] = str(datetime.now())
                return json_response(dumps(payload), code)
            except jwt.ExpiredSignatureError:
                # Token expired
                return json_response(json.dumps({'message': 'Token expired...'}), 401)
        else:
            return json_response(json.dumps({'message': 'Unauthorized access...'}), 400)
    # Process of bitcoin wallet creation (blockcypher)
    def __bitcoin_wallet_creation_blockcypher(self):
        pass
###
#   Routes
###

# User routes
api.add_resource(User, '/api/v1/users', endpoint="user")
# Accounts routes
api.add_resource(Accounts, '/api/v1/accounts/<string:process>', endpoint="account")
# Wallet routes
api.add_resource(User, '/api/v1/wallets', endpoint="wallet")