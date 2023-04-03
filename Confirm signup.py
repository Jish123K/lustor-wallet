import os

import json

import uuid

from datetime import datetime

from flask import Flask, jsonify, request

from boto3.dynamodb.conditions import Key, Attr

from flask_dynamo import Dynamo

from werkzeug.exceptions import BadRequest

app = Flask(name)

app.config["DYNAMO_TABLES"] = [{

"TableName": os.environ.get("TABLE_NAME"),

"KeySchema": [

{"AttributeName": "username", "KeyType": "HASH"}

],

"AttributeDefinitions": [

{"AttributeName": "username", "AttributeType": "S"}

],

"BillingMode": "PAY_PER_REQUEST"

}]

app.config["DYNAMO_REGION"] = os.environ.get("DYNAMODB_REGION")

dynamo = Dynamo(app)

USER_POOL_ID = os.environ.get("USER_POOL_ID")

CLIENT_ID = os.environ.get("CLIENT_ID")

CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

def get_secret_hash(username):

msg = username + CLIENT_ID

dig = hmac.new(str(CLIENT_SECRET).encode("utf-8"),

msg=str(msg).encode("utf-8"), digestmod=hashlib.sha256).digest()

d2 = base64.b64encode(dig).decode()

return d2

@app.route("/confirm_signup", methods=["POST"])

def confirm_signup():

# Ensure that required keys are present in the request JSON

for key in ["username", "KDF", "code", "asymmetricPublicKey", "encryptedAsymmetricPrivateKey", "encryptedEncryptionKey", "iterations", "passwordDerivedKeyHash", "passwordHash"]:

if not request.json.get(key):

raise BadRequest(f"{key} is required")
