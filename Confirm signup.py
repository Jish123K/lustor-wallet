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
username = request.json["username"]

code = request.json["code"]

client = boto3.client("cognito-idp")

try:

    response = client.confirm_sign_up(

        ClientId=CLIENT_ID,

        SecretHash=get_secret_hash(username),

        Username=username,

        ConfirmationCode=code,

        ForceAliasCreation=False,

    )

except client.exceptions.UserNotFoundException:

    raise BadRequest("Username doesn't exist")

except client.exceptions.CodeMismatchException:

    raise BadRequest("Invalid verification code")

except client.exceptions.NotAuthorizedException:

    raise BadRequest("User is already confirmed")

except client.exceptions.LimitExceededException:

    raise BadRequest("Attempt limit exceeded, please try again later")

except Exception as e:

    raise BadRequest(f"Unknown error: {e.__str__()}")

# Get user details from Cognito and insert into DynamoDB

response = client.admin_get_user(UserPoolId=USER_POOL_ID, Username=username)

user = {attr["Name"]: attr["Value"] for attr in response["UserAttributes"]}

user.update({

    "created_at": datetime.now().strftime("%d-%m-%Y"),

    "kdf": request.json["KDF"],

    "asymmetricPublicKey": request.json["asymmetricPublicKey"],

    "encryptedEncryptionKey": request.json["encryptedEncryptionKey"],

    "encryptedAsymmetricPrivateKey": request.json["encryptedAsymmetricPrivateKey"],

    "iterations": request.json["iterations"],

    "passwordDerivedKeyHash": request.json["passwordDerivedKeyHash"],

    "passwordHash": request.json["passwordHash"]

})

table = dynamo.tables[os.environ.get("TABLE_NAME")]

try:

    table.put_item(Item=user)

except Exception as e:

    raise BadRequest(f"The user cannot be updated to DynamoDB: {e.__str__()}")

return jsonify({"message": "The user has been confirmed"})


