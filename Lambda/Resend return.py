import hmac

import hashlib

import base64

import uuid

import requests

from botocore.exceptions import ClientError

from cognito_identity_pool.client import CognitoIdentityProviderClient

CLIENT_ID = ''

CLIENT_SECRET = ''

def get_secret_hash(username):

    msg = username + CLIENT_ID

    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 

        msg = str(msg).encode('utf-8'),

        digestmod=hashlib.sha256).digest()

    d2 = base64.b64encode(dig).decode()

    return d2

def resend_confirmation_code(username):

    client = CognitoIdentityProviderClient(CLIENT_ID, CLIENT_SECRET)

    try:

        response = client.resend_confirmation_code(username, get_secret_hash(username))

        print (username)

    except ClientError as e:

        if e.response['Error']['Code'] == 'UserNotFoundException':

            return {"error": True, "success": False, "message": "Username doesn't exist"}

        elif e.response['Error']['Code'] == 'InvalidParameterException':

            return {"error": True, "success": False, "message": "User is already confirmed"}

        else:

            return {"error": True, "success": False, "message": f"Unknown error {e.__str__()} "}

      

    return  {"error": False, "success": True}

def lambda_handler(event, context):

    try:

        username = event['username']

        response = resend_confirmation_code(username)

    except KeyError:

        return {"error": True, "success": False, "message": "Username not provided"}

      

    return response

