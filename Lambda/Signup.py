import os

import hashlib

import uuid

import requests

import json

USER_POOL_ID = ''

CLIENT_ID = ''

CLIENT_SECRET = ''

AWS_REGION = ''

def lambda_handler(event, context):

    for field in ["username", "email", "password", "name"]:

        if not event.get(field):

            return {"error": False, "success": True, 'message': f"{field} is not present", "data": None}

    username = event['username']

    email = event["email"]

    password = event['password']

    name = event["name"]

    # Use a unique UUID for each request to prevent replay attacks

    nonce = str(uuid.uuid4())

    # Hash the secret key with the client secret and username

    message = username + CLIENT_ID

    key = CLIENT_SECRET.encode('utf-8')

    msg = message.encode('utf-8')

    secret_hash = hashlib.sha256(key + msg).digest()

    secret_hash_b64 = base64.b64encode(secret_hash).decode('utf-8')

    # Make the API request to Cognito

    url = f'https://cognito-idp.{AWS_REGION}.amazonaws.com/'

    headers = {

        'Content-Type': 'application/x-amz-json-1.1',

        'X-Amz-Target': 'AWSCognitoIdentityProviderService.SignUp',

        'X-Amz-User-Agent': 'aws-sdk-js/2.902.0 promise',

        'X-Amz-Client-Id': CLIENT_ID,

        'X-Amz-Client-Version': '1.0',

        'X-Amz-Nonce': nonce,

        'X-Amz-Secret-Hash': secret_hash_b64,

    }

    payload = {

        'ClientId': CLIENT_ID,

        'Username': username,

        'Password': password,

        'UserAttributes': [

            {

                'Name': 'name',

                'Value': name

            },

            {

                'Name': 'email',

                'Value': email

            },

        ],

        'ValidationData': [

            {

                'Name': 'email',

                'Value': email

            },

            {

                'Name': 'custom:username',

                'Value': username

            },

        ],

    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    response_data = response.json()

    # Handle the response from Cognito

    if 'UserConfirmed' in response_data and response_data['UserConfirmed']:

        return {"error": False, "success": True, 'message': "Your account has been created", "data": None}

    elif 'UserSub' in response_data:

        return {"error": False, "success": True, 'message': "Please check your email to confirm your account", "data": None}

    elif 'Message' in response_data:

        return {"error": True, "success": False, 'message': response_data['Message'], "data": None}

    else:

        return {"error": True, "success": False, 'message': "An unknown error occurred", "data": None}

