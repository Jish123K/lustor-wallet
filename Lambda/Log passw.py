import boto3

import hashlib

import json

DYNAMODB_URL = ""

DYNAMODB_REGION = ""

TABLE_NAME = ""

def lambda_handler(event, context):

    # Connect to DynamoDB

    dynamodb = boto3.resource('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)

    table = dynamodb.Table(TABLE_NAME)

    # Check for required fields in event

    if not event.get('username'):

        return {'error': True, 'success': False, 'message': 'Username is required', 'data': None}

    if not event.get('passwordHash'):

        return {'error': True, 'success': False, 'message': 'Password hash is required', 'data': None}

    # Query DynamoDB for user record

    response = table.get_item(

        Key={

            'username': event['username']

        },

        ProjectionExpression='encryptedEncryptionKey, encryptedAsymmetricPrivateKey, passwordHash'

    )

    if not response.get('Item'):

        return {'error': True, 'success': False, 'message': 'User does not exist', 'data': None}

    # Validate password hash

    password_hash = hashlib.sha256(event['passwordHash'].encode('utf-8')).hexdigest()

    if password_hash != response['Item']['passwordHash']:

        return {'error': True, 'success': False, 'message': 'Incorrect password', 'data': None}

    # Remove password hash from response

    del response['Item']['passwordHash']

    return {'error': False, 'success': True, 'message': 'User logged in successfully', 'data': response['Item']}

