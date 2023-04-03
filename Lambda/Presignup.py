import json

import boto3

import botocore.exceptions

CLIENT_ID = ''

CLIENT_SECRET = ''

USER_POOL_ID = ''

def lambda_handler(event, context):

    # Create a Cognito identity provider resource

    cognito = boto3.resource('cognito-idp')

    user_pool = cognito.UserPool(USER_POOL_ID)

    try:

        email = event['request']['userAttributes']["email"]

    except:

        raise Exception("Email is required")

    # Search for users with matching email

    filter_expression = 'email = :val'

    response = user_pool.users.filter(

        FilterExpression=filter_expression,

        ExpressionAttributeValues={':val': email}

    )

    # Check if any users were found with the given email

    users = list(response)

    if len(users) > 0:

        raise Exception("This email already exists")

    return event

