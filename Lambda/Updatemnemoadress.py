import json

import uuid

from datetime import datetime

import decimal

import boto3

import pynamodb.exceptions

from pynamodb.models import Model

from pynamodb.attributes import UnicodeAttribute, NumberAttribute

DYNAMODB_URL = ""

DYNAMODB_REGION = ""

TABLE_NAME = ""

class User(Model):

    class Meta:

        table_name = TABLE_NAME

        region = DYNAMODB_REGION

        if DYNAMODB_URL:

            host = DYNAMODB_URL

    username = UnicodeAttribute(hash_key=True)

    encryptedMnemonicPhrase = UnicodeAttribute()

    eth_address = UnicodeAttribute()

def lambda_handler(event, context):

    for field in ["username", "encryptedMnemonicPhrase", "eth_address"]:

        if event.get(field) is None:

            return {"error": True, "success": False, "message": f"{field} is required", "data": None}

    user = User(username=event["username"], encryptedMnemonicPhrase=event["encryptedMnemonicPhrase"], eth_address=event["eth_address"])

    try:

        user.save()

    except pynamodb.exceptions.PutError as e:

        return {"error": True, "success": False, "message": f"Error in updating user {e.__str__()}", "data": None}

    return {"error": False, "success": True, "message": "user successfully updated", "data": None}

