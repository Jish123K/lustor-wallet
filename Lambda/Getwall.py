import boto3

from botocore.exceptions import ClientError

DYNAMODB_URL = ""

DYNAMODB_REGION = ""

TABLE_NAME = ""

def get_user_data(username):

    try:

        dynamodb_client = boto3.client('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)

        response = dynamodb_client.get_item(

            TableName=TABLE_NAME,

            Key={

                'username': {'S': username}

            },

            ProjectionExpression="encryptedMnemonicPhrase, encryptedAsymmetricPrivateKey",

            ConsistentRead=True

        )

        item = response.get('Item', {})

        return {

            'encryptedMnemonicPhrase': item.get('encryptedMnemonicPhrase', {}).get('S', ''),

            'encryptedAsymmetricPrivateKey': item.get('encryptedAsymmetricPrivateKey', {}).get('S', '')

        }

    except ClientError as e:

        if e.response['Error']['Code'] == 'ResourceNotFoundException':

            print(f"Table {TABLE_NAME} not found")

        else:

            print(f"Error: {e}")

        return {}

def lambda_handler(event, context):

    if not event.get("username"):

        return {"error": True, "success": False, "message": "username is required", "data": None}

    

    user_data = get_user_data(event["username"])

    if not user_data:

        return {"error": True, "success": False, "message": "User Doesnt exists", "data": None}

    

    user_data.pop("passwordHash", None)

    return {"error": False, "success": True, "message": "success", "data": user_data}

