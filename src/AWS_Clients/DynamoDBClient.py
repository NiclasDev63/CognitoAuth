import boto3
from loguru import logger

from AWS_Clients.aws_response_handler import handle_aws_response
from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses
from AWS_Clients.user_attributes import get_dynamodb_user_attributes

CLIENT = boto3.client("dynamodb")
USER_TABLE = "Edunity-Users"
LOG_FILE = "aws_clients"
logger.remove()
logger.add(f"logs/{LOG_FILE}.log")


class DynamoDBClient:
    @staticmethod
    @logger.catch
    def check_email_exists(email: str) -> ClientResponseObject:
        func = lambda: CLIENT.query(
            TableName=USER_TABLE,
            IndexName="email-index",
            Select="COUNT",
            KeyConditionExpression="email = :email",
            ExpressionAttributeValues={":email": {"S": email}},
            ReturnConsumedCapacity="TOTAL",
        )

        response = handle_aws_response(func, LOG_FILE)
        if response.response_type is Responses.SUCCESS:
            if response.aws_response.get("Count") == 1:
                error_dict = {
                    "Message": "The provided email is already taken",
                    "Code": Errors.EmailExistsException,
                }
                return ClientResponseObject(
                    response_type=Responses.RESOURCE_ALREADY_EXISTS,
                    status_code=400,
                    error_dict=error_dict,
                )
            else:
                return ClientResponseObject(
                    response_type=Responses.SUCCESS, status_code=200
                )

        return response

    @staticmethod
    @logger.catch
    def sign_up_init(uuid: str, email: str) -> ClientResponseObject:
        func = lambda: CLIENT.put_item(
            TableName=USER_TABLE, Item=get_dynamodb_user_attributes(uuid, email)
        )

        return handle_aws_response(func, LOG_FILE)

    @staticmethod
    @logger.catch
    def delete_user(uuid: str) -> ClientResponseObject:
        func = lambda: CLIENT.delete_item(
            TableName=USER_TABLE,
            Key={
                "uuid": {"S": uuid},
            },
        )
        return handle_aws_response(func, LOG_FILE)
