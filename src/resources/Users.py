import os

from flask import Response, json
from loguru import logger

from AWS_Clients import ClientResponses, CognitoClient, DynamoDBClient
from Schemas.UsersSchemas import *
from utils import argument_decorator, check_jwt

REGION = os.environ.get("REGION")
USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")

LOG_FILE = "users"
logger.remove()
logger.add(f"logs/{LOG_FILE}.log")

CognitoClient = CognitoClient.CognitoClient()


@argument_decorator.pass_args(DeleteUserSchema)
def delete_user(json_data: dict) -> Response:
    # Used static error message for security reasons
    error_dict = {
        "Message": "Provided IdToken or AccessToken is not issued by this service",
        "Code": ClientResponses.Errors.InvalidParameterException,
    }
    error_response_obj = ClientResponses.ClientResponseObject(
        response_type=ClientResponses.Responses.ERROR,
        status_code=400,
        error_dict=error_dict,
    )
    error_response = Response(
        json.dumps(error_response_obj.get_dict_representation()),
        error_response_obj.status_code,
    )
    # No need to check for validity of tokens, as they are checked in the decorator
    _, decoded_id_token = check_jwt.check_and_decode_jwt(
        token=json_data["IdToken"],
        region=REGION,
        user_pool_id=USER_POOL_ID,
        token_type=check_jwt.TokenType.ID_TOKEN,
    )
    _, decoded_access_token = check_jwt.check_and_decode_jwt(
        token=json_data["AccessToken"],
        region=REGION,
        user_pool_id=USER_POOL_ID,
        token_type=check_jwt.TokenType.ACCESS_TOKEN,
    )

    id_token_username = decoded_id_token.get("username")
    access_token_username = decoded_access_token.get("username")

    if not id_token_username or not access_token_username:
        return error_response
    if id_token_username != access_token_username:
        return error_response

    uuid = decoded_id_token.get("uuid")
    if not uuid:
        return error_response

    response = CognitoClient.delete_user(json_data["AccessToken"])
    error_obj = response
    if response.response_type is ClientResponses.Responses.SUCCESS:
        resp = DynamoDBClient.DynamoDBClient.delete_user(uuid)
        error_obj = resp
        if resp.response_type is ClientResponses.Responses.SUCCESS:
            return Response(
                json.dumps(response.get_dict_representation()), response.status_code
            )

    logger.error(error_obj.error_dict["Message"])
    return Response(
        json.dumps(error_obj.get_dict_representation()), error_obj.status_code
    )
