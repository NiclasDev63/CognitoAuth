import os
from functools import wraps
from typing import Callable

from dotenv import load_dotenv
from flask import Response, json

from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses
from Schemas.AuthSchemas import AuthRequiredSchema
from utils import argument_decorator, check_jwt

load_dotenv()
REGION = os.getenv("REGION")
USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")


def auth_required(func: Callable) -> Callable or Response:
    @wraps(func)
    @argument_decorator.pass_args(AuthRequiredSchema)
    def wrapper(json_data: dict, *args, **kwargs):
        check_jwt_response = check_jwt.check_and_decode_jwt(
            token=json_data["access_token"],
            region=REGION,
            user_pool_id=USER_POOL_ID,
            token_type=check_jwt.TokenType.ACCESS_TOKEN,
        )

        if check_jwt_response[0] is check_jwt.JwtStatus.VALID_JWT:
            return func(*args, **kwargs)
        error_dict = {
            "Message": check_jwt_response[0].message,
            "Code": Errors.InvalidParameterException,
        }
        response = ClientResponseObject(
            response_type=Responses.ERROR,
            status_code=400,
            error_dict=error_dict,
        )
        return Response(
            json.dumps(response.get_dict_representation()),
            400,
        )

    return wrapper
