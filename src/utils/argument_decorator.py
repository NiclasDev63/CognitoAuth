from functools import wraps
from typing import Callable, Type

from flask import Response, json, request
from marshmallow import Schema, ValidationError

from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses


def pass_args(schema: Type[Schema]) -> Response:
    def wrapper(func: Callable):
        @wraps(func)
        def check_json(*args, **kwargs):
            json_data = request.get_json(silent=True)
            json_data = json_data or {}
            try:
                json_data = schema().load(json_data)
                return func(json_data, *args, **kwargs)
            except ValidationError as e:
                error_dict = {
                    "Message": e.messages,
                    "Code": Errors.InvalidParameterException,
                }
                response = ClientResponseObject(
                    response_type=Responses.ERROR,
                    status_code=400,
                    error_dict=error_dict,
                )
                print(response.get_dict_representation())
                return Response(
                    json.dumps(
                        response.get_dict_representation(),
                    ),
                    400,
                )

        return check_json

    return wrapper
