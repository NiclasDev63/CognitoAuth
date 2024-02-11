import json

from flask import Response, make_response
from flask_restx import marshal
from loguru import logger


def doc_to_response_transformer(response: Response, doc_responses: dict) -> Response:
    json_data = json.loads(response.data)
    status_code = response.status_code
    if status_code not in doc_responses:
        logger.error(f"Status code {status_code} not found in responses dict")
        status_code = 400
    flask_model = doc_responses[status_code][1]
    marshalled_response = marshal(
        json_data,
        flask_model,
    )
    return_response = make_response(json.dumps(marshalled_response), status_code)
    return_response.headers = response.headers
    return return_response
