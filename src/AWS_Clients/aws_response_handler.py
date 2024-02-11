from typing import Callable

from botocore import exceptions
from loguru import logger

from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses


def handle_aws_response(
    func: Callable,
    log_file: str,
) -> ClientResponseObject:
    logger.remove()
    logger.add(f"logs/{log_file}.log")

    try:
        response = func()
        # print("RESPONSE: ", response)
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            logger.info(f"{response}")
            return ClientResponseObject(
                response_type=Responses.SUCCESS,
                status_code=200,
                aws_response=response,
            )

        logger.error(f"{response}")
        error_dict = {
            "Message": "An error occured while calling the aws service",
            "Code": Errors.ClientErrorException,
        }
        return ClientResponseObject(
            response_type=Responses.ERROR_CONNECTING_TO_AWS,
            status_code=500,
            aws_response=response,
            error_dict=error_dict,
        )

    except exceptions.ClientError as e:
        # print("CLIENT ERROR: ", e.response)
        error_msg = e.response["Error"]["Message"]
        error_code = e.response["Error"]["Code"]
        error_dict = {
            "Message": error_msg,
            "Code": Errors.get_error_code(error_code),
        }
        status_code = e.response["ResponseMetadata"]["HTTPStatusCode"]
        logger.error(error_msg)
        return ClientResponseObject(
            response_type=Responses.ERROR,
            status_code=status_code,
            error_dict=error_dict,
        )
    except Exception as e:
        print("UNEXPECTED ERROR: ", e)
        error_dict = {
            "Message": "An unexpected error occured while calling the aws service",
            "Code": Errors.InternalErrorException,
        }
        logger.error(e)
        return ClientResponseObject(
            response_type=Responses.ERROR,
            status_code=500,
            error_dict=error_dict,
        )
