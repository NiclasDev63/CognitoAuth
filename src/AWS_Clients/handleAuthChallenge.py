from typing import Optional

from dotenv import load_dotenv
from loguru import logger
from mypy_boto3_cognito_idp import CognitoIdentityProviderClient

from AWS_Clients.aws_response_handler import handle_aws_response
from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses
from AWS_Clients.cognito_utils import *

load_dotenv()

USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
REGION = os.getenv("REGION")
CLIENT: CognitoIdentityProviderClient = boto3.client("cognito-idp", region_name=REGION)

LOG_FILE = "aws_clients"
logger.remove()
logger.add(f"logs/{LOG_FILE}.log")


@logger.catch
def handle_no_challenge_login(response: ClientResponseObject) -> ClientResponseObject:
    challenge_name = response.aws_response.get("ChallengeName")
    if challenge_name:
        logger.error(f"The following challenge was not handled: {challenge_name}")
        error_dict = {
            "Message": f"Unknown challenge returned from cognito: {challenge_name}",
            "Code": Errors.InternalErrorException,
        }
        return ClientResponseObject(
            response_type=Responses.ERROR,
            status_code=500,
            error_dict=error_dict,
        )
    data = extract_tokens(response)
    device_data = extract_device_data(response)
    data = data | {
        "DeviceData": device_data,
    }
    return ClientResponseObject(
        response_type=response.response_type,
        status_code=response.status_code,
        data=data,
    )


@logger.catch
def _handle_new_password_required_challenge(
    response: ClientResponseObject,
) -> ClientResponseObject:
    return ClientResponseObject(
        response_type=Responses.SUCCESS,
        status_code=202,
        challenge_name="NEW_PASSWORD_REQUIRED",
        challenge_parameters={
            "Session": response.aws_response.get("Session"),
            "Username": response.aws_response.get("ChallengeParameters").get(
                "USER_ID_FOR_SRP"
            ),
        },
    )


@logger.catch
def _handle_device_srp_auth_challenge(
    srp_helper: AWSSRP,
    device_key: str,
    device_group_key: str,
) -> ClientResponseObject:
    auth_params = srp_helper.get_auth_params()
    auth_params["DEVICE_KEY"] = device_key
    func = lambda: CLIENT.respond_to_auth_challenge(
        ClientId=CLIENT_ID,
        ChallengeName="DEVICE_SRP_AUTH",
        ChallengeResponses=auth_params,
    )
    resp = handle_aws_response(func, LOG_FILE)

    return auth_challenge_handler(
        response=resp,
        username=srp_helper.username,
        password=srp_helper.password,
        device_key=device_key,
        device_group_key=device_group_key,
        srp_helper=srp_helper,
    )


@logger.catch
def _handle_device_password_verifier_challenge(
    srp_helper: AWSSRP,
    response: ClientResponseObject,
    device_key: str,
    device_group_key: str,
) -> ClientResponseObject:
    challenge_params = response.aws_response["ChallengeParameters"]
    challenge_params["USER_ID_FOR_SRP"] = device_group_key + device_key
    cr = srp_helper.process_challenge(challenge_params)
    cr["USERNAME"] = srp_helper.username
    cr["DEVICE_KEY"] = device_key

    func = lambda: CLIENT.respond_to_auth_challenge(
        ClientId=CLIENT_ID,
        ChallengeName="DEVICE_PASSWORD_VERIFIER",
        ChallengeResponses=cr,
    )

    return auth_challenge_handler(
        response=handle_aws_response(func, LOG_FILE),
        username=srp_helper.username,
        password=srp_helper.password,
        device_key=device_key,
        device_group_key=device_group_key,
        srp_helper=srp_helper,
    )


@logger.catch
def _handle_software_token_mfa_challenge(
    response: ClientResponseObject,
) -> ClientResponseObject:
    return ClientResponseObject(
        response_type=Responses.SUCCESS,
        status_code=202,
        challenge_name="SOFTWARE_TOKEN_MFA",
        challenge_parameters={
            "Session": response.aws_response.get("Session"),
            "Username": response.aws_response.get("ChallengeParameters").get(
                "USER_ID_FOR_SRP"
            ),
        },
    )


@logger.catch
def _create_srp_helper(username: str, password: str) -> AWSSRP | ClientResponseObject:
    srp_helper = None
    if username and password:
        srp_helper = AWSSRP(
            username=username,
            password=password,
            pool_id="_",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            client=CLIENT,
        )
    error_dict = {
        "Message": "Missing one or more of the following: Username, password, DeviceKey, DeviceGroupKey",
        "Code": Errors.InternalErrorException,
    }
    return srp_helper or ClientResponseObject(
        response_type=Responses.ERROR,
        status_code=500,
        error_dict=error_dict,
    )


@logger.catch
def auth_challenge_handler(
    response: ClientResponseObject,
    username: str,
    password: Optional[str] = None,
    device_key: Optional[str] = None,
    device_group_key: Optional[str] = None,
    srp_helper: Optional[AWSSRP] = None,
) -> ClientResponseObject:
    """
    Handles the response from the AWS Cognito service when a challenge is returned.

    :param response: The response from the AWS Cognito service.
    :param username: The username of the user.
    :param password: The password of the user.
    :param device_key: The device key of the device.
    :param device_group_key: The device group key of the device.
    :param srp_helper: The SRP helper object.
    :return: A ClientResponseObject.
    """
    if response.response_type is not Responses.SUCCESS:
        return response

    challenge_name = response.aws_response.get("ChallengeName")
    match challenge_name:
        case "NEW_PASSWORD_REQUIRED":
            return _handle_new_password_required_challenge(
                response=response,
            )
        case "DEVICE_SRP_AUTH":
            srp_helper = srp_helper or _create_srp_helper(
                username=username,
                password=password,
            )
            if isinstance(srp_helper, ClientResponseObject):
                return srp_helper
            return _handle_device_srp_auth_challenge(
                srp_helper=srp_helper,
                device_key=device_key,
                device_group_key=device_group_key,
            )
        case "DEVICE_PASSWORD_VERIFIER":
            srp_helper = srp_helper or _create_srp_helper(
                username=username,
                password=password,
            )
            if isinstance(srp_helper, ClientResponseObject):
                return srp_helper
            return _handle_device_password_verifier_challenge(
                srp_helper=srp_helper,
                response=response,
                device_key=device_key,
                device_group_key=device_group_key,
            )
        case "SOFTWARE_TOKEN_MFA":
            return _handle_software_token_mfa_challenge(
                response=response,
            )
        case _:
            return handle_no_challenge_login(response=response)
