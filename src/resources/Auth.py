from datetime import datetime, timedelta

from flask import Response, json, make_response, request
from loguru import logger

from AWS_Clients import CognitoClient, DynamoDBClient
from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses
from Schemas.AuthSchemas import *
from utils import argument_decorator

CognitoClient = CognitoClient.CognitoClient()
DynamoDBClient = DynamoDBClient.DynamoDBClient()
logger.remove()
logger.add("logs/auth.log")


def _remove_all_client_cookies(response: ClientResponseObject) -> Response:
    resp = make_response()
    resp.delete_cookie("Username")
    resp.delete_cookie("AccessToken")
    resp.delete_cookie("AccessTokenExpiration")
    resp.delete_cookie("RefreshToken")
    resp.delete_cookie("IsTokenSet")
    # TODO comment out when using devices
    # resp.delete_cookie("DeviceKey")
    # resp.delete_cookie("DeviceGroupKey")
    resp.response = json.dumps(response.get_dict_representation())
    resp.status_code = response.status_code
    return resp


def _add_cookies_to_response(response: ClientResponseObject) -> Response:
    resp = make_response()
    refresh_token = response.data.get("RefreshToken")
    username = response.data.get("Username")
    access_token = response.data.get("AccessToken")
    expires_in = response.data.get("ExpiresIn")
    expires_in_as_datetime = datetime.now() + timedelta(seconds=expires_in)

    if not all([username, access_token]):
        error_msg = "Failed to add cookies to response, missing Username or AccessToken"
        logger.error(error_msg)
        raise ValueError(error_msg)
    # If user logged in with username and password, set refresh token cookie
    if refresh_token:
        refresh_token_exp_time = datetime.now() + timedelta(days=30)
        # Set httponly to true to prevent javascript from accessing the cookie and removing it from the response
        resp.set_cookie(
            key="RefreshToken",
            value=refresh_token,
            expires=refresh_token_exp_time,
            samesite="Strict",
            httponly=True,
        )
        response.data.pop("RefreshToken")
        # Use sameSite: 'Strict' for all cookies, to prevent CSRF attacks
        # Set cookie to check on the frontend if the user has a refresh token set and set the expiration date to 30 days like the refresh token
        resp.set_cookie(
            key="IsTokenSet",
            value="true",
            expires=refresh_token_exp_time,
            samesite="Strict",
        )

    resp.set_cookie(
        key="Username",
        value=username,
        samesite="Strict",
    )
    resp.set_cookie(
        key="AccessToken",
        value=access_token,
        samesite="Strict",
        expires=expires_in_as_datetime,
    )
    resp.set_cookie(
        key="AccessTokenExpiration",
        value=str(expires_in),
        samesite="Strict",
    )
    response.data.pop("AccessToken")

    resp.response = json.dumps(response.get_dict_representation())
    resp.status_code = response.status_code

    # TODO comment out when using devices
    # device_data = response.data.get("DeviceData")

    # # Only needs to check for device_key since device_group_key is always set if device_key is set
    # if device_data and device_data.get("DeviceKey"):
    #     device_key = device_data.get("DeviceKey")
    #     device_group_key = device_data.get("DeviceGroupKey")
    #     resp.set_cookie(
    #         key="DeviceKey",
    #         value=device_key,
    #         samesite="Strict",
    #     )
    #     resp.set_cookie(
    #         key="DeviceGroupKey",
    #         value=device_group_key,
    #         samesite="Strict",
    #     )
    return resp


def _create_new_dynamo_user(response: ClientResponseObject) -> ClientResponseObject:
    resp = DynamoDBClient.sign_up_init(response.data["UUID"], response.data["Email"])
    if resp.response_type is Responses.SUCCESS:
        logger.info("User successfully created")
        return resp

    # Removes created user from cognito if dynamodb initialization fails
    # Safely can delete user by username from cognito since the user is freshly created in cognito and no other user has the same username
    else:
        delete_resp = CognitoClient.admin_delete_user(response.data["Username"])
        if delete_resp.response_type is Responses.ERROR:
            logger.error(delete_resp.error_dict["Message"])
            return delete_resp
        else:
            error_dict = {
                "Message": "Receveid the following error, while creating a new user "
                + resp.error_dict["Message"],
                "Code": Errors.InternalErrorException,
            }
            return ClientResponseObject(
                response_type=Responses.ERROR,
                status_code=500,
                error_dict=error_dict,
            )


@logger.catch
@argument_decorator.pass_args(GoogleSignInSchema)
def sign_in_with_google(json_data: dict) -> Response:
    auth_code = json_data["AuthCode"]
    response = CognitoClient.sign_in_with_google(auth_code=auth_code)
    if response.response_type is Responses.SUCCESS:
        already_registered = response.data.get("AlreadyRegistered")
        if already_registered:
            return _add_cookies_to_response(response)
        else:
            resp = _create_new_dynamo_user(response)
            if resp.response_type is Responses.SUCCESS:
                # If user was successfully created in dynamodb, add cookies to response using the CognitoClient response which contains the data needed for the cookies
                return _add_cookies_to_response(response)
            else:
                logger.error(resp.error_dict["Message"])
                return Response(
                    json.dumps(resp.get_dict_representation()),
                    resp.status_code,
                )
    else:
        logger.error(response.error_dict["Message"])
        return Response(
            json.dumps(response.get_dict_representation()),
            response.status_code,
        )


@logger.catch
@argument_decorator.pass_args(SignUpSchema)
def sign_up(json_data: dict) -> Response:
    response = CognitoClient.sign_up(
        json_data["Username"], json_data["Password"], json_data["Email"]
    )
    if response.response_type is Responses.SUCCESS:
        response.data["Username"] = json_data["Username"]
        response.data["Email"] = json_data["Email"]
        resp = _create_new_dynamo_user(response)
        if resp.response_type is Responses.SUCCESS:
            return Response(
                json.dumps(response.get_dict_representation()), response.status_code
            )
        else:
            logger.error(resp.error_dict["Message"])
            return Response(
                json.dumps(resp.get_dict_representation()), resp.status_code
            )

    logger.error(response.error_dict["Message"])
    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(ConfirmEmailSchema)
def confirm_email(json_data: dict) -> Response:
    response = CognitoClient.confirm_email(
        username=json_data["Username"], confirmation_code=json_data["ConfirmationCode"]
    )
    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(SignInSchema)
def sign_in(json_data: dict) -> Response:
    refresh_token = json_data.get("RefreshToken")

    # TODO comment out when using devices
    # device_key = json_data.get("DeviceKey")
    # device_group_key = json_data.get("DeviceGroupKey")

    response = CognitoClient.sign_in(
        username=json_data.get("Username"),
        password=json_data.get("Password"),
        refresh_token=refresh_token,
    )
    # If sign in was successful, return the response with a cookie containing the refresh token
    if response.response_type is Responses.SUCCESS and not response.challenge_name:
        response.data["Username"] = json_data["Username"]
        # only needs to check for device_key since device_group_key is always set if device_key is set
        # TODO comment out when using devices
        # if device_key:
        #     response.data["DeviceData"] = {
        #         "DeviceKey": device_key,
        #         "DeviceGroupKey": device_group_key,
        #     }
        return _add_cookies_to_response(response)
    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(SoftwareTokenMfaChallengeSchema)
def software_token_mfa_challenge(json_data: dict) -> Response:
    response = CognitoClient.handle_software_token_mfa_challenge(
        username=json_data["Username"],
        session=json_data["Session"],
        software_token_code=json_data["SoftwareTokenCode"],
    )
    if response.response_type is Responses.SUCCESS:
        response.data["Username"] = json_data["Username"]
        return _add_cookies_to_response(response)
    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(NewPasswordRequiredChallengeSchema)
def new_password_required_challenge(json_data: dict) -> Response:
    response = CognitoClient.handle_new_password_required_challenge(
        username=json_data["Username"],
        new_password=json_data["NewPassword"],
        session=json_data["Session"],
    )
    if response.response_type is Responses.SUCCESS:
        response.data["Username"] = json_data["Username"]
        return _add_cookies_to_response(response)
    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(ResendConfirmationCodeSchema)
def resend_confirmation_code(json_data: dict) -> Response:
    response = CognitoClient.resend_confirmation_code(json_data["Username"])

    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(AssociateSoftwareTokenSchema)
def associate_software_token(json_data: dict) -> Response:
    response = CognitoClient.associate_software_token(
        access_token=json_data["AccessToken"]
    )
    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(VerifySoftwareTokenSchema)
def verify_software_token(json_data: dict) -> Response:
    response = CognitoClient.verify_software_token(
        access_token=json_data["AccessToken"],
        software_token_code=json_data["SoftwareTokenCode"],
    )

    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(ChangePasswordSchema)
def change_password(json_data: dict) -> Response:
    response = CognitoClient.change_password(
        json_data["PreviousPassword"],
        json_data["ProposedPassword"],
        json_data["AccessToken"],
    )

    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(ResetPasswordSchema)
def reset_password(json_data: dict):
    response = CognitoClient.forgot_password(json_data["Username"])

    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


@logger.catch
@argument_decorator.pass_args(ConfirmForgotPasswordSchema)
def confirm_forgot_password(json_data: dict):
    response = CognitoClient.confirm_forgot_password(
        username=json_data["Username"],
        new_password=json_data["NewPassword"],
        confirmation_code=json_data["ConfirmationCode"],
    )

    return Response(
        json.dumps(response.get_dict_representation()),
        response.status_code,
    )


# TODO make SMS mfa work
@argument_decorator.pass_args(SetUserMfaPreferenceSchema)
def set_user_mfa_preference(json_data: dict) -> Response:
    auth_method = json_data["MfaPreference"]
    auth_method_dict = {
        "sms": {"Enabled": False, "PreferredMfa": False},
        "software_token": {"Enabled": False, "PreferredMfa": False},
    }
    auth_method_dict[auth_method]["Enabled"] = True
    auth_method_dict[auth_method]["PreferredMfa"] = True

    response = CognitoClient.set_user_mfa_preference(
        json_data["AccessToken"],
        sms_mfa_settings=auth_method_dict["sms"],
        software_token_mfa_settings=auth_method_dict["software_token"],
    )

    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(ConfirmDeviceSchema)
def confirm_device(json_data: dict) -> Response:
    response = CognitoClient.confirm_device(
        access_token=json_data["AccessToken"],
        device_name=json_data["DeviceName"],
        device_key=json_data["DeviceKey"],
        device_group_key=json_data["DeviceGroupKey"],
    )
    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(UpdateDeviceStatusSchema)
def update_device_status(json_data: dict) -> Response:
    response = CognitoClient.update_device_status(
        access_token=json_data["AccessToken"],
        device_key=json_data["DeviceKey"],
        device_remembered_status=json_data["DeviceStatus"],
    )

    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(GetDeviceSchema)
def get_device(json_data: dict) -> Response:
    response = CognitoClient.get_device(
        access_token=json_data["AccessToken"],
        device_key=json_data["DeviceKey"],
    )

    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(ForgetDeviceShema)
def forget_device(json_data: dict) -> Response:
    response = CognitoClient.forget_device(
        access_token=json_data["AccessToken"], device_key=json_data["DeviceKey"]
    )

    return Response(
        json.dumps(response.get_dict_representation()), response.status_code
    )


@logger.catch
@argument_decorator.pass_args(RevokeTokenSchema)
def revoke_token(json_data: dict) -> Response:
    response = CognitoClient.revoke_token(refresh_token=json_data["RefreshToken"])
    if response.response_type is Responses.SUCCESS:
        return _remove_all_client_cookies(response)
    else:
        return Response(
            json.dumps(response.get_dict_representation()), response.status_code
        )
