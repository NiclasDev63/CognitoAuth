import base64
import os
from base64 import b64encode
from time import time
from typing import Optional

import boto3
import pyotp
import requests as req
from dotenv import load_dotenv
from loguru import logger
from mypy_boto3_cognito_identity import CognitoIdentityClient
from mypy_boto3_cognito_idp import CognitoIdentityProviderClient

from AWS_Clients.aws_response_handler import handle_aws_response
from AWS_Clients.ClientResponses import ClientResponseObject, Errors, Responses
from AWS_Clients.cognito_utils import *
from AWS_Clients.DynamoDBClient import DynamoDBClient
from AWS_Clients.handleAuthChallenge import (
    auth_challenge_handler,
    handle_no_challenge_login,
)
from AWS_Clients.user_attributes import get_cognito_user_attributes
from utils import check_jwt, is_valid_email

load_dotenv()

USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_IDENTITY_POOL_ID = os.getenv("COGNITO_IDENTITY_POOL_ID")
AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
REGION = os.getenv("REGION")
AWS_ACCESS_KEY_ID = os.getenv("ACCESS_KEY")
AWS_SECRET_ACCESS_KEY = os.getenv("ACCESS_SECRET_KEY")
CLIENT: CognitoIdentityProviderClient = boto3.client("cognito-idp", region_name=REGION)
CLIENT_IDENTITY: CognitoIdentityClient = boto3.client(
    "cognito-identity",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
AUTH_BASIC = b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")).decode("utf-8")
REDIRECT_URI = os.getenv("REDIRECT_URI")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
LOG_FILE = "aws_clients"

logger.remove()
logger.add(f"logs/{LOG_FILE}.log")


class CognitoClient:
    @logger.catch
    def sign_in_with_google(self, auth_code: str) -> ClientResponseObject:
        get_token_url = (
            "https://edunity.auth.eu-central-1.amazoncognito.com/oauth2/token"
        )
        data = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": auth_code,
            "redirect_uri": REDIRECT_URI,
        }

        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {AUTH_BASIC}",
        }

        google_resp = req.post(get_token_url, data=data, headers=headers)
        if google_resp.status_code == 200:
            google_resp = google_resp.json()
            id_token = google_resp.get("id_token")

            # verify_signature = False because the id_token is freshly issued by aws and we need to prevent the check for iat from failing because of a time difference
            _, decoded_token = check_jwt.check_and_decode_jwt(
                token=id_token,
                region=REGION,
                user_pool_id=USER_POOL_ID,
                token_type=check_jwt.TokenType.ID_TOKEN,
                verify_signature=False,
            )
            # Since the id_token is freshly issued by aws there is no need to check the token signature
            username = decoded_token.get("username")
            email = decoded_token.get("email")
            data = {
                "IdToken": id_token,
                "AccessToken": google_resp.get("access_token"),
                "RefreshToken": google_resp.get("refresh_token"),
                "ExpiresIn": google_resp.get("expires_in"),
                "Email": email,
                "Username": username,
                "AlreadyRegistered": False,
            }

            # Is required because Cognito offers the option of creating a new user with an already existing e-mail
            check_result = DynamoDBClient.check_email_exists(email)
            if check_result.response_type not in [
                Responses.SUCCESS,
                Responses.RESOURCE_ALREADY_EXISTS,
            ]:
                return check_result
            if check_result.response_type is Responses.RESOURCE_ALREADY_EXISTS:
                data["AlreadyRegistered"] = True
                # If the user is already registered manually but with the same email as the google account, delete the freshly created google user
                if not decoded_token.get("uuid"):
                    resp = CognitoClient.admin_delete_user(username=username)
                    if resp.response_type is Responses.ERROR:
                        return resp

                    error_dict = {
                        "Message": "The provided email is already registered",
                        "Code": Errors.EmailExistsException,
                    }
                    return ClientResponseObject(
                        response_type=Responses.RESOURCE_ALREADY_EXISTS,
                        status_code=400,
                        error_dict=error_dict,
                    )

                return ClientResponseObject(
                    response_type=Responses.SUCCESS,
                    status_code=200,
                    data=data,
                )
            else:
                # If the user is not already registered, add all attributes to the user in the user pool
                new_user_attributes, uuid = get_cognito_user_attributes(
                    username=username, email=email, google_sign_in=True
                )
                data = data | {"UUID": uuid}
                func = lambda: CLIENT.admin_update_user_attributes(
                    UserPoolId=USER_POOL_ID,
                    Username=username,
                    UserAttributes=new_user_attributes,
                )

                response = handle_aws_response(func, LOG_FILE)
                if response.response_type is Responses.SUCCESS:
                    return ClientResponseObject(
                        response_type=Responses.SUCCESS,
                        status_code=200,
                        data=data,
                    )

                return response
        error_dict = {
            "Message": google_resp.json().get("error"),
            "Code": Errors.InternalErrorException,
        }
        return ClientResponseObject(
            response_type=Responses.ERROR,
            status_code=google_resp.status_code,
            error_dict=error_dict,
        )

    @logger.catch
    def sign_up(self, username: str, password: str, email: str) -> ClientResponseObject:
        secret_hash = AWSSRP.get_secret_hash(
            username=username, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
        )
        error_dict = {
            "Message": "The provided email is invalid",
            "Code": Errors.InvalidParameterException,
        }
        if not is_valid_email.is_valid_email(email):
            return ClientResponseObject(
                response_type=Responses.ERROR,
                status_code=400,
                error_dict=error_dict,
            )

        # Is required because Cognito offers the option of creating a new user with an already existing e-mail
        check_result = DynamoDBClient.check_email_exists(email)
        if check_result.response_type is Responses.RESOURCE_ALREADY_EXISTS:
            return check_result

        new_user_attributes, uuid = get_cognito_user_attributes(
            username=username, email=email
        )

        func = lambda: CLIENT.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=username,
            Password=password,
            UserAttributes=new_user_attributes,
        )

        response = handle_aws_response(func, LOG_FILE)

        if response.response_type is Responses.SUCCESS:
            return ClientResponseObject(
                response_type=response.response_type,
                status_code=response.status_code,
                data=extract_deliver_details(response=response) | {"UUID": uuid},
            )
        return response

    @logger.catch
    def confirm_email(
        self, username: str, confirmation_code: str
    ) -> ClientResponseObject:
        func = lambda: CLIENT.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=AWSSRP.get_secret_hash(
                username=username, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
            ),
            Username=username,
            ConfirmationCode=confirmation_code,
        )

        return handle_aws_response(func, LOG_FILE)

    # https://docs.aws.amazon.com/cognito/latest/developerguide/example_cognito-identity-provider_ConfirmDevice_section.html
    @logger.catch
    def _create_device_secret_verifier_config(
        self, password: str, device_key: str, device_group_key: str
    ) -> dict:
        device_and_pw = f"{device_group_key}{device_key}:{password}"
        device_and_pw_hash = hash_sha256(device_and_pw.encode("utf-8"))
        salt = pad_hex(get_random(16))
        x_value = hex_to_long(hex_hash(salt + device_and_pw_hash))
        g = hex_to_long("2")
        big_n = hex_to_long(get_n_hex())
        verifier = pad_hex(pow(g, x_value, big_n))
        return {
            "PasswordVerifier": base64.standard_b64encode(
                bytearray.fromhex(verifier)
            ).decode("utf-8"),
            "Salt": base64.standard_b64encode(bytearray.fromhex(salt)).decode("utf-8"),
        }

    @logger.catch
    def sign_in(
        self,
        username: Optional[str] = "",
        password: Optional[str] = "",
        refresh_token: Optional[str] = "",
        device_key: Optional[str] = "",
        device_group_key: Optional[str] = "",
    ) -> ClientResponseObject:
        """
        Signs in a user with the provided credentials
        If the user has MFA enabled, the user will be prompted to enter a code.
        If device tracking is enabled in the cognito user pool,
        a device_key and device_group_key needs to be provided when logging in with the refresh_token

        :param username: Username of the user
        :param password: Password of the user
        :param refresh_token: Refresh token of the user
        :param device_key: Device key of the device
        :param device_group_key: Device group key of the device

        :return: ClientResponseObject
        """
        username = username or ""
        password = password or ""
        device_key = device_key or ""
        device_group_key = device_group_key or ""

        if refresh_token:
            auth_method = "REFRESH_TOKEN_AUTH"
            auth_parameters = {
                "REFRESH_TOKEN": refresh_token,
                "SECRET_HASH": AWSSRP.get_secret_hash(
                    username.lower(), CLIENT_ID, CLIENT_SECRET
                ),
                # TODO comment out when using devices
                # "DEVICE_KEY": device_key,
            }
        else:
            auth_method = "USER_PASSWORD_AUTH"
            auth_parameters = {
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": AWSSRP.get_secret_hash(
                    username, CLIENT_ID, CLIENT_SECRET
                ),
                # TODO comment out when using devices
                # "DEVICE_KEY": device_key,
            }

        func = lambda: CLIENT.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow=auth_method,
            AuthParameters=auth_parameters,
        )
        response = handle_aws_response(func, LOG_FILE)
        return auth_challenge_handler(
            response=response,
            username=username,
            password=password,
            device_key=device_key,
            device_group_key=device_group_key,
        )

    @logger.catch
    def associate_software_token(self, access_token: str) -> ClientResponseObject:
        func = lambda: CLIENT.associate_software_token(AccessToken=access_token)
        response = handle_aws_response(func, LOG_FILE)
        if response.response_type is Responses.SUCCESS:
            secret_code = response.aws_response.get("SecretCode")
            secret_code_qr_code = pyotp.TOTP(secret_code).provisioning_uri(
                name="Edunity", issuer_name="aws"
            )
            return ClientResponseObject(
                response_type=response.response_type,
                status_code=response.status_code,
                data={"SoftwareTokenMfaQrCode": secret_code_qr_code},
            )
        return response

    @logger.catch
    def verify_software_token(
        self, access_token: str, software_token_code: str
    ) -> ClientResponseObject:
        func = lambda: CLIENT.verify_software_token(
            AccessToken=access_token,
            UserCode=software_token_code,
        )
        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def handle_software_token_mfa_challenge(
        self, username: str, session: str, software_token_code: str
    ) -> ClientResponseObject:
        kwargs = {
            "ClientId": CLIENT_ID,
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": username,
                "SOFTWARE_TOKEN_MFA_CODE": software_token_code,
                "SECRET_HASH": AWSSRP.get_secret_hash(
                    username=username, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
                ),
            },
        }
        func = lambda: CLIENT.respond_to_auth_challenge(**kwargs)
        response = handle_aws_response(func, LOG_FILE)
        if response.response_type is Responses.SUCCESS:
            return handle_no_challenge_login(response=response)
        return response

    # TODO endpunkt hinzufügen
    @logger.catch
    def handle_new_password_required_challenge(
        self, username: str, new_password: str, session: str
    ) -> ClientResponseObject:
        kwargs = {
            "ClientId": CLIENT_ID,
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": username,
                "NEW_PASSWORD": new_password,
                "SECRET_HASH": AWSSRP.get_secret_hash(
                    username=username, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
                ),
            },
        }
        func = lambda: CLIENT.respond_to_auth_challenge(**kwargs)
        response = handle_aws_response(func, LOG_FILE)
        if response.response_type is Responses.SUCCESS:
            return handle_no_challenge_login(response=response)
        return response

    @logger.catch
    def resend_confirmation_code(self, username: str) -> ClientResponseObject:
        func = lambda: CLIENT.resend_confirmation_code(
            ClientId=CLIENT_ID,
            SecretHash=AWSSRP.get_secret_hash(username, CLIENT_ID, CLIENT_SECRET),
            Username=username,
        )

        response = handle_aws_response(func, LOG_FILE)

        if response.response_type is Responses.SUCCESS:
            return ClientResponseObject(
                response_type=response.response_type,
                status_code=response.status_code,
                data=extract_deliver_details(response=response),
            )
        return response

    # TODO Überlegen ob eigene sign_out function wirklich notwendig ist, da tokens einfach aus local storage gelöscht werden können, wodurch user sich neu einloggen muss
    #  User is logged out of all devices and all tokens are invalidated
    @logger.catch
    def global_sign_out(self, access_token: str) -> ClientResponseObject:
        func = lambda: CLIENT.global_sign_out(AccessToken=access_token)

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def change_password(
        self, previous_password: str, proposed_password: str, access_token: str
    ) -> ClientResponseObject:
        func = lambda: CLIENT.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=access_token,
        )

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def forgot_password(self, username: str) -> ClientResponseObject:
        func = lambda: CLIENT.forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=AWSSRP.get_secret_hash(username, CLIENT_ID, CLIENT_SECRET),
            Username=username,
        )

        response = handle_aws_response(func, LOG_FILE)

        if response.response_type is Responses.SUCCESS:
            return ClientResponseObject(
                response_type=response.response_type,
                status_code=response.status_code,
                data=extract_deliver_details(response=response),
            )
        return response

    @logger.catch
    def confirm_forgot_password(
        self, username: str, new_password: str, confirmation_code: str
    ) -> ClientResponseObject:
        func = lambda: CLIENT.confirm_forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=AWSSRP.get_secret_hash(username, CLIENT_ID, CLIENT_SECRET),
            Username=username,
            ConfirmationCode=confirmation_code,
            Password=new_password,
        )

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def set_user_mfa_preference(
        self,
        access_token: str,
        sms_mfa_settings: dict,
        software_token_mfa_settings: dict,
    ) -> ClientResponseObject:
        func = lambda: CLIENT.set_user_mfa_preference(
            AccessToken=access_token,
            SMSMfaSettings=sms_mfa_settings,
            SoftwareTokenMfaSettings=software_token_mfa_settings,
        )

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def confirm_device(
        self,
        access_token: str,
        device_name: str,
        device_key: str,
        device_group_key: str,
    ) -> ClientResponseObject:
        device_secret_verifier_config = self._create_device_secret_verifier_config(
            password="#Fips#12431",
            device_key=device_key,
            device_group_key=device_group_key,
        )
        func = lambda: CLIENT.confirm_device(
            AccessToken=access_token,
            DeviceName=device_name,
            DeviceKey=device_key,
            DeviceSecretVerifierConfig=device_secret_verifier_config,
        )

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def get_device(self, access_token: str, device_key: str) -> ClientResponseObject:
        func = lambda: CLIENT.get_device(
            DeviceKey=device_key,
            AccessToken=access_token,
        )

        response = handle_aws_response(func, LOG_FILE)

        if response.response_type is Responses.SUCCESS:
            device_info = response.aws_response.get("Device")
            device_data = {
                "DeviceKey": device_info.get("DeviceKey"),
                "DeviceCreateData": device_info.get("DeviceCreateDate"),
                "DeviceLastModifiedDate": device_info.get("DeviceLastModifiedDate"),
                "DeviceLastAuthenticatedDate": device_info.get(
                    "DeviceLastAuthenticatedDate"
                ),
            }
            device_attributes = device_info.get("DeviceAttributes")
            for attribute in device_attributes:
                if attribute.get("Name") == "device_status":
                    device_data["DeviceStatus"] = attribute.get("Value")
                elif attribute.get("Name") == "last_ip_used":
                    device_data["LastIpUsed"] = attribute.get("Value")
                elif attribute.get("Name") == "device_name":
                    device_data["DeviceName"] = attribute.get("Value")

            return ClientResponseObject(
                response_type=response.response_type,
                status_code=response.status_code,
                data=device_data,
            )
        return response

    @logger.catch
    def update_device_status(
        self, device_key: str, access_token: str, device_remembered_status: str
    ) -> ClientResponseObject:
        func = lambda: CLIENT.update_device_status(
            DeviceKey=device_key,
            AccessToken=access_token,
            DeviceRememberedStatus=device_remembered_status,
        )

        return handle_aws_response(func, LOG_FILE)

    # TODO Falls MFA aktiviert ist, muss diese funktion beim ausloggen des nutzers ebenfalls aufgerufen werden
    @logger.catch
    def forget_device(self, device_key: str, access_token: str) -> ClientResponseObject:
        func = lambda: CLIENT.forget_device(
            DeviceKey=device_key,
            AccessToken=access_token,
        )

        return handle_aws_response(func, LOG_FILE)

    @logger.catch
    def revoke_token(self, refresh_token: str) -> ClientResponseObject:
        func = lambda: CLIENT.revoke_token(
            Token=refresh_token,
            ClientId=CLIENT_ID,
            ClientSecret=CLIENT_SECRET,
        )

        return handle_aws_response(func, LOG_FILE)

    @staticmethod
    @logger.catch
    def delete_user(access_token: str) -> ClientResponseObject:
        func = lambda: CLIENT.delete_user(AccessToken=access_token)

        return handle_aws_response(func, LOG_FILE)

    @staticmethod
    @logger.catch
    def admin_delete_user(username: str) -> ClientResponseObject:
        func = lambda: CLIENT.admin_delete_user(
            UserPoolId=USER_POOL_ID, Username=username
        )

        return handle_aws_response(func, LOG_FILE)
