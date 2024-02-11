import base64
import os
from enum import Enum
from typing import Optional, Tuple, TypedDict

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from loguru import logger

from AWS_Clients.user_attributes import User

load_dotenv()

CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")

logger.remove()
logger.add("../logs/auth.log")


class TokenType(Enum):
    ACCESS_TOKEN = 0
    ID_TOKEN = 1


# TODO Alle Enums löschen bis auf success, error und ähnliche und Nachricht der 'jwt.decode' methode zurück geben wie bei 'handle_aws_response'
class JwtStatus(Enum):
    @property
    def message(self):
        return self.value["message"]

    VALID_JWT = {"message": "valid token provided"}
    INVALID_JWT = {"message": "invalid token provided"}
    SIGNATURE_EXPIRED = {"message": "Signature of token expired"}
    INVALID_SIGNATURE = {"message": "Signature of token is invalid"}
    INVALID_PUBLIC_KEY = {
        "message": "invalid public key used to sign the token, check if the right USER POOL ID was provided"
    }
    UNEXPECTED_EXCEPTION = {
        "message": "An unexpected Exception occurred while verifying the token"
    }
    INVALID_REGION = {"message": "invalid REGION provided"}


def jwk_to_pem(jwk: dict) -> str:
    """Converts jwk in PEM-Format"""

    key = rsa.RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big"),
    ).public_key(default_backend())

    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def remove_tags(decoded_token: dict) -> dict:
    """
    removes the "custom:" and "cognito:" tag from the attributes
    e.g. >>> decoded_token = {"custom:firstname": "Niclas", "custom:gender": "male"} -> {"firstname": "Niclas", "gender": "male"}
    """
    return {
        key.split(":")[1] if ":" in key else key: value
        for key, value in decoded_token.items()
    }


def get_jwt_keys(region: str, user_pool_id: str) -> JwtStatus | dict:
    try:
        jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
        response = requests.get(jwks_url)
    except requests.exceptions.ConnectionError:
        return JwtStatus.INVALID_REGION

    jwks_data = response.json()

    if not "keys" in jwks_data.keys():
        return JwtStatus.INVALID_PUBLIC_KEY

    return jwks_data


def get_matching_jwk(token: str, jwks_data: dict) -> JwtStatus | dict:
    try:
        header = jwt.get_unverified_header(token)
        kid = header["kid"]
    except Exception as e:
        logger.error(str(e))
        return JwtStatus.INVALID_JWT
    jwk = next((key for key in jwks_data["keys"] if key["kid"] == kid), None)
    return jwk or JwtStatus.INVALID_PUBLIC_KEY


def handle_jwt_decoding_exception(exception: Exception) -> JwtStatus:
    match type(exception):
        case jwt.exceptions.ExpiredSignatureError:
            return JwtStatus.SIGNATURE_EXPIRED
        case jwt.exceptions.InvalidSignatureError:
            return JwtStatus.INVALID_SIGNATURE
        case _:
            logger.error(str(exception))
            return JwtStatus.UNEXPECTED_EXCEPTION


@logger.catch
def check_and_decode_jwt(
    token: str,
    region: str,
    user_pool_id: str,
    token_type: TokenType,
    verify_signature: bool = True,
) -> Tuple[JwtStatus, Optional[User]]:
    """
    Checks if a given jwt is valid.

    >>> check_signature = False \n
    Is used for decoding new and valid id_tokens issued by aws \n
    else
    >>> check_signature = True \n
    """
    jwks_data, jwk, pem_key = None, None, ""
    if verify_signature:
        jwks_data = get_jwt_keys(region=region, user_pool_id=user_pool_id)
        if type(jwks_data) is JwtStatus:
            return jwks_data, None

        jwk = get_matching_jwk(token=token, jwks_data=jwks_data)
        if type(jwk) is JwtStatus:
            return jwk, None
        pem_key = jwk_to_pem(jwk)

    decode_options = {
        "verify_signature": verify_signature,
        "verify_aud": token_type is not TokenType.ACCESS_TOKEN,
    }
    try:
        decoded_token = jwt.decode(
            token,
            pem_key,
            algorithms=["RS256"],
            options={
                "verify_signature": decode_options["verify_signature"],
                "verify_aud": decode_options["verify_aud"],
            },
            audience=CLIENT_ID,
        )
        return JwtStatus.VALID_JWT, remove_tags(decoded_token=decoded_token)
    except Exception as e:
        return handle_jwt_decoding_exception(e), None
