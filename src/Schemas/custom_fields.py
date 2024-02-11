import os
import re

from marshmallow import ValidationError, fields

from Schemas.utils import required_field_missing_message
from utils import check_jwt, is_valid_email, password_validator
from utils.check_jwt import JwtStatus, TokenType

USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
REGION = os.getenv("REGION")


class PasswordField(fields.Str):
    def __init__(self, field_name="Password", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages = required_field_missing_message(field_name)

    def _validate(self, password):
        is_valid, error_msg = password_validator.is_password_valid(password)
        if not is_valid:
            raise ValidationError(error_msg)


class EmailField(fields.Str):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages = required_field_missing_message("Email")

    def _validate(self, email):
        if not is_valid_email.is_valid_email(email):
            raise ValidationError("Email must be a valid email address")


class AccessTokenField(fields.Str):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages = required_field_missing_message("AccessToken")

    def _validate(self, access_token):
        token_status, _ = check_jwt.check_and_decode_jwt(
            access_token, REGION, USER_POOL_ID, TokenType.ACCESS_TOKEN
        )
        if token_status is not JwtStatus.VALID_JWT:
            raise ValidationError(token_status.value.get("message"))


class IdTokenField(fields.Str):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages = required_field_missing_message("IdToken")

    def _validate(self, id_token):
        token_status, _ = check_jwt.check_and_decode_jwt(
            id_token, REGION, USER_POOL_ID, TokenType.ID_TOKEN
        )
        if token_status is not JwtStatus.VALID_JWT:
            raise ValidationError(token_status.value.get("message"))


class UUIDField(fields.Str):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages = required_field_missing_message("UUID")
        self.pattern = re.compile(r"^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$")

    def _validate(self, uuid):
        if not self.pattern.match(uuid):
            raise ValidationError("UUID must be a valid UUID")
