import os

from flask import request
from marshmallow import (
    Schema,
    ValidationError,
    fields,
    post_load,
    validates,
    validates_schema,
)

from Schemas.utils import required_field_missing_message
from utils import password_validator

USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
REGION = os.getenv("REGION")

from Schemas.custom_fields import *


class GoogleSignInSchema(Schema):
    AuthCode = fields.Str(
        required=True, error_messages=required_field_missing_message("AuthCode")
    )


class SignUpSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )
    Password = PasswordField(required=True)
    Email = EmailField(required=True)


class SignInSchema(Schema):
    Username = fields.Str(required=False)
    Password = fields.Str(required=False)
    # TODO comment out when using devices
    # DeviceKey = fields.Str(required=False)
    # DeviceGroupKey = fields.Str(required=False)

    @validates_schema
    def validate_input(self, data, **kwargs):
        cookies = request.cookies
        refresh_token = cookies.get("RefreshToken")
        is_token_set = cookies.get("IsTokenSet")
        # If user deleted isTokenSet cookie but refresh_token cookie is still set, query user for password
        refresh_token = refresh_token if is_token_set and refresh_token else None
        username = data.get("Username") or cookies.get("Username")
        password = data.get("Password")
        if not ((username and password) or (username and refresh_token)):
            raise ValidationError(
                "One of the following combinations must be provided: (Username and Password),  (Username cookie, IsTokenSet cookie and RefreshToken cookie)"
            )
        # TODO comment out when using devices
        # if (data.get("DeviceKey") and not data.get("DeviceGroupKey")) or (
        #     data.get("DeviceGroupKey") and not data.get("DeviceKey")
        # ):
        #     raise ValidationError(
        #         "You need to provide DeviceKey AND DeviceGroupKey to use the device while logging in"
        #     )
        if username and password:
            is_valid, error_msg = password_validator.is_password_valid(password)
            if not is_valid:
                raise ValidationError(error_msg)

    @post_load
    def add_refresh_token(self, data, **kwargs):
        cookies = request.cookies
        refresh_token = cookies.get("RefreshToken")
        is_token_set = cookies.get("IsTokenSet")
        # If user deleted isTokenSet cookie but refresh_token cookie is still set, query user for password
        refresh_token = refresh_token if is_token_set and refresh_token else None
        username = data.get("Username") or cookies.get("Username")
        if refresh_token:
            data["RefreshToken"] = refresh_token
        data["Username"] = username
        return data


class ConfirmEmailSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )
    ConfirmationCode = fields.Str(
        required=True,
        error_messages=required_field_missing_message("ConfirmationCode"),
    )


class ResendConfirmationCodeSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )


class ChangePasswordSchema(Schema):
    PreviousPassword = PasswordField(required=True, field_name="PreviousPassword")
    ProposedPassword = PasswordField(required=True, field_name="ProposedPassword")
    AccessToken = AccessTokenField(required=True)


class AuthRequiredSchema(Schema):
    AccessToken = fields.Str(
        required=True, error_messages=required_field_missing_message("AccessToken")
    )


class ResetPasswordSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )


class ConfirmForgotPasswordSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )
    NewPassword = PasswordField(required=True, field_name="NewPassword")
    ConfirmationCode = fields.Str(
        required=True,
        error_messages=required_field_missing_message("ConfirmationCode"),
    )


class SetUserMfaPreferenceSchema(Schema):
    AccessToken = AccessTokenField(required=True)
    MfaPreference = fields.Str(
        required=True, error_messages=required_field_missing_message("MfaPreference")
    )

    @validates("MfaPreference")
    def validate_mfa_preference(self, value, **kwargs):
        if value not in ["sms", "software_token"]:
            raise ValidationError(
                "MfaPreference must be one of the following: sms, software_token"
            )


class ConfirmDeviceSchema(Schema):
    AccessToken = AccessTokenField(required=True)
    DeviceName = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceName")
    )
    DeviceKey = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceKey")
    )
    DeviceGroupKey = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceGroupKey")
    )


class ForgetDeviceShema(Schema):
    AccessToken = AccessTokenField(required=True)
    DeviceKey = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceKey")
    )


class UpdateDeviceStatusSchema(Schema):
    AccessToken = fields.Str(
        required=True, error_messages=required_field_missing_message("AccessToken")
    )
    DeviceKey = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceKey")
    )
    DeviceStatus = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceStatus")
    )

    @validates("DeviceStatus")
    def validate_device_status(self, value, **kwargs):
        if value not in ["remembered", "not_remembered"]:
            raise ValidationError(
                "DeviceStatus must be one of the following: remembered, not_remembered"
            )


class GetDeviceSchema(Schema):
    AccessToken = AccessTokenField(required=True)
    DeviceKey = fields.Str(
        required=True, error_messages=required_field_missing_message("DeviceKey")
    )


class AssociateSoftwareTokenSchema(Schema):
    AccessToken = AccessTokenField(required=True)


class VerifySoftwareTokenSchema(Schema):
    AccessToken = AccessTokenField(required=True)
    SoftwareTokenCode = fields.Str(
        required=True,
        error_messages=required_field_missing_message("SoftwareTokenCode"),
    )


class SoftwareTokenMfaChallengeSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )
    Session = fields.Str(
        required=True, error_messages=required_field_missing_message("Session")
    )
    SoftwareTokenCode = fields.Str(
        required=True,
        error_messages=required_field_missing_message("SoftwareTokenCode"),
    )


class NewPasswordRequiredChallengeSchema(Schema):
    Username = fields.Str(
        required=True, error_messages=required_field_missing_message("Username")
    )
    NewPassword = PasswordField(required=True, field_name="NewPassword")
    Session = fields.Str(
        required=True, error_messages=required_field_missing_message("Session")
    )


class RevokeTokenSchema(Schema):
    @validates_schema
    def validate_input(self, data, **kwargs):
        cookies = request.cookies
        refresh_token = cookies.get("RefreshToken")
        is_token_set = cookies.get("IsTokenSet")
        # If user deleted isTokenSet cookie but refresh_token cookie is still set, query user for password
        refresh_token = refresh_token if is_token_set and refresh_token else None
        if not refresh_token:
            raise ValidationError("RefreshToken cookie is missing")

    @post_load
    def add_refresh_token(self, data, **kwargs):
        cookies = request.cookies
        refresh_token = cookies.get("RefreshToken")
        data["RefreshToken"] = refresh_token
        return data
