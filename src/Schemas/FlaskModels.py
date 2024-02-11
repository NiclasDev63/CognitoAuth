from flask_restx import Namespace

from Schemas.ResponseSchemas import (
    AuthResponseSchemas,
    UsersResponseSchemas,
    UtilSchemas,
)
from Schemas.utils import marshmallow_schema_to_flask_model as converter


def BaseModel(namespace: Namespace):
    return {
        400: (
            "Error",
            converter(UtilSchemas.ErrorResponseSchema, namespace),
        ),
        500: (
            "Error",
            converter(UtilSchemas.ErrorResponseSchema, namespace),
        ),
    }


def GoogleSignInModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.GoogleSignInResponseSchema, namespace),
        ),
    }


def SingUpModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.SignUpResponseSchema, namespace),
        ),
    }


def SignInModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.SignInResponseSchema, namespace),
        ),
        202: (
            "Challenge",
            converter(
                UtilSchemas.ChallengeResponseSchema,
                namespace,
            ),
        ),
    }


def ConfirmUserModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.ConfirmUserResponseSchema, namespace),
        ),
    }


def ChangePasswordModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.ChangePasswordResponseSchema, namespace),
        )
    }


def ResetPasswordModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.ResetPasswordResponseSchema, namespace),
        )
    }


def ConfirmForgotPasswordModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.ConfirmForgotPasswordResponseSchema, namespace
            ),
        )
    }


def ResendConfirmationCodeModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.ResendConfirmationCodeResponseSchema, namespace
            ),
        )
    }


def AssociateSoftwareTokenModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.AssociateSoftwareTokenResponseSchema, namespace
            ),
        )
    }


def VerifySoftwareTokenModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(AuthResponseSchemas.VerifySoftwareTokenResponseSchema, namespace),
        )
    }


def SoftwareTokenMfaChallengeModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Challenge",
            converter(
                AuthResponseSchemas.SoftwareTokenMfaChallengeResponseSchema,
                namespace,
            ),
        ),
    }


def NewPasswordRequiredModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Challenge",
            converter(
                AuthResponseSchemas.NewPasswordRequiredResponseSchema,
                namespace,
            ),
        ),
    }


def SetMfaPreferenceModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.SetMfaPreferenceResponseSchema,
                namespace,
            ),
        ),
    }


def ConfirmDeviceModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.ConfirmDeviceResponseSchema,
                namespace,
            ),
        ),
    }


def UpdateDeviceStatusModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.UpdateDeviceStatusResponseSchema,
                namespace,
            ),
        ),
    }


def GetDeviceModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.GetDeviceResponseSchema,
                namespace,
            ),
        ),
    }


def DeleteUserModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                UsersResponseSchemas.DeleteUserResponseSchema,
                namespace,
            ),
        ),
    }


def SignOutModel(namespace: Namespace):
    return BaseModel(namespace=namespace) | {
        200: (
            "Success",
            converter(
                AuthResponseSchemas.RevokeTokenResponseSchema,
                namespace,
            ),
        ),
    }
