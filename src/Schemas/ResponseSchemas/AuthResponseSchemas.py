from marshmallow import fields

from Schemas.ResponseSchemas.UtilSchemas import (
    BaseResponseSchema,
    BaseSchema,
    DeliverySchema,
    TokenSchema,
)


class GoogleSignInResponseSchema(BaseResponseSchema):
    Data = fields.Nested(TokenSchema)


class SignUpResponseSchema(BaseResponseSchema):
    Data = fields.Nested(DeliverySchema)


class SignInResponseSchema(BaseResponseSchema):
    # TODO comment out when using devices
    # Data = fields.Nested(combine_schemas(TokenSchema, DeviceDataSchema))
    Data = fields.Nested(TokenSchema)


class ConfirmUserResponseSchema(BaseResponseSchema):
    pass


class ChangePasswordResponseSchema(BaseResponseSchema):
    pass


class ResetPasswordResponseSchema(BaseResponseSchema):
    Data = fields.Nested(DeliverySchema)


class ConfirmForgotPasswordResponseSchema(BaseResponseSchema):
    pass


class ResendConfirmationCodeResponseSchema(BaseResponseSchema):
    Data = fields.Nested(DeliverySchema)


class _AssociateSoftwareTokenResponseSchema(BaseSchema):
    SoftwareTokenMfaQrCode = fields.Str(required=True)


class AssociateSoftwareTokenResponseSchema(BaseResponseSchema):
    Data = fields.Nested(_AssociateSoftwareTokenResponseSchema)


class VerifySoftwareTokenResponseSchema(BaseResponseSchema):
    pass


class SoftwareTokenMfaChallengeResponseSchema(BaseResponseSchema):
    # TODO comment out when using devices
    # Data = fields.Nested(combine_schemas(TokenSchema, DeviceDataSchema))
    Data = fields.Nested(TokenSchema)


class NewPasswordRequiredResponseSchema(BaseResponseSchema):
    Data = fields.Nested(TokenSchema)


class SetMfaPreferenceResponseSchema(BaseResponseSchema):
    pass


class ConfirmDeviceResponseSchema(BaseResponseSchema):
    pass


class UpdateDeviceStatusResponseSchema(BaseResponseSchema):
    pass


class _GetDeviceResponseSchema(BaseSchema):
    DeviceStatus = fields.Str(required=True)
    LastIpUsed = fields.Str(required=True)
    DeviceName = fields.Str(required=True)
    DeviceCreateData = fields.Str(required=True)
    DeviceKey = fields.Str(required=True)
    DeviceLastAuthenticatedDate = fields.Str(required=True)
    DeviceLastModifiedDate = fields.Str(required=True)


class GetDeviceResponseSchema(BaseResponseSchema):
    Data = fields.Nested(_GetDeviceResponseSchema)


class RevokeTokenResponseSchema(BaseResponseSchema):
    pass
