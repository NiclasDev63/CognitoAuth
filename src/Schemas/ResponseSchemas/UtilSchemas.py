from marshmallow import EXCLUDE, Schema, fields, validates

from AWS_Clients.ClientResponses import Errors
from Schemas.custom_fields import *


class BaseSchema(Schema):
    class Meta:
        unknown = EXCLUDE


class BaseResponseSchema(BaseSchema):
    StatusCode = fields.Int()


class DeliverySchema(BaseSchema):
    class Meta:
        unknown = EXCLUDE

    DeliveryMedium = fields.Str(required=True)
    Destination = fields.Str(required=True)


class TokenSchema(BaseSchema):
    IdToken = fields.Str(required=True)


class DeviceSchema(BaseSchema):
    DeviceKey = fields.Str(required=True)
    DeviceGroupKey = fields.Str(required=True)


class DeviceDataSchema(BaseSchema):
    DeviceData = fields.Nested(DeviceSchema)


class ChallengeParamsSchema(BaseSchema):
    Session = fields.Str(required=True)
    Username = fields.Str(required=True)


class ChallengeResponseSchema(BaseResponseSchema):
    ChallengeName = fields.Str(required=True)
    ChallengeParameters = fields.Nested(ChallengeParamsSchema)


class _ErrorResponseSchema(Schema):
    Message = fields.Str(required=True)
    Code = fields.Str(required=True)

    @validates("Code")
    def validate_code(self, value):
        try:
            Errors(value)
        except ValueError:
            raise ValidationError("Invalid error code")


class ErrorResponseSchema(BaseResponseSchema):
    Error = fields.Nested(_ErrorResponseSchema)
