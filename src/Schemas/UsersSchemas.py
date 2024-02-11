from marshmallow import Schema

from Schemas.custom_fields import AccessTokenField, IdTokenField


class DeleteUserSchema(Schema):
    AccessToken = AccessTokenField(required=True)
    IdToken = IdTokenField(required=True)
