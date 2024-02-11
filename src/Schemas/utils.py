import uuid
from typing import Type

import marshmallow as ma
from flask_restx import Namespace, fields
from marshmallow import Schema

from Schemas import AuthSchemas


def combine_schemas(*schemas: Type[Schema]):
    class CombinedSchema(Schema):
        pass

    for schema in schemas:
        for field_name, field in schema._declared_fields.items():
            CombinedSchema._declared_fields[field_name] = field
    return CombinedSchema


def required_field_missing_message(field_name: str):
    return {"required": f"{field_name} is mssing"}


def marshmallow_schema_to_flask_model(ma_schema: Type[Schema], ns: Namespace):
    model_definition = {}
    for field_name, field_obj in ma_schema._declared_fields.items():
        match type(field_obj):
            case ma.fields.String:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case ma.fields.Integer:
                model_definition[field_name] = fields.Integer(
                    required=field_obj.required
                )
            case ma.fields.Boolean:
                model_definition[field_name] = fields.Boolean(
                    required=field_obj.required
                )
            case ma.fields.Float:
                model_definition[field_name] = fields.Float(required=field_obj.required)
            case ma.fields.DateTime:
                model_definition[field_name] = fields.DateTime(
                    required=field_obj.required
                )
            case ma.fields.Nested:
                model_definition[field_name] = fields.Nested(
                    marshmallow_schema_to_flask_model(field_obj.schema, ns),
                    required=field_obj.required,
                )
            case ma.fields.List:
                model_definition[field_name] = fields.List(
                    fields.Raw, required=field_obj.required
                )
            case ma.fields.Url:
                model_definition[field_name] = fields.Url(required=field_obj.required)
            case ma.fields.Email:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case ma.fields.Dict:
                model_definition[field_name] = fields.Raw(required=field_obj.required)
            case ma.fields.Decimal:
                model_definition[field_name] = fields.Fixed(
                    decimals=2, required=field_obj.required
                )
            case ma.fields.Date:
                model_definition[field_name] = fields.Date(required=field_obj.required)
            case ma.fields.Time:
                model_definition[field_name] = fields.DateTime(
                    required=field_obj.required
                )
            case ma.fields.Str:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case ma.fields.Number:
                model_definition[field_name] = fields.Float(required=field_obj.required)
            case ma.fields.Bool:
                model_definition[field_name] = fields.Boolean(
                    required=field_obj.required
                )
            case ma.fields.UUID:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case ma.fields.Pluck:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case ma.fields.Tuple:
                model_definition[field_name] = fields.List(
                    fields.Raw, required=field_obj.required
                )
            case ma.fields.Raw:
                model_definition[field_name] = fields.Raw(required=field_obj.required)
            case AuthSchemas.PasswordField:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case AuthSchemas.EmailField:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case AuthSchemas.AccessTokenField:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case AuthSchemas.UUIDField:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case AuthSchemas.IdTokenField:
                model_definition[field_name] = fields.String(
                    required=field_obj.required
                )
            case _:
                raise Exception(
                    f"Field type {type(field_obj)} is not supported by marshmallow_to_flask_converter"
                )
    if not hasattr(ma_schema, "__name__"):
        id = uuid.uuid4()
        return ns.model("Data Schema " + str(id), model_definition)
    return ns.model(ma_schema.__name__, model_definition)
