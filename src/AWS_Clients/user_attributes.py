from time import time
from typing import Dict, List, Optional, Tuple, TypedDict
from uuid import uuid4

# TODO ergänzen, falls user attribute geändert werden
class User(TypedDict):
    uuid: str
    username: str
    sensitive_username: str
    email: str
    email_verified: bool
    biography: str
    created_courses: str
    creator_rating: str
    firstname: str
    is_creator: str
    lastname: str
    locale: str
    member_since: str
    picture: str
    sold_courses: str
    event_id: str
    aud: str
    auth_time: int
    exp: int
    iat: int
    iss: str
    jti: str
    origin_jti: str
    sub: str
    token_use: str
    birthdate: Optional[str]
    gender: Optional[str]
    phone_number: Optional[str]
    phone_number_verified: Optional[bool]



# TODO uuid unveränderlich machen in aws
# TODO Überprüfen ob alle nötigen attribute gesetzt werden oder manche redundant sind
def get_cognito_user_attributes(
    username: str, email: str, google_sign_in: bool = False
) -> Tuple[List[Dict[str, str]], str]:
    uuid = str(uuid4())

    attributes = []

    # space is needed in empty strings for cognito to work properly (otherwise it will not set the attribute)
    if google_sign_in:
        attributes = [
            {"Name": "locale", "Value": "de"},
            {"Name": "custom:uuid", "Value": uuid},
            {"Name": "custom:member_since", "Value": str(round(time()))},
            {"Name": "custom:biography", "Value": " "},
            {"Name": "custom:is_creator", "Value": "false"},
            {"Name": "custom:created_courses", "Value": "0"},
            {"Name": "custom:creator_rating", "Value": "0"},
            {"Name": "custom:sold_courses", "Value": "0"},
            {"Name": "custom:firstname", "Value": " "},
            {"Name": "custom:lastname", "Value": " "},
        ]

    else:
        attributes = [
            {"Name": "email", "Value": str(email)},
            {"Name": "birthdate", "Value": "0001-01-01"},
            {"Name": "phone_number", "Value": " "},
            {"Name": "picture", "Value": " "},
            {"Name": "gender", "Value": " "},
            {"Name": "locale", "Value": "de"},
            {"Name": "custom:sensitive_username", "Value": str(username)},
            {"Name": "custom:uuid", "Value": uuid},
            {"Name": "custom:member_since", "Value": str(round(time()))},
            {"Name": "custom:biography", "Value": " "},
            {"Name": "custom:is_creator", "Value": "false"},
            {"Name": "custom:created_courses", "Value": "0"},
            {"Name": "custom:creator_rating", "Value": "0"},
            {"Name": "custom:sold_courses", "Value": "0"},
            {"Name": "custom:firstname", "Value": " "},
            {"Name": "custom:lastname", "Value": " "},
        ]
    return attributes, uuid


# TODO Überprüfen ob alle nötigen attribute gesetzt werden oder manche redundant sind
# Do not change the order of the attributes, and only append new attributes at the end
def get_dynamodb_user_attributes(uuid: str, email: str):
    return {
        "uuid": {"S": uuid},
        "email": {"S": email},
        "chats": {"M": {}},
        "boughtCourses": {"M": {}},
        "createdCourses": {"M": {}},
        "sales": {"M": {}},
        "settings": {"M": {"darkMode": {"BOOL": False}, "language": {"S": "de"}}},
    }
