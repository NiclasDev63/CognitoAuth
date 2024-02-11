from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Literal, Optional, TypedDict


class Responses(Enum):
    SUCCESS = 0
    RESOURCE_ALREADY_EXISTS = 1
    ERROR_CONNECTING_TO_AWS = 2
    ERROR = 3


class Errors(Enum):
    InternalErrorException = "InternalErrorException"
    ClientErrorException = "ClientErrorException"
    LimitExceededException = "LimitExceededException"
    NotAuthorizedException = "NotAuthorizedException"
    UserNotFoundException = "UserNotFoundException"
    UserNotConfirmedException = "UserNotConfirmedException"
    UsernameExistsException = "UsernameExistsException"
    EmailExistsException = "EmailExistsException"
    InvalidParameterException = "InvalidParameterException"
    CodeMismatchException = "CodeMismatchException"
    ExpiredCodeException = "ExpiredCodeException"

    @classmethod
    def get_error_code(cls, error):
        try:
            return cls[error]
        except KeyError:
            return cls.ClientErrorException


ErrorCodesAsString = Literal[
    "InternalErrorException",
    "ClientErrorException",
    "LimitExceededException",
    "NotAuthorizedException",
    "UserNotFoundException",
    "UserNotConfirmedException",
    "UsernameExistsException",
    "EmailExistsException",
    "InvalidParameterException",
    "CodeMismatchException",
    "ExpiredCodeException",
]


class ErrorDict(TypedDict):
    Message: str | Dict[str, Any]
    Code: Errors


class ErrorDictResp(TypedDict):
    Message: str | Dict[str, Any]
    Code: ErrorCodesAsString


class ResponseDict(TypedDict):
    StatusCode: int
    Data: Optional[dict]
    Error: Optional[ErrorDictResp]
    ChallengeName: Optional[str]
    ChallengeParameters: Optional[dict]


@dataclass
class ClientResponseObject:
    response_type: Responses
    status_code: int
    data: Optional[dict] = field(default_factory=dict)
    aws_response: Optional[dict] = field(default_factory=dict)
    error_dict: Optional[ErrorDict] = field(default_factory=dict)
    challenge_name: Optional[str] = ""
    challenge_parameters: Optional[dict] = field(default_factory=dict)

    def get_dict_representation(self) -> ResponseDict:
        return_dict = {"StatusCode": self.status_code}
        if self.data:
            return_dict["Data"] = self.data
        if self.error_dict:
            temp_dict = {}
            temp_dict["Message"] = self.error_dict["Message"]
            temp_dict["Code"] = self.error_dict["Code"].value
            return_dict["Error"] = temp_dict
        if self.challenge_name:
            return_dict["ChallengeName"] = self.challenge_name
        if self.challenge_parameters:
            return_dict["ChallengeParameters"] = self.challenge_parameters

        return return_dict
