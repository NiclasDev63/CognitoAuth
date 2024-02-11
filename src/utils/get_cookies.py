import json


def _prettify_cookies(msg: str, cookies: dict) -> str:
    cookie_description = "<ul>"
    for cookie, details in cookies.items():
        cookie_description += f"<li><b>{cookie} ({details['ValueType']}):</b>{details['Description']}</li>"
    cookie_description += "</ul>"

    return f"<p>{msg}</p>" + cookie_description


def get_sign_in_cookies():
    msg = "This endpoint sets the following cookies if the api call was successful: "
    cookies = {
        "RefreshToken": {
            "ValueType": "string",
            "Description": "a httponly JWT token used to refresh the access token",
        },
        "IsTokenSet": {
            "ValueType": "boolean",
            "Description": "a boolean indicating whether the refresh token is set",
        },
        "AccessToken": {
            "ValueType": "string",
            "Description": "a JWT token used to authenticate the user",
        },
        "AccessTokenExpiration": {
            "ValueType": "string",
            "Description": "a string representing the expiration date of the access token as a UTC timestamp",
        },
        "Username": {
            "ValueType": "string",
            "Description": "the username of the user",
        },
        # TODO comment out when using devices
        # "DeviceKey": {
        #     "ValueType": "string",
        #     "Description": "the device key of the user",
        # },
        # "DeviceGroupKey": {
        #     "ValueType": "string",
        #     "Description": "the device group key of the user",
        # },
    }
    return _prettify_cookies(msg, cookies)
