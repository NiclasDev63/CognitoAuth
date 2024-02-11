from flask import Flask, Response, json, redirect, url_for
from flask_cors import CORS
from flask_restx import Api, Resource

from resources import Auth, Users
from Schemas import AuthSchemas, FlaskModels, UsersSchemas
from Schemas.utils import marshmallow_schema_to_flask_model as converter
from utils import get_cookies
from utils.response_from_doc import doc_to_response_transformer

# TODO add Parameter description to all endpoints using @api_doc(params={})
# Find a way to make this automatically from the model
app = Flask(__name__)
api = Api(
    app,
    version="1.0",
    title="APIs for my app",
    description="A demonstration of how to create Swagger documentation",
    prefix="/api/",
    doc="/api/docs/",
)
CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:3000", "http://127.0.0.1:3000"],
)

# namespaces
auth_ns = api.namespace("auth", description="Auth operations")
users_ns = api.namespace("users", description="Users operations")


@app.errorhandler(404)
def redirect_to_docs(e):
    """Redirect all non-existing routes to the Swagger documentation"""
    return redirect(url_for("doc"))


# Needed to fix "net::ERR_CONTENT_LENGTH_MISMATCH 200" when calling the sign_up endpoint
@app.after_request
def remove_content_length(response):
    response.headers.remove("Content-Length")
    return response


@api.route("/hello_world")
class HelloWorld(Resource):
    def get(self):
        """Returns a hello world message"""
        response = {
            "message": "Welcome to Edunity's API!",
            "StatusCode": 200,
        }
        return Response(response=json.dumps(response), status=200)


@api.route("/health")
class Health(Resource):
    def get(self):
        """Returns server health status"""
        response = {
            "StatusCode": 200,
        }
        return Response(response=json.dumps(response), status=200)


# auth endpoints
@auth_ns.route(
    "/sign_in_with_google",
    methods=["POST"],
)
class GoogleSignIn(Resource):
    @api.doc(
        responses=FlaskModels.GoogleSignInModel(auth_ns),
        description=get_cookies.get_sign_in_cookies(),
    )
    @api.expect(converter(AuthSchemas.GoogleSignInSchema, auth_ns))
    def post(self):
        """Sign a user in with google and creates a new user if the user does not exist."""
        resp: Response = Auth.sign_in_with_google()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.GoogleSignInModel(auth_ns)
        )


@auth_ns.route("/sign_up", methods=["POST"])
class SignUp(Resource):
    @api.doc(
        responses=FlaskModels.SingUpModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.SignUpSchema, auth_ns))
    def post(self):
        """Signs a user up"""
        resp: Response = Auth.sign_up()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.SingUpModel(auth_ns)
        )


@auth_ns.route("/sign_in", methods=["POST"])
class SignIn(Resource):
    @api.doc(
        responses=FlaskModels.SignInModel(auth_ns),
        description=get_cookies.get_sign_in_cookies()
        + "<p>If the request contains the cookies <b>IsTokenSet</b> and <b>RefreshToken</b>, no password is needed. (If signed in without password, the RefreshToken Cookie does not get renewed)</p>",
    )
    @api.expect(converter(AuthSchemas.SignInSchema, auth_ns))
    def post(self):
        """Signs a user in"""
        resp: Response = Auth.sign_in()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.SignInModel(auth_ns)
        )


@auth_ns.route("/confirm_user", methods=["POST"])
class ConfirmUser(Resource):
    @api.doc(
        responses=FlaskModels.ConfirmUserModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.ConfirmEmailSchema, auth_ns))
    def post(self):
        """Confirms a user's email"""
        resp: Response = Auth.confirm_email()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.ConfirmUserModel(auth_ns)
        )


@auth_ns.route("/change_password", methods=["POST"])
class ChangePassword(Resource):
    @api.doc(
        responses=FlaskModels.ChangePasswordModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.ChangePasswordSchema, auth_ns))
    def post(self):
        """Changes a user's password"""
        resp: Response = Auth.change_password()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.ChangePasswordModel(auth_ns)
        )


@auth_ns.route("/reset_password", methods=["POST"])
class ResetPassword(Resource):
    @api.doc(
        responses=FlaskModels.ResetPasswordModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.ResetPasswordSchema, auth_ns))
    def post(self):
        """Sends a reset password code to the user's email"""
        resp: Response = Auth.reset_password()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.ResetPasswordModel(auth_ns)
        )


@auth_ns.route("/confirm_forgot_password", methods=["POST"])
class SetNewPassword(Resource):
    @api.doc(
        responses=FlaskModels.ConfirmForgotPasswordModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.ConfirmForgotPasswordSchema, auth_ns))
    def post(self):
        """Sets new password after user has requested a reset password code"""
        resp: Response = Auth.confirm_forgot_password()
        return doc_to_response_transformer(
            response=resp, doc_responses=FlaskModels.ConfirmForgotPasswordModel(auth_ns)
        )


@auth_ns.route("/resend_confirmation_code", methods=["POST"])
class ResendConfirmationCode(Resource):
    @api.doc(
        responses=FlaskModels.ResendConfirmationCodeModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.ResendConfirmationCodeSchema, auth_ns))
    def post(self):
        """Resends the confirmation code for the user's email to their email"""
        resp: Response = Auth.resend_confirmation_code()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.ResendConfirmationCodeModel(auth_ns),
        )


@auth_ns.route("/associate_software_token", methods=["POST"])
class AssociateSoftwareToken(Resource):
    @api.doc(
        responses=FlaskModels.AssociateSoftwareTokenModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.AssociateSoftwareTokenSchema, auth_ns))
    def post(self):
        """Associates a software token with the user's account"""
        resp: Response = Auth.associate_software_token()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.AssociateSoftwareTokenModel(auth_ns),
        )


@auth_ns.route("/verify_software_token", methods=["POST"])
class VerifySoftwareToken(Resource):
    @api.doc(
        responses=FlaskModels.AssociateSoftwareTokenModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.VerifySoftwareTokenSchema, auth_ns))
    def post(self):
        """ "Verifys a software token code provided by the user"""
        resp: Response = Auth.verify_software_token()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.VerifySoftwareTokenModel(auth_ns),
        )


@auth_ns.route("/software_token_mfa_challenge", methods=["POST"])
class SoftwareTokenMfaChallenge(Resource):
    @api.doc(
        responses=FlaskModels.SoftwareTokenMfaChallengeModel(auth_ns),
        description=get_cookies.get_sign_in_cookies(),
    )
    @api.expect(converter(AuthSchemas.SoftwareTokenMfaChallengeSchema, auth_ns))
    def post(self):
        """Handles the client response to the software token mfa challenge which is initiated by the server when the user has enabled mfa and tries to sign in"""
        resp: Response = Auth.software_token_mfa_challenge()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.SoftwareTokenMfaChallengeModel(auth_ns),
        )


@auth_ns.route("/new_password_required_challenge", methods=["POST"])
class SoftwareTokenMfaChallenge(Resource):
    @api.doc(
        responses=FlaskModels.NewPasswordRequiredModel(auth_ns),
        description=get_cookies.get_sign_in_cookies(),
    )
    @api.expect(converter(AuthSchemas.NewPasswordRequiredChallengeSchema, auth_ns))
    def post(self):
        """Handles the client response to the new password required challenge which is initiated by the server when the user needs to set a new password and tries to sign in"""
        resp: Response = Auth.software_token_mfa_challenge()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.NewPasswordRequiredModel(auth_ns),
        )


@auth_ns.route("/set_mfa_preference", methods=["POST"])
class SetUserMfaPreference(Resource):
    @api.doc(
        responses=FlaskModels.SetMfaPreferenceModel(auth_ns),
    )
    @api.expect(converter(AuthSchemas.SetUserMfaPreferenceSchema, auth_ns))
    def post(self):
        """Sets the user's mfa preference to either software_token or sms"""
        resp: Response = Auth.set_user_mfa_preference()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.SetMfaPreferenceModel(auth_ns),
        )


@auth_ns.route("/sign_out", methods=["POST"])
class SignOut(Resource):
    @api.doc(
        responses=FlaskModels.SignOutModel(auth_ns),
        description="<p>To successfully call this endpoint, cookies <b>IsTokenSet</b> and <b>RefreshToken</b> have to be set.<br>Revokes all of the access tokens generated by, and at the same time as, the specified refresh token and deletes all auth related cookies</p>",
    )
    @api.expect(converter(AuthSchemas.RevokeTokenSchema, auth_ns))
    def post(self):
        """Signs a user out and revoke the user's refresh and access tokens"""
        resp: Response = Auth.revoke_token()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.SignOutModel(auth_ns),
        )


# TODO find solution for password field
# TODO comment out when using devices
# @auth_ns.route("/confirm_device", methods=["POST"])
# class ConfirmDevice(Resource):
#     @api.doc(
#         responses=FlaskModels.ConfirmDeviceModel(auth_ns),
#     )
#     @api.expect(converter(AuthSchemas.ConfirmDeviceSchema, auth_ns))
#     def post(self):
#         """Confirms tracking of the device"""
#         resp: Response = Auth.confirm_device()
#         return doc_to_response_transformer(
#             response=resp,
#             doc_responses=FlaskModels.ConfirmDeviceModel(auth_ns),
#         )

# TODO comment out when using devices
# @auth_ns.route("/update_device_status", methods=["POST"])
# class UpdateDeviceStatus(Resource):
#     @api.doc(
#         responses=FlaskModels.UpdateDeviceStatusModel(auth_ns),
#     )
#     @api.expect(converter(AuthSchemas.UpdateDeviceStatusSchema, auth_ns))
#     def post(self):
#         """Updates the device status"""
#         resp: Response = Auth.update_device_status()
#         return doc_to_response_transformer(
#             response=resp,
#             doc_responses=FlaskModels.UpdateDeviceStatusModel(auth_ns),
#         )

# TODO comment out when using devices
# @auth_ns.route("/get_device", methods=["POST"])
# class GetDevice(Resource):
#     @api.doc(
#         responses=FlaskModels.GetDeviceModel(auth_ns),
#     )
#     @api.expect(converter(AuthSchemas.GetDeviceSchema, auth_ns))
#     def post(self):
#         """Returns information about the device"""
#         resp: Response = Auth.get_device()
#         return doc_to_response_transformer(
#             response=resp,
#             doc_responses=FlaskModels.GetDeviceModel(auth_ns),
#         )


# Users endpoints
@users_ns.route("/delete", methods=["POST"])
class DeleteUser(Resource):
    @api.doc(
        responses=FlaskModels.DeleteUserModel(users_ns),
    )
    @api.expect(converter(UsersSchemas.DeleteUserSchema, users_ns))
    def post(self):
        """Deletes a user"""
        resp: Response = Users.delete_user()
        return doc_to_response_transformer(
            response=resp,
            doc_responses=FlaskModels.DeleteUserModel(users_ns),
        )


if __name__ == "__main__":
    app.run(host="localhost", port=7000, debug=True, use_reloader=False)
