import os

from dotenv import load_dotenv

from src.utils.check_jwt import JwtStatus, check_and_decode_jwt

load_dotenv()

USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
REGION = os.getenv("REGION")

VALID_TOKEN = """eyJraWQiOiJEUFdRMHNFaytpZFpEeUpQcEU3S0ljbXpIMjFlZVhTWU9ZeWFGeXJZQ1pZPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxM2U0MzgxMi0zMDAxLTcwYjctNWEyNC1kNjUxNzI2MDBmYzkiLCJjdXN0b206Zmlyc3RuYW1lIjoiICIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvZXUtY2VudHJhbC0xX0dyNllTZjJjcyIsImN1c3RvbTpiaXJ0aF9kYXRlIjoiMCIsImN1c3RvbTpwaG9uZSI6IiAiLCJhdXRoX3RpbWUiOjE3MDAyNjU5ODIsImN1c3RvbTpsYXN0bmFtZSI6IiAiLCJjdXN0b206bG9jYWxlX3N0ciI6IkRFIiwiZXhwIjoxNzAwMjY5NTgyLCJjdXN0b206Y3JlYXRlZF9jb3Vyc2VzIjoiMCIsImlhdCI6MTcwMDI2NTk4MiwianRpIjoiZjIyY2I3MzctMmFlNi00MjNiLWFkNDEtNzhmODMxMTY4YmFiIiwiZW1haWwiOiJuaWNsYXMuZ3JlZ29yMjBAZ21haWwuY29tIiwiY3VzdG9tOnV1aWQiOiJlZmVhNmY3MS0xZmQ4LTQwOTItOTgwOS0yNWUxOWQyMTJjZDkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImN1c3RvbTppc19jcmVhdG9yIjoiRmFsc2UiLCJjb2duaXRvOnVzZXJuYW1lIjoibmljbGFzNjMiLCJjdXN0b206Y3JlYXRvcl9yYXRpbmciOiIwIiwib3JpZ2luX2p0aSI6ImIxMmU3YjExLWUyMDQtNDkyMy1iZDg5LWMzNDliYTMxOGM2NSIsImN1c3RvbTpnZW5kZXIiOiJNYWxlIiwiYXVkIjoiNGE0ZnMzaHFkMWsyYzEyMmRlajdpdTR2ZjMiLCJjdXN0b206bWVtYmVyX3NpbmNlIjoiMTY5NzAzMzU4MSIsImV2ZW50X2lkIjoiZjkzNWE0NTUtYjAyMi00ZWU3LTlkNTAtNzBmOGJiYmY4ZjAwIiwiY3VzdG9tOnByb2ZpbGVfcGljdHVyZSI6IiAiLCJ0b2tlbl91c2UiOiJpZCIsImN1c3RvbTpzb2xkX2NvdXJzZXMiOiIwIiwiY3VzdG9tOmJpb2dyYXBoeSI6IiAifQ.cE7equv7L52gfZRLrXh24CaijxQKbceZG01LecWjcMCCAZzbAjlHWWJd3uAsFnhfKeCCR1CyiPnY7o1mmddFJ-XUoZ8NBb-AbYQR9b2RAGuGFHdOdKeFLSM13_zhlfeNdx7ev4ZMSeLT-wBvqKQbM1TROYOxWlwDRBc-uhSL5JlPaFAfd9BcCp2-MtP8ZUXlqx6EqC0FaC0BeTJWHzbe9YILQUdSnD6QP7MTSLflP0cnNKkMCqFDr8pJkKEQ2HAZ_MaLctSP4SpF77MPyIQE5-kTv0mJuu7NeNv9YZU-C_Y74A0RkXai8aehE-5buBo0wRrm1BSC3wboMiELcvM5vw"""


def test_correct_decoding():
    resp = check_and_decode_jwt(
        token=VALID_TOKEN,
        region=REGION,
        user_pool_id=USER_POOL_ID,
        check_signature=False,
    )
    assert resp[0] is JwtStatus.VALID_JWT
    assert resp[1] == {
        "aud": "4a4fs3hqd1k2c122dej7iu4vf3",
        "auth_time": 1700265982,
        "biography": " ",
        "birth_date": "0",
        "username": "niclas63",
        "created_courses": "0",
        "creator_rating": "0",
        "email": "niclas.gregor20@gmail.com",
        "email_verified": False,
        "event_id": "f935a455-b022-4ee7-9d50-70f8bbbf8f00",
        "exp": 1700269582,
        "firstname": " ",
        "gender": "Male",
        "iat": 1700265982,
        "is_creator": "False",
        "iss": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Gr6YSf2cs",
        "jti": "f22cb737-2ae6-423b-ad41-78f831168bab",
        "lastname": " ",
        "locale_str": "DE",
        "member_since": "1697033581",
        "origin_jti": "b12e7b11-e204-4923-bd89-c349ba318c65",
        "phone": " ",
        "profile_picture": " ",
        "sold_courses": "0",
        "sub": "13e43812-3001-70b7-5a24-d65172600fc9",
        "token_use": "id",
        "uuid": "efea6f71-1fd8-4092-9809-25e19d212cd9",
    }


def test_invalid_region_and_user_pool():
    resp = check_and_decode_jwt(
        token=VALID_TOKEN,
        region="123",
        user_pool_id=USER_POOL_ID,
        check_signature=False,
    )
    assert resp[0] is JwtStatus.INVALID_REGION
    assert resp[0].message == "invalid REGION provided"

    resp = check_and_decode_jwt(
        token=VALID_TOKEN, region=REGION, user_pool_id="123", check_signature=False
    )

    assert resp[0] is JwtStatus.INVALID_PUBLIC_KEY
    assert (
        resp[0].message
        == "invalid public key used to sign the token, check if the right USER POOL ID was provided"
    )


def test_invalid_jwt():
    resp = check_and_decode_jwt(
        token="123", region=REGION, user_pool_id=USER_POOL_ID, check_signature=False
    )
    assert resp[0] is JwtStatus.INVALID_JWT
    assert resp[0].message == "invalid jwt provided"

    resp = check_and_decode_jwt(
        token="'\n123'-:",
        region=REGION,
        user_pool_id=USER_POOL_ID,
        check_signature=False,
    )
    assert resp[0] is JwtStatus.INVALID_JWT
    assert resp[0].message == "invalid jwt provided"


def test_invalid_public_key():
    INVALID_PUB_KEY = """eyJraWQiOiJEUFdRMHNFaytpZDpEeUpQcEU3S0ljbXpIMjFlZVhTWU9ZeWFGeXJZQ1pZPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxM2U0MzgxMi0zMDAxLTcwYjctNWEyNC1kNjUxNzI2MDBmYzkiLCJjdXN0b206Zmlyc3RuYW1lIjoiICIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvZXUtY2VudHJhbC0xX0dyNllTZjJjcyIsImN1c3RvbTpiaXJ0aF9kYXRlIjoiMCIsImN1c3RvbTpwaG9uZSI6IiAiLCJhdXRoX3RpbWUiOjE2OTcyMjA4OTcsImN1c3RvbTpsYXN0bmFtZSI6IiAiLCJjdXN0b206bG9jYWxlX3N0ciI6IkRFIiwiZXhwIjoxNjk3MjI0NDk3LCJjdXN0b206Y3JlYXRlZF9jb3Vyc2VzIjoiMCIsImlhdCI6MTY5NzIyMDg5NywianRpIjoiNTc3MWRhNWEtZDA5OS00MGMwLTkyZjMtZWZmZTc3YWU4Y2YxIiwiZW1haWwiOiJuaWNsYXMuZ3JlZ29yMjBAZ21haWwuY29tIiwiY3VzdG9tOnV1aWQiOiJlZmVhNmY3MS0xZmQ4LTQwOTItOTgwOS0yNWUxOWQyMTJjZDkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImN1c3RvbTppc19jcmVhdG9yIjoiRmFsc2UiLCJjb2duaXRvOnVzZXJuYW1lIjoibmljbGFzNjMiLCJjdXN0b206Y3JlYXRvcl9yYXRpbmciOiIwIiwib3JpZ2luX2p0aSI6ImM0OGZiYWE2LTFiOGQtNDQwMS1hOGNiLWI0ZWYyYjYxMzkwYSIsImN1c3RvbTpnZW5kZXIiOiJNYWxlIiwiYXVkIjoiNGE0ZnMzaHFkMWsyYzEyMmRlajdpdTR2ZjMiLCJjdXN0b206bWVtYmVyX3NpbmNlIjoiMTY5NzAzMzU4MSIsImV2ZW50X2lkIjoiNDdjZmI3NTMtNjkzMC00ZmNhLWE5MDMtNmE1ZjFjMWU0NzJjIiwiY3VzdG9tOnByb2ZpbGVfcGljdHVyZSI6IiAiLCJ0b2tlbl91c2UiOiJpZCIsImN1c3RvbTpzb2xkX2NvdXJzZXMiOiIwIiwiY3VzdG9tOmJpb2dyYXBoeSI6IiAifQ.juunFZPrZwn37KyMz60FGHbMnxTpnRsU38uj6hpbu7cq7erdLVAtc2ONdKNVSuzRKQtz6u1TupXbuhoA9oUJEvrRs-HqiMMLYCg4xo0IWb1FIml4u8SR6sI2qMHic5tMGQy-1aCZstPk-6tWhCzdZjcCRYnB31k5vs_p0M_XHwf3RugYk3tEyjMA9s4m9oj1gFXNd_pC0be7Bkb5dMU7sIsj2JEaRSj3GXxrX2PE5bGj9xEfwbTY6I1Qzio2rAfUnP08ePqriX04RrZ4nss1qAS8F-zjQ1gfpL4KlOaxEVqtRNZ-R5d9Mhjb8yuxu0CPtaGYBlEfSvqJ1LhCRhDIBg"""

    resp = check_and_decode_jwt(
        token=INVALID_PUB_KEY,
        region=REGION,
        user_pool_id=USER_POOL_ID,
    )
    assert resp[0] is JwtStatus.INVALID_PUBLIC_KEY
    assert (
        resp[0].message
        == "invalid public key used to sign the token, check if the right USER POOL ID was provided"
    )


def test_expired_signature_key():
    resp = check_and_decode_jwt(
        token=VALID_TOKEN,
        region=REGION,
        user_pool_id=USER_POOL_ID,
    )
    assert resp[0] is JwtStatus.SIGNATURE_EXPIRED
    assert resp[0].message == "Signature of jwt expired"


def test_invalid_signature():
    INVALID_SIGNATURE = """eyJraWQiOiJEUFdRMHNFaytpZFpEeUpQcEU3S0ljbXpIMjFlZVhTWU9ZeWFGeXJZQ1pZPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxM2U0MzgxMi0zMDAxLTcwYjctNWEyNC1kNjUxNzI2MDBmYzkiLCJjdXN0b206Zmlyc3RuYW1lIjoiICIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvZXUtY2VudHJhbC0xX0dyNllTZjJjcyIsImN1c3RvbTpiaXJ0aF9kYXRlIjoiMCIsImN1c3RvbTpwaG9uZSI6IiAiLCJhdXRoX3RpbWUiOjE2OTcyMjA4OTcsImN1c3RvbTpsYXN0bmFtZSI6IiAiLCJjdXN0b206bG9jYWxlX3N0ciI6IkRFIiwiZXhwIjoxNjk3MjI0NDk3LCJjdXN0b206Y3JlYXRlZF9jb3Vyc2VzIjoiMCIsImlhdCI6MTY5NzIyMDg5NywianRpIjoiNTc3MWRhNWEtZDA5OS00MGMwLTkyZjMtZWZmZTc3YWU4Y2YxIiwiZW1haWwiOiJuaWNsYXMuZ3JlZ29yMjBAZ21haWwuY29tIiwiY3VzdG9tOnV1aWQiOiJlZmVhNmY3MS0xZmQ4LTQwOTItOTgwOS0yNWUxOWQyMTJjZDkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImN1c3RvbTppc19jcmVhdG9yIjoiRmFsc2UiLCJjb2duaXRvOnVzZXJuYW1lIjoibmljbGFzNjMiLCJjdXN0b206Y3JlYXRvcl9yYXRpbmciOiIwIiwib3JpZ2luX2p0aSI6ImM0OGZiYWE2LTFiOGQtNDQwMS1hOGNiLWI0ZWYyYjYxMzkwYSIsImN1c3RvbTpnZW5kZXIiOiJNYWxlIiwiYXVkIjoiNGE0ZnMzaHFkMWsyYzEyMmRlajdpdTR2ZjMiLCJjdXN0b206bWVtYmVyX3NpbmNlIjoiMTY5NzAzMzU4MSIsImV2ZW50X2lkIjoiNDdjZmI3NTMtNjkzMC00ZmNhLWE5MDMtNmE1ZjFjMWU0NzJjIiwiY3VzdG9tOnByb2ZpbGVfcGljdHVyZSI6IiAiLCJ0b2tlbl91c2UiOiJpZCIsImN1c3RvbTpzb2xkX2NvdXJzZXMiOiIwIiwiY3VzdG9tOmJpb2dyYXBoeSI6IiAifQ.juunFZPrZwn37KyMz60FGHbMnxTpnRsU38uj6hpbu7cq7erdLVAtc2ONdKNVSuzRKQtz6u1TupXbuhoA9oUJEvrRs-HqiMMLYCg4xo0IWb1FIml4u8SR6sI2qMHic5tMGQy-1aCZstPk-6tWhCzdZjcCRYnB31k5vs_p0M_XHwf3RugYk3tEyjMA9s4m9oj1gFXNd_pC0be7Bkb5dMU7sIsj2JEaRSj3GXxrX2PE5bGj9xEfwbTY6I1Qzio2rAfUnP08ePqriX04RrZ4nss1qAS8F-zjQ1gfpL4KlOaxEVqtRNZ-R5d9Mhjb8yuxu0CPtaGyBlEfSvqJ1LhCRhDIBg"""

    resp = check_and_decode_jwt(
        token=INVALID_SIGNATURE,
        region=REGION,
        user_pool_id=USER_POOL_ID,
    )
    assert resp[0] is JwtStatus.INVALID_SIGNATURE
    assert resp[0].message == "Signature of jwt is invalid"
