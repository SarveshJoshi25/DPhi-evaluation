import json
import uuid
from django.http import JsonResponse
import psycopg2
from django.views.decorators.csrf import csrf_exempt
from psycopg2 import IntegrityError
import re
import jwt
from email_validator import validate_email, EmailNotValidError
from config import database, username, hostname, password, port, jwt_secret
import bcrypt
import smtplib
from smtplib import SMTPException

# Global variable declaration.
client_error = 400
conn = psycopg2.connect(database=database, user=username, host=hostname, password=password,
                        port=port)


# Declaration of Non view functions

def validate_email_address(email_address: str) -> bool:
    try:
        email_address = validate_email(email_address).email
    except EmailNotValidError:
        return False
    return True


def does_email_already_exists(email_address: str) -> bool:
    cur = conn.cursor()
    cur.execute("select email_address from users where email_address = %(value)s",
                {"value": email_address})
    if cur.rowcount == 1:
        return True
    return False


def does_username_already_exist(received_username: str) -> bool:
    cur = conn.cursor()
    cur.execute("select username from users where username = %(value)s",
                {"value": received_username})
    if cur.rowcount == 1:
        return True
    return False


def is_username_valid(received_username: str) -> bool:
    if not 3 < len(received_username) < 18:
        return False
    if not re.match("^[a-zA-Z0-9_.-]+$", received_username):
        return False
    return True


def is_name_valid(first_name: str) -> bool:
    if len(first_name) < 4:
        return False
    return True


def hash_password(received_password: str) -> str:
    return bcrypt.hashpw(received_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(hashed_password: str, received_password: str) -> bool:
    return bcrypt.checkpw(received_password.encode("utf-8"), hashed_password.encode("utf-8"))


def generate_jwt_token(user_id: str) -> str:
    return jwt.encode({"user_id": user_id, "is_user": True}, jwt_secret, algorithm='HS256')


def index(request) -> JsonResponse:
    # This view is for testing purpose, and can be used to "wake up" the server.
    return JsonResponse({"welcome": "This API is working successfully!"})


@csrf_exempt
def user_signup(request) -> JsonResponse:
    """
            This view (user_signup) is for serving requests to create new user accounts.

            This API request don't require Authorization.

            The user's data should be sent with the request in the body section, as sending through URL is unsafe and
            doesn't look good on User's side.

            1. Sample Input:
            {
                "username" : "_sarveshjoshi",
                "email_address" : "my_valid_email@gmail.com",
                "first_name" : "Sarvesh",
                "last_name" : "Joshi",
                "country" : "India",
                "password" : "ValidPassword"
            }

            2. Sample Output:
            {
                "user_id" : "JWTEncodedTokenOfUserID"
            }

            3. Sample Error:
            {
                "error" : "Reason of Error generation"
            }

                The front-end is supposed to save this returned user_id in the User's cookies. This is JWT Encoded ID,
            so original ID won't be disclosed. This ID should be sent with every request that needs Authentication.
        """
    if request.method != "POST":
        return JsonResponse({"error": "A POST Request was expected"}, status=client_error)
    if not request.content_type == "application/json":
        return JsonResponse({"error": "JSON Data was expected."}, status=client_error)
    try:
        received_data = json.loads(request.body.decode("utf-8"))

        received_username = received_data["username"]
        email_address = received_data["email_address"]
        first_name = received_data["first_name"]
        last_name = received_data["last_name"]
        country = received_data["country"]
        user_password = received_data["password"]

        if not (received_username or email_address or first_name or country or user_password):
            return JsonResponse({"error": "Required fields can't be empty."}, status=client_error)

        #     Validating the Email Address first.
        if not validate_email_address(email_address):
            return JsonResponse({"error": "The Email Address is invalid."}, status=client_error)
        if does_email_already_exists(email_address):
            return JsonResponse({"error": "The Email Address does already exist."}, status=client_error)
        if not is_username_valid(received_username):
            return JsonResponse({"error": "The Username is not valid"}, status=client_error)
        if does_username_already_exist(received_username):
            return JsonResponse({"error": "The entered username does already exists."}, status=client_error)
        if not is_name_valid(first_name):
            return JsonResponse({"error": "The length of first name should be at least 3 letters."},
                                status=client_error)

        user_password = hash_password(user_password)

        user_id = uuid.uuid4()

        cur = conn.cursor()
        try:
            cur.execute(
                "insert into users(user_id, username, email_address, first_name, last_name, country, user_password) "
                " values (%s,%s,%s,%s,%s,%s,%s)",
                (user_id, received_username, email_address, first_name, last_name, country, user_password))

            conn.commit()
            return JsonResponse({"user_id": generate_jwt_token(str(user_id))})
        except IntegrityError:
            return JsonResponse({"error": "Something went wrong."}, status=client_error)
    except KeyError:
        return JsonResponse({"error": "Required field was not found. Please send null data fields too."},
                            status=client_error)