import json
import uuid
from django.http import JsonResponse
import psycopg2
from django.views.decorators.csrf import csrf_exempt
from psycopg2 import IntegrityError, InternalError, DatabaseError
import re
import jwt
from email_validator import validate_email, EmailNotValidError
from config import database, username, hostname, password, port, jwt_secret
import bcrypt

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


def get_user_password(received_username: str):
    try:
        cur = conn.cursor()
        cur.execute("select user_password from users where username = %(value)s", {"value": received_username})
        if cur.rowcount != 1:
            return None
        return cur.fetchone()[0]
    except (DatabaseError, InternalError):
        return None


def get_educator_password(received_email: str):
    try:
        cur = conn.cursor()
        cur.execute("select password from educator where educator_email = %(value)s", {"value": received_email})
        if cur.rowcount != 1:
            return None
        return cur.fetchone()[0]
    except (DatabaseError, InternalError):
        return None


def get_educator_id(received_email: str):
    try:
        cur = conn.cursor()
        cur.execute("select educator_id from educator where educator_email = %(value)s", {"value": received_email})
        if cur.rowcount != 1:
            return None
        return cur.fetchone()[0]
    except (DatabaseError, InternalError):
        return None


def get_user_id(received_username: str):
    try:
        cur = conn.cursor()
        cur.execute("select user_id from users where username = %(value)s", {"value": received_username})
        if cur.rowcount != 1:
            return None
        return cur.fetchone()[0]
    except (DatabaseError, InternalError):
        return None


def is_username_valid(received_username: str) -> bool:
    if not 3 < len(received_username) < 18:
        return False
    if not re.match("^[a-zA-Z0-9_.-]+$", received_username):
        return False
    return True


def is_name_valid(first_name: str) -> bool:
    if len(first_name) < 2:
        return False
    return True


def hash_password(received_password: str) -> str:
    return bcrypt.hashpw(received_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(hashed_password: str, received_password: str) -> bool:
    return bcrypt.checkpw(received_password.encode("utf-8"), hashed_password.encode("utf-8"))


def generate_jwt_token_user(user_id: str) -> str:
    return jwt.encode({"user_id": user_id, "is_user": True}, jwt_secret, algorithm='HS256')


def generate_jwt_token_educator(educator_id: str) -> str:
    return jwt.encode({"user_id": educator_id, "is_user": False}, jwt_secret, algorithm='HS256')


def get_jwt_token(request, **kwargs):
    token = request.META['HTTP_TOKEN']
    return token


def decode_jwt(auth_token: str) -> str:
    return jwt.decode(auth_token, jwt_secret, algorithms='HS256')


def authenticate_user(request):
    try:
        received_token = request.COOKIES.get('JWT-TOKEN')
        if not received_token:
            raise False
        payload = jwt.decode(received_token, jwt_secret, algorithms='HS256')
        if not does_username_already_exist(payload['user_id']):
            return False
        if not payload['is_user']:
            return False
        return True
    except KeyError:
        return False
    except jwt.ExpiredSignatureError:
        return False


def educator_email_already_exists(email_address: str):
    cur = conn.cursor()
    cur.execute("select educator_email from educator where educator_email = %(value)s",
                {"value": email_address})
    if cur.rowcount == 1:
        return True
    return False


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
            return JsonResponse({"error": "The length of first name should be at least 2 letters."},
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
            token = generate_jwt_token_user(str(user_id))
            jsonResponse = JsonResponse({"message": "Success"})
            jsonResponse.set_cookie(key="JWT-TOKEN", value=token)
            return jsonResponse
        except IntegrityError:
            return JsonResponse({"error": "Something went wrong."}, status=client_error)
    except KeyError:
        return JsonResponse({"error": "Required field was not found. Please send null data fields too."},
                            status=client_error)


@csrf_exempt
def user_login(request) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "A POST Request was expected."}, status=client_error)
    if not request.content_type == "application/json":
        return JsonResponse({"error": "JSON Data was expected."}, status=client_error)
    try:
        received_data = json.loads(request.body.decode("utf-8"))
        received_username = received_data["username"]
        received_password = received_data["password"]
        if not (received_username or received_password):
            return JsonResponse({"error": "Required data was not found."}, status=client_error)
        hashed_password = get_user_password(received_username)
        if hashed_password:
            if check_password(hashed_password, received_password):
                user_id = get_user_id(received_username)
                if user_id:
                    token = generate_jwt_token_user(str(user_id))
                    jsonResponse = JsonResponse({"message": "Success"})
                    jsonResponse.set_cookie(key="JWT-TOKEN", value=token)
                    return jsonResponse
            else:
                return JsonResponse({"error": "The Username and Password combination didn't match."},
                                    status=client_error)
        else:
            return JsonResponse({"error": "The entered username don't exists."}, status=client_error)
    except KeyError:
        return JsonResponse({"error": "Required keys not found."}, status=client_error)


@csrf_exempt
def educator_signup(request) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "A POST Request was expected"}, status=client_error)
    if not request.content_type == "application/json":
        return JsonResponse({"error": "JSON Data was expected."}, status=client_error)
    try:
        received_data = json.loads(request.body.decode("utf-8"))

        educator_email = received_data["educator_email"]
        educator_first_name = received_data["educator_first_name"]
        educator_last_name = received_data["educator_last_name"]
        educator_country = received_data["educator_country"]
        educator_password = received_data["educator_password"]

        if not (educator_email or educator_first_name or educator_last_name or educator_country or educator_password):
            return JsonResponse({"error": "Required fields can't be empty."}, status=client_error)

        if not validate_email_address(educator_email):
            return JsonResponse({"error": "The Email Address is invalid."}, status=client_error)
        if educator_email_already_exists(educator_email):
            return JsonResponse({"error": "The Email Address is already registered by other educator."},
                                status=client_error)

        if not is_name_valid(educator_first_name):
            return JsonResponse({"error": "The length of first name should be at least 2 letters."},
                                status=client_error)

        if not is_name_valid(educator_last_name):
            return JsonResponse({"error": "The length of last name should be at least 2 letters."}, status=client_error)

        educator_password = hash_password(educator_password)

        educator_id = uuid.uuid4()

        cur = conn.cursor()
        try:
            cur.execute(
                "insert into educator(educator_id, educator_email, first_name, last_name, country, password) "
                " values (%s,%s,%s,%s,%s,%s)",
                (educator_id, educator_email, educator_first_name, educator_last_name, educator_country,
                 educator_password))

            conn.commit()
            token = generate_jwt_token_educator(str(educator_id))
            jsonResponse = JsonResponse({"message": "Success"})
            jsonResponse.set_cookie(key="JWT-TOKEN", value=token)
            return jsonResponse
        except IntegrityError:
            return JsonResponse({"error": "Something went wrong."}, status=client_error)
    except KeyError:
        return JsonResponse({"error": "Required field was not found. Please send null data fields too."},
                            status=client_error)


@csrf_exempt
def educator_login(request) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "A POST Request was expected."}, status=client_error)
    if not request.content_type == "application/json":
        return JsonResponse({"error": "JSON Data was expected."}, status=client_error)
    try:
        received_data = json.loads(request.body.decode("utf-8"))

        received_email = received_data["educator_email"]
        received_password = received_data["educator_password"]

        if not (received_email or received_password):
            return JsonResponse({"error": "Required data was not found."}, status=client_error)

        hashed_password = get_educator_password(received_email)
        if hashed_password:
            if check_password(hashed_password, received_password):
                educator_id = get_educator_id(received_email)
                if educator_id:
                    token = generate_jwt_token_educator(str(educator_id))
                    jsonResponse = JsonResponse({"message": "Success"})
                    jsonResponse.set_cookie(key="JWT-TOKEN", value=token)
                    return jsonResponse
            else:
                return JsonResponse({"error": "The Email and Password combination didn't match."},
                                    status=client_error)
        else:
            return JsonResponse({"error": "The entered email don't exists."}, status=client_error)
    except KeyError:
        return JsonResponse({"error": "Required keys not found."}, status=client_error)
