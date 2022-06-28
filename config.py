from dotenv import load_dotenv
import os

load_dotenv()

hostname = os.getenv("DATABASE_HOST")
username = os.getenv("DATABASE_USER")
password = os.getenv("DATABASE_PASSWORD")
database = os.getenv("DATABASE_NAME")
port = os.getenv("PORT")
jwt_secret = os.getenv("JWT_SECRET")
django_secret = os.getenv("DJANGO_SECRET")


