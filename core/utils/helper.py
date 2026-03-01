import datetime
import os
from io import BytesIO
from django.core.files import File
from PIL import Image, ImageOps
from contextlib import suppress
import jwt
import requests
from cryptography.fernet import Fernet
from django.conf import settings
import base64
from django.core.mail import EmailMessage, send_mass_mail
import blurhash
# image compression
from rest_framework.exceptions import ValidationError
from decimal import Decimal


def ImageCompress(file):
    """
    Image size compression
    """
    if file:
        try:
            im = Image.open(file)
            image = im.convert("RGB")
            image = ImageOps.exif_transpose(image)
            im_io = BytesIO()
            image.save(
                im_io, im.format, quality=50, width=image.width, height=image.height
            )
            new_image = File(im_io, name=file.name)
            return new_image
        except IOError:
            return file


# multiple object update get id/ other field based
def validate_ids(data, field="id", unique=True):
    if isinstance(data, list):
        id_list = [int(x[field]) for x in data]

        if unique and len(id_list) != len(set(id_list)):
            raise ValidationError(f"Multiple updates to a single {field} found")

        return id_list

    return [data]


def send_sms(numbers: list, message: str):
    for number in numbers:
        # requests.post(f"http://10.27.27.147:8000/?number={number}&message={message}")

        url = f"http://10.27.27.147:8000/?number={number}&message={message}"

        response = requests.request("POST", url)

        print(response.text)


def create_token(payload: dict):
    return jwt.encode(
        payload=payload,
        key=settings.SECRET_KEY,
        algorithm=settings.SIMPLE_JWT["ALGORITHM"],
    )


def secret_encode(data: str):
    key = bytes(settings.SECRET_KEY, "utf-8")
    return Fernet(key).encrypt(bytes(data, "utf-8")).decode("utf-8")


def secret_decode(token: str):
    key = bytes(settings.SECRET_KEY, "utf-8")
    return Fernet(key).decrypt(bytes(token, "utf-8")).decode("utf-8")


# get client ip address
def get_client_ip(request):
    with suppress(Exception):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return (
            x_forwarded_for.split(",")[0]
            if x_forwarded_for
            else request.META.get("REMOTE_ADDR")
        )

    return None


# rename file
def content_file_path(instance, filename):
    model_name = instance.__class__.__name__
    name = model_name.replace("Model", "")  # replace model from model name
    ext = filename.split(".")[-1]
    date = datetime.datetime.now()
    filename = f"{instance.id}.{ext}"
    return f"{name}/{date.year}-{date.month}-{date.day}/{filename}"


# email send function
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data["email_subject"],
            body=data["email_body"],
            to=[data["to_email"]],
        )
        email.send()


def base64_encode(data):
    return base64.b64encode(str(data).encode("utf-8")).decode("utf-8")


def base64_decode(data):
    return base64.b64decode(str(data)).decode("utf-8")


def int_to_hex(data):
    return '{:016x}'.format(int(data))


def hex_to_int(data):
    return int(str(data), 16)


def get_hash(picture_url):
    # with open(picture_url[1:], 'rb') as image_file:
    #     url_hash = blurhash.encode(image_file, x_components=4, y_components=3)
    # with Image.open(picture_url[1:]) as image_file:
    #     image_file.thumbnail((100, 100))
    #     url_hash = blurhash.encode(image_file, x_components=4, y_components=3)
    loaded_image = Image.open(picture_url[1:])
    temp = loaded_image.copy()
    temp.thumbnail((100, 100))
    url_hash = blurhash.encode(temp, x_components=4, y_components=3)
    return str(url_hash)


def get_original_hash(picture_url):
    with open(picture_url[1:], 'rb') as image_file:
        url_hash = blurhash.encode(image_file, x_components=4, y_components=3)
    return str(url_hash)


def get_hash_from_memory(picture):
    loaded_image = Image.open(BytesIO(picture.read()))
    temp = loaded_image
    temp.thumbnail((100, 100))
    url_hash = blurhash.encode(temp, x_components=4, y_components=3)
    return str(url_hash)


def rounding(number, precision):
    decimal_number = Decimal(str(number))  # Convert to Decimal
    cut_number = decimal_number.quantize(Decimal('0.' + '0' * (precision - 1) + '1'))  # Precision of 5 decimal places
    return float(cut_number)
