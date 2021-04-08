
import base64
import json
import random
import sys
from halo import Halo

from config import Config
from dbhelper import logger

ANSII_GREEN = '\u001b[32m'
ANSII_RESET = '\x1b[0m'


def print_message(msg_name, message):
    print_object(message, "<<<", f"Incoming Message -- {msg_name}")


def print_object(obj, prefix, preamble):
    print(f"{prefix}  {preamble}")

    if isinstance(obj, str):
        obj_str = obj
    else:
        obj_str = json.dumps(obj, indent=2)

    for line in obj_str.splitlines():
        print(f"{prefix} {line}")

    print()


def non_handled(error_msg: str, received_message=None):
    # global server
    print_error(error_msg)
    if received_message is not None:
        print_error(received_message)
    # if server:
    #     server.close()
    # sys.exit(1)


def default_handler(message):
    non_handled(f'Message name is not handled', message)


def make_spinner(msg):
    return Halo(text=f'{msg} ... ', spinner='line', interval=450, color=None, placement='right')


def console_input(request, default_value=None):
    print()
    if default_value:
        print(f'{request}:')
        print(f'{ANSII_GREEN}{default_value}{ANSII_RESET} is set via environment variable')
        input('Press any key to continue')
        return default_value
    else:
        val = input(f"{request}: ").strip()
        if not val:
            return ""
        return val


def console_yes_no(request, default_yes):
    yes_no = "[y]/n" if default_yes else "y/n"
    modified_request = request + "? " + yes_no
    response = console_input(modified_request).strip().lower()

    if default_yes and not response:
        return True
    elif "y" == response:
        return True
    elif "n" == response:
        return False
    raise Exception("Did not get a valid response -- '" + response + "' is not y or n")


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def get_random_version():
    return '{}.{}.{}'.format(get_random_int(), get_random_int(), get_random_int())


def get_random_int():
    random.seed()
    return random.randrange(0, 1000)


def validate_application_id(application_id):
    error_response = {
        "status": "fail", "message": "application_id_incorrect",
        "error": "Application Id is not correct"
    }
    try:
        application_id_bytes = base64.b64decode(application_id)
    except Exception as error:
        logger("Error", "URS", "Inbound",0, "validate_application_id", error, "401")
        return error_response, 401

    if application_id_bytes != Config.APPLICATION_ID:
        logger("Error", "URS", "Inbound",0, "validate_application_id", "Wrong Application ID passed", "401")
        return error_response, 401
    return {"status": "success", "message": "success"}, 200


def validate_param(param_name, param_value, fun_name):
    response_data = {}
    is_valid = True
    if not param_value:
        is_valid = False
        response_data = {
            "status": "fail", "message": "{}_IS_INCORRECT".format((param_name.upper())),
            "error": "Please pass {} as query param".format(param_name)
        }
        logger("Error", "URS", "Inbound", 0, fun_name, "{} not passed".format(param_name), "400")

    if not param_value.isnumeric() and is_valid:
        is_valid = False
        response_data = {
            "status": "fail", "message": "{}_IS_INCORRECT".format((param_name.upper())),
            "error": "{} should be integer".format(param_name.upper())
        }
        logger("Error", "URS", "Inbound", 0, fun_name, "{} : {} should be integer".format(param_name.upper(), str(param_value)), "400")

    if is_valid and (9223372036854775807 < int(param_value) or int(param_value) < 0):
        is_valid = False
        response_data = {
            "status": "fail", "message": "{}_IS_INCORRECT".format(param_name.upper()),
            "error": "{} : {} Should be in  range 0 to 9223372036854775806.".format(param_name.upper(), str(param_value))
        }
        logger("Error", "URS", "Inbound", param_value, fun_name, "{} : {} Should be in  range 0 to 9223372036854775806.".format(param_name.upper(), str(param_value)), "400")
    return is_valid, response_data


async def noop(msg_name, message):
    pass
