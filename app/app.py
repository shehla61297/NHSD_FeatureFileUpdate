import logging
import os
import time
import pyqrcode
import requests
import traceback
import asyncio
from asyncio.base_events import Server
from aiohttp import web
from aiohttp.web_routedef import RouteTableDef
import jinja2
import aiohttp_jinja2

from verity_sdk.handlers import Handlers
from verity_sdk.protocols.v0_6.IssuerSetup import IssuerSetup
from verity_sdk.protocols.v0_6.UpdateConfigs import UpdateConfigs
from verity_sdk.protocols.v0_6.UpdateEndpoint import UpdateEndpoint
from verity_sdk.protocols.v0_6.WriteCredentialDefinition import WriteCredentialDefinition
from verity_sdk.protocols.v0_6.WriteSchema import WriteSchema
from verity_sdk.protocols.v0_7.Provision import Provision
from verity_sdk.protocols.v1_0.Connecting import Connecting
from verity_sdk.protocols.v1_0.IssueCredential import IssueCredential
from verity_sdk.protocols.v1_0.Relationship import Relationship
from verity_sdk.utils.Context import Context
from indy import crypto
from indy.error import WalletAlreadyOpenedError

import dbhelper
from helper import *
import config
from urs_service import get_user_detail

logging_format = "[%(asctime)s] %(process)d-%(levelname)s "
logging_format += "%(module)s::%(funcName)s():l%(lineno)d: "
logging_format += "%(message)s"

logging.basicConfig(
    format=logging_format,
    level=logging.DEBUG
)
log = logging.getLogger()

INSTITUTION_NAME: str = config.Config.INSTITUTION_NAME
LOGO_URL: str = config.Config.LOGO_URL
WALLET_NAME: str = config.Config.WALLET_NAME
WALLET_KEY: str = config.Config.WALLET_KEY
CONFIG_PATH: str = 'verity-context.json'
QR_CODE_STRING: str = ""

context = Context
issuer_did: str = config.Config.ISSUER_DID
issuer_verkey: str = ''

server: Server
port: int = 4000
handlers: Handlers = Handlers()
handlers.set_default_handler(default_handler)
handlers.add_handler('trust_ping', '1.0', noop)

routes: RouteTableDef = web.RouteTableDef()


async def set_up_and_generate_qr_code(loop):
    global context
    await setup(loop)
    relationship_did, qr_code_str = await create_relationship(loop)
    return relationship_did, qr_code_str


async def create_relationship(loop) -> tuple:
    global context
    global handlers

    # Relationship protocol has two steps
    # 1. create relationship key
    # 2. create invitation

    # Constructor for the Relationship API
    relationship: Relationship = Relationship()

    relationship_did = loop.create_future()
    thread_id = loop.create_future()

    spinner = make_spinner('Waiting to create relationship')  # Console spinner

    # handler for the response to the request to start the Connecting protocol.
    async def created_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        # print_message(msg_name, message)
        if msg_name == Relationship.CREATED:
            thread_id.set_result(message['~thread']['thid'])
            relationship_did.set_result(message['did'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, created_handler
    )

    spinner.start()

    # starts the relationship protocol
    await relationship.create(context)
    thread_id = await thread_id
    relationship_did = await relationship_did

    # Step 2
    invitation = loop.create_future()
    qr_string = ""

    spinner = make_spinner('Waiting to create invitation')  # Console spinner

    # handler for the accept message sent when invitation is created
    async def invitation_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        # print_message(msg_name, message)
        if msg_name == Relationship.INVITATION:
            # invite_url = message['inviteURL']
            invite_url = message['shortInviteURL']
            qr = pyqrcode.create(invite_url)
            nonlocal qr_string
            qr_string = qr.png_as_base64_str(scale=5)
            # write QRCode to disk
            # Saving as png not required here
            qr.png("qrcode.png")
            invitation.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    spinner.start()
    handlers.add_handler(
        Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, invitation_handler
    )

    relationship: Relationship = Relationship(relationship_did, thread_id)
    await relationship.connection_invitation(context, True)
    await invitation
    return relationship_did, qr_string  # return owning DID for the connection


async def create_connection(loop):
    global context
    global handlers

    # Connecting protocol is started from the Holder's side (ConnectMe)
    # by scanning the QR code containing connection invitation
    # Connection is established when the Holder accepts the connection on the device
    # i.e. when the RESPONSE_SENT control message is received

    connection = loop.create_future()

    spinner = make_spinner('Waiting to respond to connection')  # Console spinner

    # handler for messages in Connecting protocol
    async def connection_handler(msg_name, message):
        if msg_name == Connecting.REQUEST_RECEIVED:
            pass
        elif msg_name == Connecting.RESPONSE_SENT:
            spinner.stop_and_persist('Done')
            connection.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(Connecting.MSG_FAMILY, Connecting.MSG_FAMILY_VERSION, connection_handler)

    spinner.start()

    # waits for request
    try:
        await connection  # wait for response from verity application
    except Exception as e:
        dbhelper.logger(
            "Error", "Verity", "Inbound", 0, "create_connection",
            "create_connection failed", "NA"
        )
        log.error("Issue with connection creation: {}", e)


async def write_ledger_schema(loop) -> str:
    global context
    schema_name = config.Config.SCHEMA_NAME
    schema_version = get_random_version()
    # constructor for the Write Schema protocol
    schema = WriteSchema(schema_name, schema_version, config.Config.SCHEMA_ATTRIBUTES)

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write schema to ledger')  # Console spinner

    # handler for message received when schema is written
    async def schema_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        # print_message(msg_name, message)
        if msg_name == WriteSchema.STATUS:
            first_step.set_result(message['schemaId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        WriteSchema.MSG_FAMILY, WriteSchema.MSG_FAMILY_VERSION, schema_written_handler
    )

    spinner.start()

    # request schema be written to ledger
    await schema.write(context)
    schema_id = await first_step  # wait for operation to be complete
    # print("SCHEMAIDDDDDDDDDDDDDDDDD" + schema_id)
    return schema_id  # returns ledger schema identifier


async def write_ledger_cred_def(loop, schema_id: str) -> str:
    global context
    # constructor for the Write Credential Definition protocol
    cred_def = WriteCredentialDefinition(
        config.Config.CRED_DEFINITION_NAME, schema_id, config.Config.CRED_DEF_TAG
    )

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write cred def to ledger')  # Console spinner

    # handler for message received when schema is written
    async def cred_def_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        # print_message(msg_name, message)
        if msg_name == WriteCredentialDefinition.STATUS:
            first_step.set_result(message['credDefId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        WriteCredentialDefinition.MSG_FAMILY,
        WriteCredentialDefinition.MSG_FAMILY_VERSION,
        cred_def_written_handler
    )

    spinner.start()

    # request the cred def be writen to ledger
    await cred_def.write(context)
    cred_def_id = await first_step  # wait for operation to be complete
    return cred_def_id  # returns ledger cred def identifier


async def issue_credential(loop, relationship_did, user_uuid, requester_id):
    credential_name = config.Config.CRED_DEFINITION_NAME
    credential_data = await get_user_detail(user_uuid, requester_id)

    issue = IssueCredential(
        relationship_did, None, config.Config.CRED_DEF_ID, credential_data, credential_name, "0", True
    )

    await issue.offer_credential(context)


async def setup(loop):
    global context
    global issuer_did
    await set_context()

    with open('verity-context.json', 'w') as f:
        f.write(context.to_json())

    await update_configs()
    await issuer_identifier(loop)

    if not issuer_did:
        log.info('\nIssuer DID is not created. Performing Issuer setup now...')
        await setup_issuer(loop)
    # print(issuer_did + "     ISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUERISSSUER")
    # log.info('\nIssuer DID is  created....' + issuer_did)


async def set_context():
    global context
    with open(CONFIG_PATH, 'r') as f:
        config_data = f.read()

    with open("test.json", 'r') as f:
        test_data = json.loads(f.read())

    if dict(test_data).get("contextAlreadyExist") == "true":
        try:
            await update_webhook_endpoint()
        except Exception as e:
            log.error("Error: {} , in updating endpoint on context".format(e))
            await create_context_from_config(config_data)
    else:
        if not config_data:
            context = await provision_agent()
        else:
            await create_context_from_config(config_data)

        with open('verity-context.json', 'w') as f:
            f.write(context.to_json())


async def create_context_from_config(config_data):
    global context
    try:
        context = await Context.create_with_config(config_data)
    except WalletAlreadyOpenedError:
        await context.close_wallet()

    with open("test.json", 'w') as f:
        json.dump({"contextAlreadyExist": "true"}, f)
    await update_webhook_endpoint()


async def setup_schema(request):
    # TODO: Need extra layer of security at this endpoint, this should be callable by mastek user only
    loop = asyncio.get_event_loop()
    await set_context()
    schema_id = await write_ledger_schema(loop)
    credential_definition_id = await write_ledger_cred_def(loop, schema_id)
    # print("CREDDDDDDDDDDDDDDDDDDDDDDD" + credential_definition_id)
    return web.json_response({'credentialDefinitionID': credential_definition_id}, status=200)


async def provision_agent():
    global context

    # replace token value here it must be a valid JSON string, or fetch from OS environment
    # this is currently used by AWS linux instance
    # token = '{"sponseeId": "Mastek", "sponsorId": "evernym-demo-sponsor", "nonce": "0Cx672Cpu1Ym6iucfr8SWBNszkBnaWr3", "timestamp": "2021-01-29T12:01:06.846458", "sig": "iGgohqAxg0V0lZ2ymz2ldmaj1Gr71WQCg7jIHhPhOE6DCuiHOP3u8wpvqGOqhLURlUI5PiFLu6dHvGRIZN26CA==", "sponsorVerKey": "BCHo16QAdnZtPxaEjGBPQEiohxF62LR3qVwce298g7Jf"}'
    token = config.Config.TOKEN
    # on local:
    # token = '{"sponseeId": "Mastek", "sponsorId": "evernym-demo-sponsor", "nonce": "0YClz7Xw76BbE0xtEsUuUPweKpvKCK9z", "timestamp": "2021-01-29T12:01:06.846458", "sig": "5Z8u98J2KUGW/CDY15pz9BdqI7XQvtHg8BPOOhd4rXKO6quMJVXxESVGtkbdGPXhN8W39pb+5CbEjApgv24lCQ==", "sponsorVerKey": "BCHo16QAdnZtPxaEjGBPQEiohxF62LR3qVwce298g7Jf"}'
    verity_url = config.Config.VERITY_URL
    # create initial Context
    context = await Context.create(WALLET_NAME, WALLET_KEY, verity_url)

    # ask that an agent by provision (setup) and associated with created key pair
    try:
        response = await Provision(token).provision(context)
        return response
    except Exception as e:
        log.error(e)
        log.warning('Provisioning failed! Likely causes:')
        log.warning('- token not provided but Verity Endpoint requires it')
        log.warning('- token provided but is invalid or expired')
        sys.exit(1)


async def update_webhook_endpoint():
    global context, port
    webhook = config.Config.WEBHOOK_URL
    # for local use ngrok:
    context.endpoint_url = webhook

    # request that verity application use specified webhook endpoint
    await UpdateEndpoint().update(context)


async def update_configs():
    handlers.add_handler('update-configs', '0.6', noop)
    configs = UpdateConfigs(INSTITUTION_NAME, LOGO_URL)
    await configs.update(context)


async def issuer_identifier(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()

    spinner = make_spinner('Waiting for current issuer DID')  # Console spinner

    # handler for current issuer identifier message
    async def current_identifier(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER:
            issuer_did = message['did']
            issuer_verkey = message['verKey']
            first_step.set_result(None)
        elif msg_name == IssuerSetup.PROBLEM_REPORT:
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, current_identifier
    )

    spinner.start()

    # query the current identifier
    await issuer_setup.current_public_identifier(context)
    await first_step  # wait for response from verity application


async def setup_issuer(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()
    spinner = make_spinner('Waiting for setup to complete')  # Console spinner

    # handler for created issuer identifier message
    async def public_identifier_handler(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER_CREATED:
            issuer_did = message['identifier']['did']
            # print(issuer_did)
            issuer_verkey = message['identifier']['verKey']
            automated_registration = console_yes_no(
                f'Attempt automated registration via {ANSII_GREEN}https://selfserve.sovrin.org{ANSII_RESET}', True)
            if automated_registration:
                url = 'https://selfserve.sovrin.org/nym'
                payload = json.dumps({
                    'network': 'stagingnet',
                    'did': issuer_did,
                    'verkey': issuer_verkey,
                    'paymentaddr': ''
                })
                headers = {'Accept': 'application/json'}
                response = requests.request('POST', url, headers=headers, data=payload)
                if response.status_code != 200:
                    log.error('Something went wrong with contactig Sovrin portal')
                    log.error('Please add Issuer DID and Verkey to the ledger manually')
                    console_input('Press ENTER when DID is on ledger')
                else:
                    log.info(f'Got response from Sovrin portal: {ANSII_GREEN}{response.text}{ANSII_RESET}')
            else:
                log.info('Please add Issuer DID and Verkey to the ledger manually')
                console_input('Press ENTER when DID is on ledger')
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}')

    # adds handler to the set of handlers
    handlers.add_handler(
        IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, public_identifier_handler
    )

    spinner.start()

    # request that issuer identifier be created
    await issuer_setup.create(context)

    await first_step  # wait for request to complete


async def unpack_message(ctx, message: bytes):
    """
    Extracts the message in the byte array that has been packaged and encrypted for a key that is locally held.
    Args:
        ctx (Context): an instance of the Context object initialized to a verity-application agent
        message (bytes): the raw message received from the verity-application agent
    Returns:
        dict: an unencrypted messages as a JSON object
    """
    jwe: bytes = await crypto.unpack_message(
        ctx.wallet_handle,
        message
    )
    message = json.loads(jwe.decode('utf-8'))['message']
    return json.loads(message)


async def endpoint_handler(request):
    global context
    try:
        if request is not None :
            m = await request.read()
            message = await unpack_message(context, m)
            try:
                await handlers.handle_message(context, m)
            except Exception as e:
                log.error("EXCEPTION in endpoint_handler: {}", e)

            # print("TTTTTTTTTTTTTTTTTTTTT" + message)

            # if message['@type'] == 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response-sent':

            if message['@type'] == 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/sent-response':
                local_loop = asyncio.get_event_loop()
                relationship_did = message.get("relationship")
                for key, value in message.get("~thread")["received_orders"].items():
                    #print("ReceiveOrderIDINSENT" + str(key))
                    receive_orders = str(key)

                user_uuid, request_user_id = dbhelper.get_userid(relationship_did)
                #
                #     dbhelper.logger(
                #         "Audit", "Verity", "Outbound", user_uuid, "Create Connection Start",
                #         "Request to connect verity: {}".format(user_uuid), "NA"
                #     )
                #     start_time = time.time()
                #     # await create_connection(local_loop)
                #     end_time = time.time()
                #     log.info("Time taken by create connection for user: {} is: {}".format(user_uuid, end_time-start_time))
                #
                #recieved orderid update into the userstatus table
                dbhelper.update_user_status(relationship_did, receive_orders, 2)

                dbhelper.logger(
                    "Audit", "Verity", "Outbound", user_uuid, "Create Connection End",
                    "Connected and Update Status to UHE: {}".format(user_uuid), "NA"
                )

                await issue_credential(local_loop, relationship_did, user_uuid, request_user_id)

            if message['@type'] == 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/sent':
                for key, value in message.get("~thread")["received_orders"].items():
                    #print("ReceiveOrderID" + str(key))
                    receive_orders = str(key)

                dbhelper.update_user_status('',receive_orders,3)

                dbhelper.logger(
                    "Audit", "Verity", "Outbound", receive_orders, "Issue Credentials End",
                    "Credentials issued to user and status updated: {}".format(receive_orders), "NA"
                )

        return web.Response(text='Success')
    except Exception as e:
        traceback.print_exc()
        return web.Response(text=str(e))


async def get_identity_qr_code(request):
    generate_qr_image = request.rel_url.query.get("generate_qr_image", "")
    application_id = request.headers.get('applicationId', "")
    if generate_qr_image != "true":
        data, status_code = validate_application_id(application_id)
        if status_code != 200:
            return web.json_response(data, status=status_code)

    user_uuid = request.rel_url.query.get("uuid", "")
    is_valid, response_data = validate_param("uuid", user_uuid, "get_identity_qr_code")
    if not is_valid:
        return web.json_response(response_data, status=400)

    requester_id = request.rel_url.query.get("requesterId", "")
    is_valid, response_data = validate_param("requesterId", requester_id, "get_identity_qr_code")
    if not is_valid:
        return web.json_response(response_data, status=400)

    dbhelper.logger(
        "Audit", "URS", "Inbound", user_uuid, "get_identity_qr_code",
        "getDWIdentityQrCode called for {}".format(user_uuid), "NA"
    )
    # Get Status form DB for UUID and RequesterID the
    # If Status is User Not Enrolled only than return with QrCode from DB.
    # If Status is Enrolled or Activated return with Message User already been scanned QrCode
    # If status is activated than return with Message User already been issued credentials
    status_code, qr_string_db = dbhelper.check_userid_status(user_uuid, requester_id)

    if status_code == "UNE":
        image_source = qr_string_db
        if generate_qr_image:
            response = aiohttp_jinja2.render_template(
                "result.html", request=request,
                context={"image_source": image_source}
            )
            return response
        response_data = {"status": "success", "message": "success", "qrCode": image_source}
        return web.json_response(response_data, status=200)
    elif status_code == "UHE":
        response_data = {
            "status": "fail", "message": "UUID_STATUS_IS_UHE",
            "error": "QR Code of this user have been scanned but credentials not issued"
        }
        return web.json_response(response_data, status=400)
    elif status_code == "UHA":
        response_data = {
            "status": "fail", "message": "UUID_STATUS_IS_UHA",
            "error": "Credential have been already issued to this UUID"
        }
        return web.json_response(response_data, status=400)
    # Store this id as well along with uuid will be required in status call
    loop = asyncio.get_event_loop()
    rel_id, qr_string = await set_up_and_generate_qr_code(loop)
    image_source = "data:image/png;base64,{}".format(qr_string)
    dbhelper.insert_user_status(user_uuid, rel_id, image_source, requester_id)
    # Note: This is just for demo/local purpose only
    if generate_qr_image:
        response = aiohttp_jinja2.render_template(
            "result.html", request=request,
            context={"image_source": image_source}
        )
        return response

    # Note: Here not logging qrCode string as it contains large string
    response_data = {"status": "success", "message": "success"}
    dbhelper.logger("Audit", "URS", "Inbound", user_uuid, "get_identity_qr_code", json.dumps(response_data), "200")
    response_data["qrCode"] = image_source

    return web.json_response(response_data, status=200)


async def home(request):
    response = aiohttp_jinja2.render_template("index.html", request=request, context={})
    return response


async def get_user_identity_status(request):
    application_id = request.headers.get('applicationId', "")

    data, status_code = validate_application_id(application_id)
    if status_code != 200:
        return web.json_response(data, status=status_code)

    user_uuid = request.rel_url.query.get("uuid", "")
    is_valid, response_data = validate_param("uuid", user_uuid, "get_user_identity_status")
    if not is_valid:
        return web.json_response(response_data, status=400)

    dbhelper.logger(
        "Audit", "URS", "Inbound", "get_user_identity_status", user_uuid,
        "getDWUserIdentityStatus called for uuid: {}".format(user_uuid), "NA"
    )

    status_code, requester_id, status_details = dbhelper.get_user_status_by_uuid(user_uuid)
    if not status_code:
        response_data = {
            "status": "fail", "message": "user_not_found", "error": "Digital Credential not issued to Holder"
        }
        dbhelper.logger("Error", "URS", "Inbound", user_uuid, "get_user_identity_status",
                        "Digital Credential not issued to Holder",
                        "404")
        return web.json_response(response_data, status=404)

    response_data = {"status": "success", "message": "success", "userStatusCode": status_code,
                     "userStatusDescription": status_details, "requesterId": requester_id}

    # Do this only if user is enrolled, ONHOLD till further discussion
    # response_data["requesterId"] = requester_id

    dbhelper.logger("Audit", "URS", "Inbound", user_uuid, "get_user_identity_status", json.dumps(response_data), "200")
    return web.json_response(response_data, status=200)


my_web_app = web.Application()
my_web_app.add_routes(routes)

my_web_app.add_routes(
    [web.get('/', home),
     web.get('/setupSchema', setup_schema),
     web.post('/webhook', endpoint_handler),
     web.get('/getDWUserIdentityStatus', get_user_identity_status),
     web.get('/getDWIdentityQrCode', get_identity_qr_code)]
)

aiohttp_jinja2.setup(
    my_web_app, loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates"))
)

#if __name__ == '__main__':
#    web.run_app(my_web_app, port=4000)
