import aiohttp
import json
import os
from dbhelper import logger
import asyncio
import logging
import config
log = logging.getLogger()


async def get_user_detail(uuid, requester_user_id):
    logger(
        "Audit", "URS", "Outbound", int(uuid), "get_user_detail",
        "Getting detail from URS for user: {}".format(uuid), "NA"
    )
    urs_response = ""
    if config.Config.URS_ENDPOINT_URL == "":
        filename = "./" + str(uuid) + ".json"
        if os.path.isfile(filename):
            urs_response = ""
            try:
                with open(filename, 'r') as f:
                    urs_response = json.loads(f.read())
            except Exception as e:
                log.error("Error: {} , Reading json of uuid".format(e))
                logger(
                    "Error", "DW", "Outbound", uuid, "get_user_detail",
                    "Reading json of uuid: {}".format(uuid) + "" + str(e) , "NA"
                )
    else:
        try:
            #print('In try')
            async with aiohttp.ClientSession() as session:
                payload = {"uuid": uuid, "requesterId": requester_user_id}
                header = {"applicationId": "RGlnaXRhbFdhbGxldDk2NQ=="}
                # Do post to URS with above payload
                #print('Calling Async')
                async with session.post(config.Config.URS_ENDPOINT_URL, json=payload,headers=header) as resp:
                    urs_response = await resp.json()

                    #print(urs_response)

        except Exception as e:
            logger(
                "Error", "DW", "Outbound", int(uuid), "get_user_detail", str(e), "500"
            )
    urs_response['base64Image'] = {"mime-type": "image/jpeg", "extension": "jpeg", "name": "man.jpeg",
                                   "data": {"base64": urs_response["base64Image"]}}
    #print('URS Response'+ urs_response)
    urs_response['base64Image'] = json.dumps(urs_response['base64Image'])
    # Map this with existing keys that we have in schema as of now
    mapped_data = {
        "NHSD_CIS Title": urs_response.get("title"),
        "NHSD_CIS First Name": urs_response.get("givenName"),
        "NHSD_CIS Surname": urs_response.get("familyName"),
        "NHSD_CIS Preferred Name": urs_response.get("preferredName"),
        "NHSD_CIS Date of Birth": urs_response.get("dateOfBirth"),
        "NHSD_CIS National Insurance Number": urs_response.get("nINumber"),
        "NHSD_CIS Identity Assurance Level": urs_response.get("eGifReg"),
        "NHSD_CIS UUID": urs_response.get("uuid"),
        "NHSD_CIS User Photograph_link": urs_response.get("base64Image")
    }
    logger(
        "Audit", "URS", "Inbound", int(uuid), "get_user_detail", "Success", "200"
    )
    return mapped_data

#loop = asyncio.get_event_loop()
#loop.run_until_complete(get_user_detail(240000328107,"010000001110"))
#loop.close()