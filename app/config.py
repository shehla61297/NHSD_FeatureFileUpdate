import os
import enum
from configparser import ConfigParser


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


class USERSTATUS(enum.Enum):
    UNE = 0
    UHE = 1
    UHA = 2


class Config:
    DEBUG = False
    INSTITUTION_NAME: str = 'NHS Digital_CIS'
    LOGO_URL: str = 'https://www.england.nhs.uk/nhsidentity/wp-content/themes/nhsengland-identity/templates/assets/img/favicon.png'
    WALLET_NAME: str = 'NHSD User Identity Credentials'
    WALLET_KEY: str = 'NHSD User Identity Credentials'
    CRED_DEF_ID = "4d9FRKDn96bsXcwRuMpMWD:3:CL:198685:LATEST022020V1" # for QA Server: Kf6dx6qPRqSGCh9QDQNKLM:3:CL:187801:LATEST022020V1
    SCHEMA_ID = "4d9FRKDn96bsXcwRuMpMWD:2:NHSD User Identity Credentials Schema:971.85.937"
    SCHEMA_VERSION = 'V1.0'
    TOKEN ='{"sponseeId": "Mastek", "sponsorId": "evernym-demo-sponsor", "nonce": "iSG6i5JJ65K2EWWujKLd4QbaW5ylqcUu", "timestamp": "2021-01-29T12:01:06.846458", "sig": "5NLbJWeud8HHk7FuQ/sjN2wntCEbSlz5OgZylMDimmOOZhRk5Gecx3ZigcdrtUpLXV0bV08XiuybjIGmx7R5Aw==", "sponsorVerKey": "BCHo16QAdnZtPxaEjGBPQEiohxF62LR3qVwce298g7Jf"}'
    SCHEMA_ATTRIBUTES = ['NHSD_CIS Title', 'NHSD_CIS First Name', 'NHSD_CIS Surname', 'NHSD_CIS Preferred Name', 'NHSD_CIS Date of Birth',
                         'NHSD_CIS National Insurance Number', 'NHSD_CIS Identity Assurance Level',
                         'NHSD_CIS UUID', 'NHSD_CIS User Photograph_link']
    SCHEMA_NAME = 'NHSD User Identity Credentials Schema'
    VERITY_URL = "http://vas.pps.evernym.com/"
    CRED_DEFINITION_NAME = 'NHSD CIS Credential'
    CRED_DEF_TAG = "LATEST022020V1"
    WEBHOOK_URL = "https://dwissuer.devbox.cis.spine2.ncrs.nhs.uk/webhook"

    APPLICATION_ID = b"DigitalWallet965" #"RGlnaXRhbFdhbGxldDk2NQ=="
    ISSUER_DID = "4d9FRKDn96bsXcwRuMpMWD"
    URS_ENDPOINT_URL = "https://digitalwallet.devbox.cis.spine2.ncrs.nhs.uk/urswebapp/issueDigitalWalletCredentials"

class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    DEBUG = True
    TESTING = True


class ProductionConfig(Config):
    DEBUG = False


config_by_name = dict(
    dev=DevelopmentConfig,
    test=TestingConfig,
    prod=ProductionConfig
)