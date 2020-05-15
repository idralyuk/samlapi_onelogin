#!/usr/bin/env python3

import sys
import os
import pathlib
import botocore
import boto3
import requests
import getpass
from configparser import ConfigParser
from configparser import RawConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

from onelogin.api.client import OneLoginClient

##########################################################################
# Variables
ConfigParser.samlSECT = 'saml'
Config = ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'settings.ini'))

# The saml AWS region to be used
region = Config.get('Settings', 'region')

# OneLogin Client ID
onelogin_client_id = Config.get('Settings', 'onelogin_client_id')

# OneLogin Client Secret
onelogin_client_secret = Config.get('Settings', 'onelogin_client_secret')

# OneLogin Region
onelogin_region = Config.get('Settings', 'onelogin_region')

# onelogin subdomain
onelogin_subdomain = Config.get('Settings', 'onelogin_subdomain')

# app id
app_id = Config.get('Settings', 'onelogin_appid')

# The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = Config.get('Settings', 'outputformat')

# The file where this script will store the STS credentials
awsconfigfile = Config.get('Settings', 'awsconfigfile')

# If only using locally/for yourself, you can hardcode your login email
email = Config.get('Settings', 'Email') if Config.has_option('Settings', 'Email') else None

# Account Name and ID details loaded from setting file
account_dict = {}
account_details= Config.get('Settings', 'AccountNameId').split(",")
for account_detail in account_details:
 account_dict[account_detail.split("::")[1]] = account_detail.split("::")[0]

# The duration, in seconds, of the role session
durationseconds = int(Config.get('Settings', 'DurationSeconds')) if Config.has_option('Settings', 'DurationSeconds') and Config.get('Settings', 'DurationSeconds').isdigit() else 3600

# False should only be used for dev/test
sslverification = True

# Account Name and ID details loaded from setting file
accountDict = {}
accountDetails= Config.get('Settings', 'AccountNameId').split(",")
for accountDetail in accountDetails:
 accountDict[accountDetail.split("::")[1]] = accountDetail.split("::")[0]

def get_account_name(role):
    account_id = role[0].split('/')[0].split(':role')[0].split('arn:aws:iam::')[1]
    account_user = role[0].split('/')[1].lower()
    return '{}-{}'.format(accountDict.get(account_id), account_user)


# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)
##########################################################################

# Get the credentials from the user
if not email:
    email = input("Email: ")
else:
    print("Using: %s" % email)
password = getpass.getpass()
otp_code = input("OTP Code (MFA): ")
print('')

client = OneLoginClient(onelogin_client_id, onelogin_client_secret, onelogin_region)

onelogin_response = client.get_saml_assertion(email, password, app_id, onelogin_subdomain)

saml = None

if onelogin_response is None:
    print('Failed logging in (password was incorrect)')
    exit(1)
elif onelogin_response and onelogin_response.type == "success":
    state_token = onelogin_response.mfa.state_token
    device_id = onelogin_response.mfa.devices[0].id
    mfa_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, otp_code, do_not_notify=True)

    if mfa_response is None:
        print('Failed logging in (OTP code)')
        exit(1)
    
    saml = mfa_response.saml_response
else:
    saml = onelogin_response.saml_response


print('Login successful')

# Overwrite and delete the credential variables, just for safety
username = '#################################################'
password = '#################################################'
otp_code = '#################################################'
del username
del password
del otp_code

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(saml))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text.split(','))

# Note the format of the attribute value should be role_arn,principal_arn, but
# lots of blogs list it as principal_arn,role_arn so let's reverse if needed
for awsrole in awsroles:
    if'saml-provider' in awsrole[0]:
        newawsrole = awsrole[1] + ',' + awsrole[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole.split(','))
        awsroles.remove(awsrole)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = RawConfigParser()
config.read(filename)

stsclient = boto3.client('sts')
for awsrole in awsroles:
    try:
        role_arn = awsrole[0]
        principal_arn = awsrole[1]
        token = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml, DurationSeconds=durationseconds)
        creds = token['Credentials']
        aws_key = creds['AccessKeyId']
        aws_sec = creds['SecretAccessKey']
        aws_tok = creds['SessionToken']
        aws_exp = creds['Expiration']

        config[get_account_name(awsrole)] = {
            'output': outputformat,
            'region': region,
            'aws_access_key_id': aws_key,
            'aws_secret_access_key': aws_sec,
            'aws_session_token': aws_tok,
            'aws_security_token': aws_tok
        }
    except botocore.exceptions.ClientError as e:
        pass


# If there's more than one role, ask the user to pick one; otherwise proceed
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to be default:")
    for awsrole in awsroles:
        account_id=awsrole[0].split('/')[0].split(':role')[0].split('arn:aws:iam::')[1]
        print(' [{}]:\t{}\t{}'.format(i, account_dict.get(account_id), awsrole[0]))
        i += 1
    selectedroleindex = int(input("Selection: "))

    # Basic sanity check of input
    if selectedroleindex > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(1)

    selected_account = get_account_name(awsroles[selectedroleindex])
else:
    selected_account = get_account_name(awsroles[0])

config['saml'] = config[selected_account]
config['default'] = config[selected_account]

# Write the updated config file
pathlib.Path(os.path.dirname(filename)).mkdir(parents=True, exist_ok=True)
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n\n-------------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file:')
print('    {0} (under the saml profile).'.format(filename))
print('Note that it will expire at {0}.'.format(aws_exp))
print('To use this credential, call the AWS CLI:')
print('    (e.g. aws ec2 describe-instances).')
print('Additional profiles were also written for all the above accounts to a profile by their name:')
print('    (e.g. aws ec2 --profile wiser-prod describe-instances).')
print('-------------------------------------------------------------------\n\n')
