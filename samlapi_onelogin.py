#!/usr/bin/env python3

import sys
import os
import boto3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

##########################################################################
# Variables
Config = configparser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'settings.ini'))

# The default AWS region to be used
region = Config.get('Settings', 'region')

# The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = Config.get('Settings', 'outputformat')

# The file where this script will store the STS credentials
awsconfigfile = Config.get('Settings', 'awsconfigfile')

# The initial url that starts the authentication process
idpentryurl = Config.get('Settings', 'URL')

# If only using locally/for yourself, you can hardcode your login email
if Config.has_option('Settings', 'Email'):
    email = Config.get('Settings', 'Email')
else:
    email = None

# False should only be used for dev/test
sslverification = True

# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)
##########################################################################

# Get the credentials from the user
if not email:
    print("Email: "),
    email = raw_input()
else:
    print("Using: {0}".format(email))
password = getpass.getpass()
print("OTP Code (MFA): "),
otp_code = input()
print('')

# Initiate session handler
session = requests.Session()
# Configure Session Headers
session.headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:52.0) Gecko/20100101 AWS Login/1.0"

# Initial Page load
onelogin_session = session.get(idpentryurl)
onelogin_session.raise_for_status()
session.headers['Referer'] = onelogin_session.url

# Collect information from the page source
decoded = BeautifulSoup(onelogin_session.text, 'html.parser')
auth_token = decoded.find('input', {'id': 'auth_token'}).get('value')
action = decoded.find('form', {'id': 'login-form'}).get('action')

# Setup the payload
payload = {
    'authenticity_token': auth_token,
    'email': email,
    'password': password,
    'otp_token_1': otp_code,
    'commit': 'Log in',
}

parsedurl = urlparse(idpentryurl)
login_url = parsedurl.scheme + "://" + parsedurl.netloc + action

# POST to login page
onelogin_session.headers['Referrer'] = onelogin_session.url
onelogin_session = session.post(login_url, data=payload)
onelogin_session.raise_for_status()

# Submit again with OTP, but only if OTP was provided
if otp_code:
    onelogin_session = session.post(login_url, data=payload)
    onelogin_session.raise_for_status()

# Debug the response if needed
# print (onelogin_session.text)

parsed = BeautifulSoup(onelogin_session.text, 'html.parser')
saml_element = parsed.find('input', {'name':'SAMLResponse'})

if not saml_element:
    raise StandardError('Could not get a SAML reponse, check credentials.')

saml = saml_element['value']

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
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn, but
# lots of blogs list it as principal_arn,role_arn so let's reverse if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If there's more than one role, ask the user to pick one; otherwise proceed
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print(' [', i, ']: ', awsrole.split(',')[0])
        i += 1
    print("Selection: "),
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
stsclient = boto3.client('sts')
token = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml)
creds = token['Credentials']
aws_key = creds['AccessKeyId']
aws_sec = creds['SecretAccessKey']
aws_tok = creds['SessionToken']
aws_exp = creds['Expiration']

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the creds into a saml-specific profile instead of clobbering other creds
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', aws_key)
config.set('saml', 'aws_secret_access_key', aws_sec)
config.set('saml', 'aws_session_token', aws_tok)

# boto is special, see https://github.com/boto/boto/issues/2988
config.set('saml', 'aws_security_token', aws_tok)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n\n-------------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file:')
print('    {0} (under the saml profile).'.format(filename))
print('Note that it will expire at {0}.'.format(aws_exp))
print('To use this credential, call the AWS CLI with the --profile option')
print('    (e.g. aws --profile saml ec2 describe-instances).')
print('-------------------------------------------------------------------\n\n')
