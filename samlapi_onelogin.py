#!/usr/bin/env python

import sys
import os
import boto3
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse

from onelogin.api.client import OneLoginClient

##########################################################################
# Variables
ConfigParser.DEFAULTSECT = 'default'
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'settings.ini'))

# The default AWS region to be used
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


# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)
##########################################################################

# Get the credentials from the user
if not email:
    print "Email: ",
    email = raw_input()
else:
    print "Using: %s" % email
password = getpass.getpass()
print "OTP Code (MFA): ",
otp_code = raw_input()
print ''

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
    print "Please choose the role you would like to assume:"
    for awsrole in awsroles:
        account_id=awsrole.split(',')[0].split('/')[0].split(':role')[0].split('arn:aws:iam::')[1]
        print ' [{}]:\t{}\t{}'.format(i, account_dict.get(account_id), awsrole.split(',')[0])
        i += 1
    print "Selection: ",
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print 'You selected an invalid role index, please try again'
        sys.exit(0)

    role = awsroles[int(selectedroleindex)].split(',')
else:
    role = awsroles[0].split(',')
role_arn = role[0]
principal_arn = role[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
stsclient = boto3.client('sts')
token = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml, DurationSeconds=durationseconds)
creds = token['Credentials']
aws_key = creds['AccessKeyId']
aws_sec = creds['SecretAccessKey']
aws_tok = creds['SessionToken']
aws_exp = creds['Expiration']

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)

config.set('default', 'output', outputformat)
config.set('default', 'region', region)
config.set('default', 'aws_access_key_id', aws_key)
config.set('default', 'aws_secret_access_key', aws_sec)
config.set('default', 'aws_session_token', aws_tok)

# boto is special, see https://github.com/boto/boto/issues/2988
config.set('default', 'aws_security_token', aws_tok)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print '\n\n-------------------------------------------------------------------'
print 'Your new access key pair has been stored in the AWS configuration file:'
print '    {0} (under the saml profile).'.format(filename)
print 'Note that it will expire at {0}.'.format(aws_exp)
print 'To use this credential, call the AWS CLI with the --profile option'
print '    (e.g. aws ec2 describe-instances).'
print '-------------------------------------------------------------------\n\n'
