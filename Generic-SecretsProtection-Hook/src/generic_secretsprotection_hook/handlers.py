import logging
from typing import Any, MutableMapping, Optional

from cloudformation_cli_python_lib import (
    BaseHookHandlerRequest,
    HandlerErrorCode,
    Hook,
    HookInvocationPoint,
    OperationStatus,
    ProgressEvent,
    SessionProxy,
    exceptions,
)

from .models import HookHandlerRequest, TypeConfigurationModel

import toml
import re

# Use this logger to forward log messages to CloudWatch Logs.
LOG = logging.getLogger(__name__)
TYPE_NAME = "Generic::SecretsProtection::Hook"

hook = Hook(TYPE_NAME, TypeConfigurationModel)
test_entrypoint = hook.test_entrypoint


def _find_violations(propname, prop, violations, config):
    if isinstance(prop, dict):
        for k in prop:
            violations = _find_violations(propname + ".__{}_KEY".format(str(k)), str(k), violations, config)
            violations = _find_violations(propname + ".{}".format(str(k)), prop.get(k), violations, config)
        pass
    elif isinstance(prop, list) and not isinstance(prop, str):
        i = 0
        for item in prop:
            violations = _find_violations(propname + "[{}]".format(str(i)), item, violations, config)
            i+=1
    else:
        teststr = str(prop)

        if 'rules' in config:
            for rule in config['rules']:
                rulename = "Unknown"
                if 'description' in rule:
                    rulename = rule['description']
                elif 'id' in rule:
                    rulename = rule['id']
                if 'regex' in rule:
                    if re.match(rule['regex'], teststr):
                         violations.append("{} secret detected ({})".format(rulename, propname))

    return violations


def _validate_properties(progress, target_name, target_type, resource_properties, type_configuration, session):
    progress.status = OperationStatus.SUCCESS
    progress.message = f"Successfully invoked secrets protection and found no violations"

    config_str = "\"gitleaks config\"\r\n\r\n# Gitleaks rules are defined by regular expressions and entropy ranges.\r\n# Some secrets have unique signatures which make detecting those secrets easy.\r\n# Examples of those secrets would be Gitlab Personal Access Tokens, AWS keys, and Github Access Tokens.\r\n# All these examples have defined prefixes like `glpat`, `AKIA`, `ghp_`, etc.\r\n#\r\n# Other secrets might just be a hash which means we need to write more complex rules to verify\r\n# that what we are matching is a secret.\r\n#\r\n# Here is an example of a semi-generic secret\r\n#\r\n#   discord_client_secret = \"8dyfuiRyq=vVc3RRr_edRk-fK__JItpZ\"\r\n#\r\n# We can write a regular expression to capture the variable name (identifier),\r\n# the assignment symbol (like '=' or ':='), and finally the actual secret.\r\n# The structure of a rule to match this example secret is below:\r\n#\r\n#                                                           Beginning string\r\n#                                                               quotation\r\n#                                                                   \u2502            End string quotation\r\n#                                                                   \u2502                      \u2502\r\n#                                                                   \u25BC                      \u25BC\r\n#    (?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9=_\\-]{32})['\\\"]\r\n#\r\n#                   \u25B2                              \u25B2                                \u25B2\r\n#                   \u2502                              \u2502                                \u2502\r\n#                   \u2502                              \u2502                                \u2502\r\n#              identifier                  assignment symbol\r\n#                                                                                Secret\r\n#\r\n[[rules]]\r\nid = \"gitlab-pat\"\r\ndescription = \"GitLab Personal Access Token\"\r\nregex = '''glpat-[0-9a-zA-Z\\-]{20}'''\r\n\r\n[[rules]]\r\nid = \"aws-access-token\"\r\ndescription = \"AWS\"\r\nregex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''\r\n\r\n# Cryptographic keys\r\n[[rules]]\r\nid = \"PKCS8-PK\"\r\ndescription = \"PKCS8 private key\"\r\nregex = '''-----BEGIN PRIVATE KEY-----'''\r\n\r\n[[rules]]\r\nid = \"RSA-PK\"\r\ndescription = \"RSA private key\"\r\nregex = '''-----BEGIN RSA PRIVATE KEY-----'''\r\n\r\n[[rules]]\r\nid = \"OPENSSH-PK\"\r\ndescription = \"SSH private key\"\r\nregex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''\r\n\r\n[[rules]]\r\nid = \"PGP-PK\"\r\ndescription = \"PGP private key\"\r\nregex = '''-----BEGIN PGP PRIVATE KEY BLOCK-----'''\r\n\r\n[[rules]]\r\nid = \"github-pat\"\r\ndescription = \"Github Personal Access Token\"\r\nregex = '''ghp_[0-9a-zA-Z]{36}'''\r\n\r\n[[rules]]\r\nid = \"github-oauth\"\r\ndescription = \"Github OAuth Access Token\"\r\nregex = '''gho_[0-9a-zA-Z]{36}'''\r\n\r\n[[rules]]\r\nid = \"SSH-DSA-PK\"\r\ndescription = \"SSH (DSA) private key\"\r\nregex = '''-----BEGIN DSA PRIVATE KEY-----'''\r\n\r\n[[rules]]\r\nid = \"SSH-EC-PK\"\r\ndescription = \"SSH (EC) private key\"\r\nregex = '''-----BEGIN EC PRIVATE KEY-----'''\r\n\r\n\r\n[[rules]]\r\nid = \"github-app-token\"\r\ndescription = \"Github App Token\"\r\nregex = '''(ghu|ghs)_[0-9a-zA-Z]{36}'''\r\n\r\n[[rules]]\r\nid = \"github-refresh-token\"\r\ndescription = \"Github Refresh Token\"\r\nregex = '''ghr_[0-9a-zA-Z]{76}'''\r\n\r\n[[rules]]\r\nid = \"shopify-shared-secret\"\r\ndescription = \"Shopify shared secret\"\r\nregex = '''shpss_[a-fA-F0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"shopify-access-token\"\r\ndescription = \"Shopify access token\"\r\nregex = '''shpat_[a-fA-F0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"shopify-custom-access-token\"\r\ndescription = \"Shopify custom app access token\"\r\nregex = '''shpca_[a-fA-F0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"shopify-private-app-access-token\"\r\ndescription = \"Shopify private app access token\"\r\nregex = '''shppa_[a-fA-F0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"slack-access-token\"\r\ndescription = \"Slack token\"\r\nregex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''\r\n\r\n[[rules]]\r\nid = \"stripe-access-token\"\r\ndescription = \"Stripe\"\r\nregex = '''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}'''\r\n\r\n[[rules]]\r\nid = \"pypi-upload-token\"\r\ndescription = \"PyPI upload token\"\r\nregex = '''pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}'''\r\n\r\n[[rules]]\r\nid = \"gcp-service-account\"\r\ndescription = \"Google (GCP) Service-account\"\r\nregex = '''\\\"type\\\": \\\"service_account\\\"'''\r\n\r\n[[rules]]\r\nid = \"heroku-api-key\"\r\ndescription = \"Heroku API Key\"\r\nregex = ''' (?i)(heroku[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"slack-web-hook\"\r\ndescription = \"Slack Webhook\"\r\nregex = '''https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}'''\r\n\r\n[[rules]]\r\nid = \"twilio-api-key\"\r\ndescription = \"Twilio API Key\"\r\nregex = '''SK[0-9a-fA-F]{32}'''\r\n\r\n[[rules]]\r\nid = \"age-secret-key\"\r\ndescription = \"Age secret key\"\r\nregex = '''AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}'''\r\n\r\n[[rules]]\r\nid = \"facebook-token\"\r\ndescription = \"Facebook token\"\r\nregex = '''(?i)(facebook[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"twitter-token\"\r\ndescription = \"Twitter token\"\r\nregex = '''(?i)(twitter[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{35,44})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"adobe-client-id\"\r\ndescription = \"Adobe Client ID (Oauth Web)\"\r\nregex = '''(?i)(adobe[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"adobe-client-secret\"\r\ndescription = \"Adobe Client Secret\"\r\nregex = '''(p8e-)(?i)[a-z0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"alibaba-access-key-id\"\r\ndescription = \"Alibaba AccessKey ID\"\r\nregex = '''(LTAI)(?i)[a-z0-9]{20}'''\r\n\r\n[[rules]]\r\nid = \"alibaba-secret-key\"\r\ndescription = \"Alibaba Secret Key\"\r\nregex = '''(?i)(alibaba[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{30})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"asana-client-id\"\r\ndescription = \"Asana Client ID\"\r\nregex = '''(?i)(asana[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9]{16})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"asana-client-secret\"\r\ndescription = \"Asana Client Secret\"\r\nregex = '''(?i)(asana[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"atlassian-api-token\"\r\ndescription = \"Atlassian API token\"\r\nregex = '''(?i)(atlassian[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{24})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"bitbucket-client-id\"\r\ndescription = \"Bitbucket client ID\"\r\nregex = '''(?i)(bitbucket[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"bitbucket-client-secret\"\r\ndescription = \"Bitbucket client secret\"\r\nregex = '''(?i)(bitbucket[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9_\\-]{64})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"beamer-api-token\"\r\ndescription = \"Beamer API token\"\r\nregex = '''(?i)(beamer[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](b_[a-z0-9=_\\-]{44})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"clojars-api-token\"\r\ndescription = \"Clojars API token\"\r\nregex = '''(CLOJARS_)(?i)[a-z0-9]{60}'''\r\n\r\n[[rules]]\r\nid = \"contentful-delivery-api-token\"\r\ndescription = \"Contentful delivery API token\"\r\nregex = '''(?i)(contentful[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9\\-=_]{43})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"contentful-preview-api-token\"\r\ndescription = \"Contentful preview API token\"\r\nregex = '''(?i)(contentful[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9\\-=_]{43})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"databricks-api-token\"\r\ndescription = \"Databricks API token\"\r\nregex = '''dapi[a-h0-9]{32}'''\r\n\r\n[[rules]]\r\nid = \"discord-api-token\"\r\ndescription = \"Discord API key\"\r\nregex = '''(?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{64})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"discord-client-id\"\r\ndescription = \"Discord client ID\"\r\nregex = '''(?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9]{18})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"discord-client-secret\"\r\ndescription = \"Discord client secret\"\r\nregex = '''(?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9=_\\-]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"doppler-api-token\"\r\ndescription = \"Doppler API token\"\r\nregex = '''['\\\"](dp\\.pt\\.)(?i)[a-z0-9]{43}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"dropbox-api-secret\"\r\ndescription = \"Dropbox API secret\/key\"\r\nregex = '''(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{15})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"dropbox--api-key\"\r\ndescription = \"Dropbox API secret\/key\"\r\nregex = '''(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{15})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"dropbox-short-lived-api-token\"\r\ndescription = \"Dropbox short lived API token\"\r\nregex = '''(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](sl\\.[a-z0-9\\-=_]{135})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"dropbox-long-lived-api-token\"\r\ndescription = \"Dropbox long lived API token\"\r\nregex = '''(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"duffel-api-token\"\r\ndescription = \"Duffel API token\"\r\nregex = '''['\\\"]duffel_(test|live)_(?i)[a-z0-9_-]{43}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"dynatrace-api-token\"\r\ndescription = \"Dynatrace API token\"\r\nregex = '''['\\\"]dt0c01\\.(?i)[a-z0-9]{24}\\.[a-z0-9]{64}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"easypost-api-token\"\r\ndescription = \"EasyPost API token\"\r\nregex = '''['\\\"]EZAK(?i)[a-z0-9]{54}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"easypost-test-api-token\"\r\ndescription = \"EasyPost test API token\"\r\nregex = '''['\\\"]EZTK(?i)[a-z0-9]{54}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"fastly-api-token\"\r\ndescription = \"Fastly API token\"\r\nregex = '''(?i)(fastly[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9\\-=_]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"finicity-client-secret\"\r\ndescription = \"Finicity client secret\"\r\nregex = '''(?i)(finicity[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{20})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"finicity-api-token\"\r\ndescription = \"Finicity API token\"\r\nregex = '''(?i)(finicity[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"flutterweave-public-key\"\r\ndescription = \"Flutterweave public key\"\r\nregex = '''FLWPUBK_TEST-(?i)[a-h0-9]{32}-X'''\r\n\r\n[[rules]]\r\nid = \"flutterweave-secret-key\"\r\ndescription = \"Flutterweave secret key\"\r\nregex = '''FLWSECK_TEST-(?i)[a-h0-9]{32}-X'''\r\n\r\n[[rules]]\r\nid = \"flutterweave-enc-key\"\r\ndescription = \"Flutterweave encrypted key\"\r\nregex = '''FLWSECK_TEST[a-h0-9]{12}'''\r\n\r\n[[rules]]\r\nid = \"frameio-api-token\"\r\ndescription = \"Frame.io API token\"\r\nregex = '''fio-u-(?i)[a-z0-9-_=]{64}'''\r\n\r\n[[rules]]\r\nid = \"gocardless-api-token\"\r\ndescription = \"GoCardless API token\"\r\nregex = '''['\\\"]live_(?i)[a-z0-9-_=]{40}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"grafana-api-token\"\r\ndescription = \"Grafana API token\"\r\nregex = '''['\\\"]eyJrIjoi(?i)[a-z0-9-_=]{72,92}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"hashicorp-tf-api-token\"\r\ndescription = \"Hashicorp Terraform user\/org API token\"\r\nregex = '''['\\\"](?i)[a-z0-9]{14}\\.atlasv1\\.[a-z0-9-_=]{60,70}['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"hubspot-api-token\"\r\ndescription = \"Hubspot API token\"\r\nregex = '''(?i)(hubspot[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"intercom-api-token\"\r\ndescription = \"Intercom API token\"\r\nregex = '''(?i)(intercom[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9=_]{60})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"intercom-client-secret\"\r\ndescription = \"Intercom client secret\/ID\"\r\nregex = '''(?i)(intercom[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"ionic-api-token\"\r\ndescription = \"Ionic API token\"\r\nregex = '''(?i)(ionic[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](ion_[a-z0-9]{42})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"linear-api-token\"\r\ndescription = \"Linear API token\"\r\nregex = '''lin_api_(?i)[a-z0-9]{40}'''\r\n\r\n[[rules]]\r\nid = \"linear-client-secret\"\r\ndescription = \"Linear client secret\/ID\"\r\nregex = '''(?i)(linear[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"lob-api-key\"\r\ndescription = \"Lob API Key\"\r\nregex = '''(?i)(lob[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]((live|test)_[a-f0-9]{35})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"lob-pub-api-key\"\r\ndescription = \"Lob Publishable API Key\"\r\nregex = '''(?i)(lob[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]((test|live)_pub_[a-f0-9]{31})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"mailchimp-api-key\"\r\ndescription = \"Mailchimp API key\"\r\nregex = '''(?i)(mailchimp[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-f0-9]{32}-us20)['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"mailgun-private-api-token\"\r\ndescription = \"Mailgun private API token\"\r\nregex = '''(?i)(mailgun[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](key-[a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"mailgun-pub-key\"\r\ndescription = \"Mailgun public validation key\"\r\nregex = '''(?i)(mailgun[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](pubkey-[a-f0-9]{32})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"mailgun-signing-key\"\r\ndescription = \"Mailgun webhook signing key\"\r\nregex = '''(?i)(mailgun[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"mapbox-api-token\"\r\ndescription = \"Mapbox API token\"\r\nregex = '''(?i)(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})'''\r\n\r\n[[rules]]\r\nid = \"messagebird-api-token\"\r\ndescription = \"MessageBird API token\"\r\nregex = '''(?i)(messagebird[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{25})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"messagebird-client-id\"\r\ndescription = \"MessageBird API client ID\"\r\nregex = '''(?i)(messagebird[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"new-relic-user-api-key\"\r\ndescription = \"New Relic user API Key\"\r\nregex = '''['\\\"](NRAK-[A-Z0-9]{27})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"new-relic-user-api-id\"\r\ndescription = \"New Relic user API ID\"\r\nregex = '''(?i)(newrelic[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([A-Z0-9]{64})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"new-relic-browser-api-token\"\r\ndescription = \"New Relic ingest browser API token\"\r\nregex = '''['\\\"](NRJS-[a-f0-9]{19})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"npm-access-token\"\r\ndescription = \"npm access token\"\r\nregex = '''['\\\"](npm_(?i)[a-z0-9]{36})['\\\"]'''\r\n\r\n[[rules]]\r\nid = \"planetscale-password\"\r\ndescription = \"Planetscale password\"\r\nregex = '''pscale_pw_(?i)[a-z0-9\\-_\\.]{43}'''\r\n\r\n[[rules]]\r\nid = \"planetscale-api-token\"\r\ndescription = \"Planetscale API token\"\r\nregex = '''pscale_tkn_(?i)[a-z0-9\\-_\\.]{43}'''\r\n\r\n[[rules]]\r\nid = \"postman-api-token\"\r\ndescription = \"Postman API token\"\r\nregex = '''PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34}'''\r\n\r\n[[rules]]\r\nid = \"pulumi-api-token\"\r\ndescription = \"Pulumi API token\"\r\nregex = '''pul-[a-f0-9]{40}'''\r\n\r\n[[rules]]\r\nid = \"rubygems-api-token\"\r\ndescription = \"Rubygem API token\"\r\nregex = '''rubygems_[a-f0-9]{48}'''\r\n\r\n[[rules]]\r\nid = \"sendgrid-api-token\"\r\ndescription = \"Sendgrid API token\"\r\nregex = '''SG\\.(?i)[a-z0-9_\\-\\.]{66}'''\r\n\r\n[[rules]]\r\nid = \"sendinblue-api-token\"\r\ndescription = \"Sendinblue API token\"\r\nregex = '''xkeysib-[a-f0-9]{64}\\-(?i)[a-z0-9]{16}'''\r\n\r\n[[rules]]\r\nid = \"shippo-api-token\"\r\ndescription = \"Shippo API token\"\r\nregex = '''shippo_(live|test)_[a-f0-9]{40}'''\r\n\r\n[[rules]]\r\nid = \"linedin-client-secret\"\r\ndescription = \"Linkedin Client secret\"\r\nregex = '''(?i)(linkedin[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z]{16})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"linedin-client-id\"\r\ndescription = \"Linkedin Client ID\"\r\nregex = '''(?i)(linkedin[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{14})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"twitch-api-token\"\r\ndescription = \"Twitch API token\"\r\nregex = '''(?i)(twitch[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{30})['\\\"]'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"typeform-api-token\"\r\ndescription = \"Typeform API token\"\r\nregex = '''(?i)(typeform[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}(tfp_[a-z0-9\\-_\\.=]{59})'''\r\nsecretGroup = 3\r\n\r\n[[rules]]\r\nid = \"generic-api-key\"\r\ndescription = \"Generic API Key\"\r\nregex = '''(?i)((key|api|token|secret|password)[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9a-zA-Z\\-_=]{8,64})['\\\"]'''\r\nentropy = 3.7\r\nsecretGroup = 4\r\n\r\n\r\n[allowlist]\r\ndescription = \"global allow lists\"\r\nregexes = ['''219-09-9999''', '''078-05-1120''', '''(9[0-9]{2}|666)-\\d{2}-\\d{4}''']\r\npaths = [\r\n    '''gitleaks.toml''',\r\n    '''(.*?)(jpg|gif|doc|pdf|bin|svg|socket)$'''\r\n]"
    if type_configuration and type_configuration.Configuration and type_configuration.Configuration is not None and type_configuration.Configuration != "":
        config_str = type_configuration.Configuration
    config = toml.loads(config_str)

    try:
        if resource_properties:
            violations = []
            for k in resource_properties:
                violations = _find_violations("{}.{}".format(target_type, k), resource_properties.get(k), violations, config)

            if len(violations) > 0:
                progress.status = OperationStatus.FAILED
                progress.message = f"Secrets found in resource: {', '.join(violations)}"
                progress.errorCode = HandlerErrorCode.NonCompliant
                LOG.warn(f"{target_name} - {progress.message}")
            
    except Exception as e:
        progress.status = OperationStatus.FAILED
        progress.message = f"{e}"
        progress.errorCode = HandlerErrorCode.InternalFailure

    return progress


@hook.handler(HookInvocationPoint.CREATE_PRE_PROVISION)
def pre_create_handler(
        session: Optional[SessionProxy],
        request: HookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    
    return _validate_properties(progress, request.hookContext.targetName, request.hookContext.targetType, request.hookContext.targetModel.get("resourceProperties"), type_configuration, session)


@hook.handler(HookInvocationPoint.UPDATE_PRE_PROVISION)
def pre_update_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    
    return _validate_properties(progress, request.hookContext.targetName, request.hookContext.targetType, request.hookContext.targetModel.get("resourceProperties"), type_configuration, session)


@hook.handler(HookInvocationPoint.DELETE_PRE_PROVISION)
def pre_delete_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS
    )
