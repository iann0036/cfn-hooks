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

import re

# Use this logger to forward log messages to CloudWatch Logs.
LOG = logging.getLogger(__name__)
TYPE_NAME = "Generic::SecretsProtection::Hook"

hook = Hook(TYPE_NAME, TypeConfigurationModel)
test_entrypoint = hook.test_entrypoint


def _find_violations(propname, prop, violations, rules, exceptions):
    if isinstance(prop, dict):
        for k in prop:
            violations = _find_violations("{}.__KEY".format(propname), str(k), violations, rules, exceptions)
            violations = _find_violations("{}.{}".format(propname, str(k)), prop.get(k), violations, rules, exceptions)
        pass
    elif isinstance(prop, list) and not isinstance(prop, str):
        for item in prop:
            violations = _find_violations(propname + "[]", item, violations, rules, exceptions)
    else:
        if propname in exceptions:
            return violations

        teststr = str(prop)
        
        for rule in rules:
            if re.match(rule.get('Regex'), teststr):
                violations.append("{} ({})".format(rule.get('Description'), propname))

    return violations


def _validate_properties(progress, target_name, target_type, resource_properties, type_configuration, session):
    progress.status = OperationStatus.SUCCESS
    progress.message = f"Successfully invoked secrets protection and found no violations"

    try:
        rules = [ # default ruleset
            {
                "Description": "GitLab Personal Access Token",
                "Regex": f"glpat-[0-9a-zA-Z\\-]{{20}}"
            },
            {
                "Description": "AWS Access Token",
                "Regex": f"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{{16}}"
            },
            {
                "Description": "PKCS8 private key",
                "Regex": f"-----BEGIN PRIVATE KEY-----"
            },
            {
                "Description": "RSA private key",
                "Regex": f"-----BEGIN RSA PRIVATE KEY-----"
            },
            {
                "Description": "SSH private key",
                "Regex": f"-----BEGIN OPENSSH PRIVATE KEY-----"
            },
            {
                "Description": "PGP private key",
                "Regex": f"-----BEGIN PGP PRIVATE KEY BLOCK-----"
            },
            {
                "Description": "GitHub Personal Access Token",
                "Regex": f"ghp_[0-9a-zA-Z]{{36}}"
            },
            {
                "Description": "GitHub OAuth Access Token",
                "Regex": f"gho_[0-9a-zA-Z]{{36}}"
            },
            {
                "Description": "SSH (DSA) private key",
                "Regex": f"-----BEGIN DSA PRIVATE KEY-----"
            },
            {
                "Description": "SSH (EC) private key",
                "Regex": f"-----BEGIN EC PRIVATE KEY-----"
            },
            {
                "Description": "GitHub App Token",
                "Regex": f"(ghu|ghs)_[0-9a-zA-Z]{{36}}"
            },
            {
                "Description": "GitHub Refresh Token",
                "Regex": f"ghr_[0-9a-zA-Z]{{76}}"
            },
            {
                "Description": "Shopify shared secret",
                "Regex": f"shpss_[a-fA-F0-9]{{32}}"
            },
            {
                "Description": "Shopify access token",
                "Regex": f"shpat_[a-fA-F0-9]{{32}}"
            },
            {
                "Description": "Shopify custom app access token",
                "Regex": f"shpca_[a-fA-F0-9]{{32}}"
            },
            {
                "Description": "Shopify private app access token",
                "Regex": f"shppa_[a-fA-F0-9]{{32}}"
            },
            {
                "Description": "Slack token",
                "Regex": f"xox[baprs]-([0-9a-zA-Z]{{10,48}})?"
            },
            {
                "Description": "Stripe",
                "Regex": f"(sk|pk)_(test|live)_[0-9a-zA-Z]{{10,32}}"
            },
            {
                "Description": "PyPI upload token",
                "Regex": f"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{{50,1000}}"
            },
            {
                "Description": "Google (GCP) Service account",
                "Regex": f"\"type\": \"service_account\""
            },
            {
                "Description": "Heroku API Key",
                "Regex": f"(heroku[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([0-9A-F]{{8}}-[0-9A-F]{{4}}-[0-9A-F]{{4}}-[0-9A-F]{{4}}-[0-9A-F]{{12}})['\\\"]"
            },
            {
                "Description": "Slack Webhook",
                "Regex": f"https://hooks.slack.com/services/T[a-zA-Z0-9_]{{8}}/B[a-zA-Z0-9_]{{8,12}}/[a-zA-Z0-9_]{{24}}"
            },
            {
                "Description": "Twilio API Key",
                "Regex": f"SK[0-9a-fA-F]{{32}}"
            },
            {
                "Description": "Age secret key",
                "Regex": f"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{{58}}"
            },
            {
                "Description": "Facebook token",
                "Regex": f"(facebook[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Twitter token",
                "Regex": f"(twitter[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{35,44}})['\\\"]"
            },
            {
                "Description": "Adobe Client ID (Oauth Web)",
                "Regex": f"(adobe[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Adobe Client Secret",
                "Regex": f"(p8e-)[a-zA-Z0-9]{{32}}"
            },
            {
                "Description": "Alibaba AccessKey ID",
                "Regex": f"(LTAI)[a-zA-Z0-9]{{20}}"
            },
            {
                "Description": "Alibaba Secret Key",
                "Regex": f"(alibaba[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{30}})['\\\"]"
            },
            {
                "Description": "Asana Client ID",
                "Regex": f"(asana[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([0-9]{{16}})['\\\"]"
            },
            {
                "Description": "Asana Client Secret",
                "Regex": f"(asana[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Atlassian API token",
                "Regex": f"(atlassian[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{24}})['\\\"]"
            },
            {
                "Description": "Bitbucket client ID",
                "Regex": f"(bitbucket[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Bitbucket client secret",
                "Regex": f"(bitbucket[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9_\\-]{{64}})['\\\"]"
            },
            {
                "Description": "Beamer API token",
                "Regex": f"(beamer[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([bB]_[a-z0-9=_\\-]{{44}})['\\\"]"
            },
            {
                "Description": "Clojars API token",
                "Regex": f"(CLOJARS_)[a-zA-Z0-9]{{60}}"
            },
            {
                "Description": "Contentful preview/delivery API token",
                "Regex": f"(contentful[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9\\-=_]{{43}})['\\\"]"
            },
            {
                "Description": "Databricks API token",
                "Regex": f"dapi[a-h0-9]{{32}}"
            },
            {
                "Description": "Discord API key",
                "Regex": f"(discord[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-h0-9]{{64}})['\\\"]"
            },
            {
                "Description": "Discord client ID",
                "Regex": f"(discord[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([0-9]{{18}})['\\\"]"
            },
            {
                "Description": "Discord client secret",
                "Regex": f"(discord[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9=_\\-]{{32}})['\\\"]"
            },
            {
                "Description": "Doppler API token",
                "Regex": f"['\\\"](dp\\.pt\\.)[a-zA-Z0-9]{{43}}['\\\"]"
            },
            {
                "Description": "Dropbox API secret/key",
                "Regex": f"(dropbox[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{15}})['\\\"]"
            },
            {
                "Description": "Dropbox short lived API token",
                "Regex": f"(dropbox[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"](sl\\.[a-z0-9\\-=_]{{135}})['\\\"]"
            },
            {
                "Description": "Dropbox long lived API token",
                "Regex": f"(dropbox[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"][a-z0-9]{{11}}(AAAAAAAAAA)[a-z0-9\\-_=]{{43}}['\\\"]"
            },
            {
                "Description": "Duffel API token",
                "Regex": f"['\\\"]duffel_(test|live)_[a-zA-Z0-9_-]{{43}}['\\\"]"
            },
            {
                "Description": "Dynatrace API token",
                "Regex": f"['\\\"]dt0c01\\.[a-zA-Z0-9]{{24}}\\.[a-zA-Z0-9]{{64}}['\\\"]"
            },
            {
                "Description": "EasyPost API token",
                "Regex": f"['\\\"]EZAK[a-zA-Z0-9]{{54}}['\\\"]"
            },
            {
                "Description": "EasyPost test API token",
                "Regex": f"['\\\"]EZTK[a-zA-Z0-9]{{54}}['\\\"]"
            },
            {
                "Description": "Fastly API token",
                "Regex": f"(fastly[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9\\-=_]{{32}})['\\\"]"
            },
            {
                "Description": "Finicity client secret",
                "Regex": f"(finicity[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{20}})['\\\"]"
            },
            {
                "Description": "Finicity API token",
                "Regex": f"(finicity[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Flutterwave public key",
                "Regex": f"FLWPUBK_TEST-(?i)[a-h0-9]{{32}}-X"
            },
            {
                "Description": "Flutterwave secret key",
                "Regex": f"FLWSECK_TEST-(?i)[a-h0-9]{{32}}-X"
            },
            {
                "Description": "Flutterwave encrypted key",
                "Regex": f"FLWSECK_TEST[a-h0-9]{{12}}"
            },
            {
                "Description": "Frame.io API token",
                "Regex": f"fio-u-(?i)[a-z0-9-_=]{{64}}"
            },
            {
                "Description": "GoCardless API token",
                "Regex": f"['\\\"]live_(?i)[a-z0-9-_=]{{40}}['\\\"]"
            },
            {
                "Description": "Grafana API token",
                "Regex": f"['\\\"]eyJrIjoi(?i)[a-z0-9-_=]{{72,92}}['\\\"]"
            },
            {
                "Description": "HashiCorp Terraform user/org API token",
                "Regex": f"['\\\"](?i)[a-z0-9]{{14}}\\.atlasv1\\.[a-z0-9-_=]{{60,70}}['\\\"]"
            },
            {
                "Description": "HubSpot API token",
                "Regex": f"(hubspot[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-h0-9]{{8}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{12}})['\\\"]"
            },
            {
                "Description": "Intercom API token",
                "Regex": f"(intercom[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9=_]{{60}})['\\\"]"
            },
            {
                "Description": "Intercom client secret/ID",
                "Regex": f"(intercom[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-h0-9]{{8}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{12}})['\\\"]"
            },
            {
                "Description": "Ionic API token",
                "Regex": f"(ionic[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"](ion_[a-z0-9]{{42}})['\\\"]"
            },
            {
                "Description": "Linear API token",
                "Regex": f"lin_api_(?i)[a-z0-9]{{40}}"
            },
            {
                "Description": "Linear client secret/ID",
                "Regex": f"(linear[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Lob API Key",
                "Regex": f"(lob[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]((live|test)_[a-f0-9]{{35}})['\\\"]"
            },
            {
                "Description": "Lob Publishable API Key",
                "Regex": f"(lob[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]((test|live)_pub_[a-f0-9]{{31}})['\\\"]"
            },
            {
                "Description": "Mailchimp API key",
                "Regex": f"(mailchimp[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-f0-9]{{32}}-us20)['\\\"]"
            },
            {
                "Description": "Mailgun private API token",
                "Regex": f"(mailgun[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"](key-[a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Mailgun public validation key",
                "Regex": f"(mailgun[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"](pubkey-[a-f0-9]{{32}})['\\\"]"
            },
            {
                "Description": "Mailgun webhook signing key",
                "Regex": f"(mailgun[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-h0-9]{{32}}-[a-h0-9]{{8}}-[a-h0-9]{{8}})['\\\"]"
            },
            {
                "Description": "Mapbox API token",
                "Regex": f"(pk\\.[a-zA-Z0-9]{{60}}\\.[a-zA-Z0-9]{{22}})"
            },
            {
                "Description": "MessageBird API token",
                "Regex": f"(messagebird[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{25}})['\\\"]"
            },
            {
                "Description": "MessageBird API client ID",
                "Regex": f"(messagebird[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-h0-9]{{8}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{4}}-[a-h0-9]{{12}})['\\\"]"
            },
            {
                "Description": "New Relic user API Key",
                "Regex": f"['\\\"](NRAK-[A-Z0-9]{{27}})['\\\"]"
            },
            {
                "Description": "New Relic user API ID",
                "Regex": f"(newrelic[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([A-Z0-9]{{64}})['\\\"]"
            },
            {
                "Description": "New Relic ingest browser API token",
                "Regex": f"['\\\"](NRJS-[a-f0-9]{{19}})['\\\"]"
            },
            {
                "Description": "npm access token",
                "Regex": f"['\\\"](npm_(?i)[a-z0-9]{{36}})['\\\"]"
            },
            {
                "Description": "PlanetScale password",
                "Regex": f"pscale_pw_(?i)[a-z0-9\\-_\\.]{{43}}"
            },
            {
                "Description": "PlanetScale API token",
                "Regex": f"pscale_tkn_(?i)[a-z0-9\\-_\\.]{{43}}"
            },
            {
                "Description": "Postman API token",
                "Regex": f"PMAK-(?i)[a-f0-9]{{24}}\\-[a-f0-9]{{34}}"
            },
            {
                "Description": "Pulumi API token",
                "Regex": f"pul-[a-f0-9]{{40}}"
            },
            {
                "Description": "Rubygem API token",
                "Regex": f"rubygems_[a-f0-9]{{48}}"
            },
            {
                "Description": "SendGrid API token",
                "Regex": f"SG\\.(?i)[a-z0-9_\\-\\.]{{66}}"
            },
            {
                "Description": "Sendinblue API token",
                "Regex": f"xkeysib-[a-f0-9]{{64}}\\-(?i)[a-z0-9]{{16}}"
            },
            {
                "Description": "Shippo API token",
                "Regex": f"shippo_(live|test)_[a-f0-9]{{40}}"
            },
            {
                "Description": "LinkedIn Client secret",
                "Regex": f"(linkedin[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z]{{16}})['\\\"]"
            },
            {
                "Description": "LinkedIn Client ID",
                "Regex": f"(linkedin[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{14}})['\\\"]"
            },
            {
                "Description": "Twitch API token",
                "Regex": f"(twitch[a-zA-Z0-9_ .\\-,]{{0,25}})(=|>|:=|\\|\\|:|<=|=>|:).{{0,5}}['\\\"]([a-z0-9]{{30}})['\\\"]"
            },
            {
                "Description": "Typeform API token",
                "Regex": f"(typeform[a-zA-Z0-9_ .\-,]{{0,25}})(=|>|:=|\|\|:|<=|=>|:).{{0,5}}(tfp_[a-z0-9\-_\.=]{{59}})"
            }
        ]
        if type_configuration and hasattr(type_configuration, 'Rules') and type_configuration.Rules is not None and len(type_configuration.Rules) > 0:
            rules = type_configuration.Rules

        exceptions = []
        if type_configuration and hasattr(type_configuration, 'Exceptions') and type_configuration.Exceptions is not None and len(type_configuration.Exceptions) > 0:
            exceptions = type_configuration.Exceptions

        if resource_properties:
            violations = []
            for k in resource_properties:
                violations = _find_violations("{}.{}".format(target_type, k), resource_properties.get(k), violations, rules, exceptions)

            if len(violations) > 0:
                progress.status = OperationStatus.FAILED
                progress.message = f"Secrets found in resource: {', '.join(violations)}"
                progress.errorCode = HandlerErrorCode.NonCompliant
                LOG.warn(f"{progress.message}")
            
    except Exception as e:
        LOG.warn(str(e))
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
