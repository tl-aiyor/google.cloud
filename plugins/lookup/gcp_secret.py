# (c) 2023, Tze L. <tze@aiyor.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# References:
#   - API: https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access
#   - Lookup workflow based on: https://github.com/ansible-collections/community.google/blob/main/plugins/lookup/gcp_storage_file.py
from __future__ import absolute_import, division, print_function
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display


__metaclass__ = type

DOCUMENTATION = """
lookup: gcp_secret
description:
  - This lookup returns the secrets stored in GCP Secret Manager provided
    the caller has the appropriate permissions to read the secret.
requirements:
  - python >= 3.0
  - requests >= 2.18.4
  - google-auth >= 1.3.0
options:
  project:
    description:
      - GCP project number.
    default: environment variable 'GCP_PROJECT'
  secret:
    description:
      - The name of the secret.
    required: yes
  version:
    description:
      - The version of the secret.
    required: no
    default: latest
  auth_kind:
    description:
    - The type of credential used.
    type: str
    default: environment variable 'GCP_AUTH_KIND'
    required: true
    choices:
    - application
    - machineaccount
    - serviceaccount
    - accesstoken
  service_account_contents:
    description:
    - The contents of a Service Account JSON file, either in a dictionary or as a
      JSON string that represents it.
    type: jsonarg
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
  service_account_email:
    description:
    - An optional service account email address if machineaccount is selected and
      the user does not wish to use the default email.
    type: str
  access_token:
    description:
    - An OAuth2 access token if credential type is accesstoken.
    type: str
  scopes:
    description:
    - Array of scopes to be used
    type: list
    elements: str
    default: https://www.googleapis.com/auth/cloud-platform
notes:
- If version is not provided, this plugin will default to using 'latest' secret version
- for authentication, you can set service_account_file using the C(GCP_SERVICE_ACCOUNT_FILE)
  env variable.
- for authentication, you can set service_account_contents using the C(GCP_SERVICE_ACCOUNT_CONTENTS)
  env variable.
- For authentication, you can set service_account_email using the C(GCP_SERVICE_ACCOUNT_EMAIL)
  env variable.
- For authentication, you can set access_token using the C(GCP_ACCESS_TOKEN)
  env variable.
- For authentication, you can set auth_kind using the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if the playbook values are not set.
- The I(service_account_email) and I(service_account_file) options are mutually exclusive.
"""

EXAMPLES = """
- ansible.builtin.debug: # Using service account json authentication file
    msg: |
         the secret value is {{ 
         lookup(
           'gcp_secret',
           project='my-gcp-project-id',
           secret='mysecret', 
           version='3',
           auth_kind='serviceaccount', 
           service_account_file='/tmp/myserviceaccountfile.json')
         }}
"""

RETURN = """
_raw:
    description:
        - secret content string
"""

try:
    import os
    import requests
    import json
    import base64
except ImportError:
    pass

try:
    from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
        GcpSession,
    )
    HAS_GOOGLE_CLOUD_COLLECTION = True
except ImportError:
    HAS_GOOGLE_CLOUD_COLLECTION = False

display = Display()

class GcpMockModule(object):
    def __init__(self, params):
        self.params = params

    def fail_json(self, *args, **kwargs):
        raise AnsibleError(kwargs["msg"])

    def raise_for_status(self, response):
        try:
            response.raise_for_status()
        except getattr(requests.exceptions, "RequestException"):
            self.fail_json(msg="GCP returned error: %s" % response.json())


class GcpSecretLookup:
    def run(self, method, **kwargs):
        params = {
            "project": kwargs.get("project", os.environ.get("GCP_PROJECT")),
            "secret": kwargs.get("secret", None),
            "version": kwargs.get("version", "latest"),
            "auth_kind": kwargs.get("auth_kind", os.environ.get("GCP_AUTH_KIND")),
            "service_account_file": kwargs.get("service_account_file", os.environ.get("GCP_SERVICE_ACCOUNT_FILE")),
            "service_account_email": kwargs.get("service_account_email", os.environ.get("GCP_SERVICE_ACCOUNT_EMAIL")),
            "service_account_contents": kwargs.get("service_account_contents", os.environ.get("GCP_SERVICE_ACCOUNT_CONTENTS")),
            "access_token": kwargs.get("access_token", os.environ.get("GCP_ACCESS_TOKEN")), # added for https://github.com/ansible-collections/google.cloud/pull/574
            "scopes": kwargs.get("scopes", None),
        }
        if not params["scopes"]:
            params["scopes"] = ["https://www.googleapis.com/auth/cloud-platform"]
        fake_module = GcpMockModule(params)
        result = self.get_secret(fake_module)
        return [base64.b64decode(result)]

    def get_secret(self, module):
        auth = GcpSession(module, "secretmanager")
        url = "https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret}/versions/{version}:access".format(
            **module.params
        )
        response = auth.get(url)
        return response.json()['payload']['data']

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not HAS_GOOGLE_CLOUD_COLLECTION:
            raise AnsibleError(
                "gcp_secret lookup needs a supported version of the google.cloud collection installed. Use `ansible-galaxy collection install google.cloud` to install it"
            )
        return GcpSecretLookup().run(terms, variables=variables, **kwargs)
