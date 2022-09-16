import json
import os
import sys
import requests
import hashlib
import random
from splunklib.modularinput import *
import splunklib.client as client

class OneTrustAssessments(Script):
    
    MASK = "***ENCRYPTED***"
    
    def get_scheme(self):
        scheme = Scheme("OneTrust Assessments")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "OneTrust Assessments Token Credentials"

        base_url = Argument("base_url")
        base_url.title = "URL"
        base_url.data_type = Argument.data_type_string
        base_url.description = "E.g. https://customer.my.onetrust.com"
        base_url.required_on_create = True
        base_url.required_on_edit = True
        scheme.add_argument(base_url)
        
        api_token = Argument("api_token")
        api_token.title = "API Token"
        api_token.data_type = Argument.data_type_string
        api_token.description = "OAuth2 Bearer Token"
        api_token.required_on_create = True
        api_token.required_on_edit = True
        scheme.add_argument(api_token) 
        
        return scheme
    
    def validate_input(self, definition):
        pass
    
    def encrypt_keys(self, _base_url, _api_token, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"baseUrl": _base_url, "apiToken": _api_token}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _base_url:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _base_url)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))
    
    def decrypt_keys(self, _base_url, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _base_url:
                return storage_password.content.clear_password
    
    def mask_credentials(self, _base_url, _api_token, _input_name, _session_key):

        try:
            args = {"token": _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "base_url": _base_url,
                "api_token": self.MASK
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))
    
    def get_assessment_list(self, ew, _base_url, _api_token, _page):
        if _base_url[-1] == '/':
            _base_url = _base_url.rstrip(_base_url[-1])

        url = f"{_base_url}/api/assessment/v2/assessments?assessmentArchivalState=ALL&size=2000&page={_page}"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_token}"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                ew.log("ERROR", f"request_status_code={str(response.status_code)}. Failed to get total number of pages from {base_url}.")
                sys.exit(1)
            
            return response.json()
        except Exception as e:
            ew.log("ERROR", "Error streaming events: %s" % str(e))
            sys.exit(1)

    def stream_events(self, inputs, ew):

        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = self.input_items["base_url"]
        api_token = self.input_items["api_token"]

        try:
            if api_token != self.MASK:
                self.encrypt_keys(base_url, api_token, session_key)
                self.mask_credentials(base_url, api_token, self.input_name, session_key)

            decrypted = self.decrypt_keys(base_url, session_key)
            self.CREDENTIALS = json.loads(decrypted)
            api_token = self.CREDENTIALS["apiToken"]

            # Assumed there at least 1 page
            assessment_ids_pages = 1
            page_flipper = 0

            while page_flipper < assessment_ids_pages:

                assessment_ids = self.get_assessment_list(ew, base_url, api_token, page_flipper)

                if "page" in assessment_ids:
                    if "totalPages" in assessment_ids["page"]:
                        assessment_ids_pages = assessment_ids["page"]["totalPages"]

                for assessment in assessment_ids["content"]:
                    asId = Event()
                    asId.stanza = self.input_name
                    asId.sourceType  = "onetrust:assessmentId"
                    asId.data = json.dumps(assessment)
                    ew.write_event(asId)

        except Exception as e:
            ew.log("ERROR", "Error streaming events: %s" % str(e))
            

if __name__ == "__main__":
    sys.exit(OneTrustAssessments().run(sys.argv))