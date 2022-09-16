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
    
    def encrypt_keys(self, _inpname, _api_token, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"inpName": _inpname, "apiToken": _api_token}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _inpname:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _token_name)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))
    
    def decrypt_keys(self, _inpname, _api_token, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _token_name:
                return storage_password.content.clear_password
    
    def mask_credentials(self, _input_name, _base_url, _api_token, _session_key):

        try:
            args = {"token": _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "input_name": _input_name,
                "base_url": _base_url,
                "api_token": self.MASK
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))
    
    def get_assessment_list_total_pages(self, _base_url, _api_token):

        if _base_url[-1] == '/':
            _base_url = _base_url.rstrip(_base_url[-1])

        url = f"{_base_url}/api/assessment/v2/assessments?assessmentArchivalState=ALL&size=2000"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_token}"
        }

        totalPages = 0

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            ew.log("ERROR", f'Failed to get total number of pages from {base_url}.')

        if "page" in response.json():
            if "totalPages" in response.json()["page"]:
                totalPages = response.json()["page"]["totalPages"]

        return totalPages

    def get_assessment_list():
        pass
    
    def stream_events(self, inputs, ew):

        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = self.input_items["base_url"]
        api_token = self.input_items["api_token"]
        
        totalPages = self.get_assessment_list_total_pages(base_url, api_token)

        testing = Event()
        testing.stanza = self.input_name
        testing.sourceType  = "onetrust:totalPages"
        testing.data = f"Total pages: {str(totalPages)}"
        ew.write_event(testing)
            

if __name__ == "__main__":
    sys.exit(OneTrustAssessments().run(sys.argv))