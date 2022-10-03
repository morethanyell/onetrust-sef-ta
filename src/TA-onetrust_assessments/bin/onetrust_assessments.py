import json
import os
import sys
import requests
import hashlib
import socket
from splunklib.modularinput import *
import splunklib.client as client

class OneTrustAssessments(Script):
    
    MASK = "***ENCRYPTED***"
    NO_JSON_DATA = "n/a"
    
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
        
        url = f"{_base_url}/api/assessment/v2/assessments?assessmentArchivalState=ALL&size=2000&page={_page}"

        ew.log("INFO", f"Performing API get request on {url}")

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

    def get_assessment_details(self, ew, _base_url, _api_token, _assessmentId):
        
        url = f"{_base_url}/api/assessment/v2/assessments/assessment-results"
        url = f"{_base_url}/api/assessment/v2/assessments/{_assessmentId}/export?ExcludeSkippedQuestions=true"

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

    def assessment_json_bldr(self, ew, _data):
        assessmentJsonRetVal = {}

        assessmentJsonRetVal['assessmentId'] = NO_JSON_DATA
        if 'assessmentId' in data:
            assessmentJsonRetVal['assessmentId'] = data['assessmentId']

        assessmentJsonRetVal['assessmentNumber'] = NO_JSON_DATA
        if 'assessmentNumber' in data:
            assessmentJsonRetVal['assessmentNumber'] = data['assessmentNumber']

        assessmentJsonRetVal['lastUpdated'] = NO_JSON_DATA
        if 'lastUpdated' in data:
            assessmentJsonRetVal['lastUpdated'] = data['lastUpdated']

        assessmentJsonRetVal['submittedOn'] = NO_JSON_DATA
        if 'lastUpdated' in data:
            assessmentJsonRetVal['submittedOn'] = data['submittedOn']

        assessmentJsonRetVal['completedOn'] = NO_JSON_DATA
        if 'completedOn' in data:
            assessmentJsonRetVal['completedOn'] = data['completedOn']

        assessmentJsonRetVal['createdDT'] = NO_JSON_DATA
        if 'createdDT' in data:
            assessmentJsonRetVal['createdDT'] = data['createdDT']

        assessmentJsonRetVal['template'] = NO_JSON_DATA
        if 'template' in data:
            if 'name' in data['template']:
                assessmentJsonRetVal['template'] = data['template']['name']

        assessmentJsonRetVal['title'] = NO_JSON_DATA
        if 'name' in data:
            assessmentJsonRetVal['title'] = data['name']

        assessmentJsonRetVal['orgGroup'] = NO_JSON_DATA
        if 'orgGroup' in data:
            if 'name' in data['orgGroup']:
                assessmentJsonRetVal['orgGroup'] = data['orgGroup']['name']

        assessmentJsonRetVal['createdBy'] = NO_JSON_DATA
        if 'createdBy' in data:
            if 'name' in data['createdBy']:
                assessmentJsonRetVal['createdBy'] = data['createdBy']['name']

        assessmentJsonRetVal['responseTitle'] = NO_JSON_DATA
        if 'sections' in data:
            if 'questions' in data['sections'][0]:
                for question in data['sections'][0]['questions']:
                    if 'content' in question['question']:
                        if question['question']['content'] == 'Please provide a request title':
                            assessmentJsonRetVal['responseTitle'] = question['questionResponses'][0]['responses'][0]['response']
                            break

        assessmentJsonRetVal['approvalInfo'] = []
        if 'approvers' in data:
            for approvers in data['approvers']:
                assessmentJsonRetVal['approvalInfo'].append({
                    "approvers": approvers['approver']['fullName'], 
                    "approvedOn": approvers['approvedOn'], 
                    "approverResult": approvers['resultName']
                    })

        assessmentJsonRetVal['respondent'] = NO_JSON_DATA
        if 'respondent' in data:
            if 'name' in data['respondent']:
                assessmentJsonRetVal['respondent'] = data['respondent']['name']

        assessmentJsonRetVal['status'] = NO_JSON_DATA
        if 'status' in data:
            assessmentJsonRetVal['status'] = data['status']

        assessmentJsonRetVal['result'] = NO_JSON_DATA
        if 'result' in data:
            assessmentJsonRetVal['result'] = data['result']

        assessmentJsonRetVal['riskLevel'] = NO_JSON_DATA
        if 'residualRiskScore' in data:
            assessmentJsonRetVal['riskLevel'] = data['residualRiskScore']
        
        return assessmentJsonRetVal

    def stream_events(self, inputs, ew):

        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = self.input_items["base_url"]
        api_token = self.input_items["api_token"]

        if base_url[-1] == '/':
            base_url = base_url.rstrip(base_url[-1])

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
            apiScriptHost = socket.gethostname()

            while page_flipper < assessment_ids_pages:

                assessment_ids = self.get_assessment_list(ew, base_url, api_token, page_flipper)

                # At first iteration, get the total number of pages
                if page_flipper == 0:
                    if "page" in assessment_ids:
                        if "totalPages" in assessment_ids["page"]:
                            assessment_ids_pages = assessment_ids["page"]["totalPages"]

                for assessment in assessment_ids["content"]:
                    assessment["tenantHostname"] = base_url
                    assessment["apiPage"] = page_flipper
                    assessment["apiScriptHost"] = apiScriptHost
                    asId = Event()
                    asId.stanza = self.input_name
                    asId.sourceType  = "onetrust:assessmentId"
                    asId.data = json.dumps(assessment)
                    ew.write_event(asId)
                
                page_flipper = page_flipper + 1

        except Exception as e:
            ew.log("ERROR", "Error streaming events: %s" % str(e))
            

if __name__ == "__main__":
    sys.exit(OneTrustAssessments().run(sys.argv))