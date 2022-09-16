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
    CREDENTIALS = None
    # CHECKPOINT_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'tmp', 'CHECKPOINT'))
    
    def get_scheme(self):
        scheme = Scheme("OneTrust Assessments")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "OneTrust Assessments Token Credentials"

        input_name = Argument("input_name")
        input_name.title = "Name"
        input_name.data_type = Argument.data_type_string
        input_name.description = "Give a name to this input, without spaces"
        input_name.required_on_create = True
        input_name.required_on_edit = False
        scheme.add_argument(input_name)

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
    
    def encrypt_keys(self, _input_name, _api_token, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"inputName": _input_name, "apiToken": _api_token}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _input_name:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _token_name)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))
    
    def decrypt_keys(self, _input_name, _api_token, _session_key):

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
        token_name = self.input_items["token_name"]
        auth_token = self.input_items["auth_token"]

        ew.log("INFO", f'Collecting BigID Audit Logs from: {str(base_url)}')
        
        try:
            if auth_token != self.MASK:
                self.encrypt_keys(token_name, auth_token, session_key)
                self.mask_credentials(base_url, token_name, self.input_name, session_key)
            
            decrypted = self.decrypt_keys(token_name, session_key)
            self.CREDENTIALS = json.loads(decrypted)
            auth_token = self.CREDENTIALS["authToken"]
            
            # Retrieve checkpoint 
            checkpoint_hash = self.read_tail(ew)
            ew.log("INFO", f'Checkpoint retrieved: {checkpoint_hash}.')
            
            ew.log("INFO", f'Refreshing token on {base_url} with token (secret) length: {str(len(auth_token))}')
            r_rt = self.refresh_token(ew, base_url, auth_token)
            
            ew.log("INFO", 'Token refreshed. Now retrieving audit logs...')
            r_al = self.get_audit_logs(ew, base_url, r_rt)
            audit_dumps = r_al.text.splitlines()
            total_audit_dumps = len(audit_dumps)
            
            ew.log("INFO", f'Audit logs retrieved. A total of {str(total_audit_dumps)} lines. Now working on checkpoint matching...')
            index_to_start = -1
            
            if checkpoint_hash != self.CHECKPOINT_HEADER:
                ew.log("INFO", f'Checkpoint is not empty. Starting with new events only. Searching audit dumps for a checkpoint match...')
                for ad in audit_dumps:
                    index_to_start = index_to_start + 1
                    ad_line_hash = hashlib.sha256(ad.strip().encode())
                    ad_line_hash = ad_line_hash.hexdigest()
                    if checkpoint_hash == ad_line_hash: 
                        ew.log("INFO", f'Checkpoint found. Starting at line: {str(index_to_start)}.')
                        break
                
                ew.log("INFO", f'Checkpoint engine report: {str(index_to_start + 1)}/{total_audit_dumps}.')

                if index_to_start == total_audit_dumps - 1:
                    ew.log("INFO", f'No checkpoint found. All audit logs will be indexed.')
                    index_to_start = -1

            else:
                ew.log("INFO", f'Checkpoint is empty. All audit logs will be indexed.')
            
            new_audit_logs = audit_dumps[index_to_start + 1:]
            
            for line in new_audit_logs:
                auditLine = Event()
                auditLine.stanza = self.input_name
                auditLine.sourceType  = "bigid:audit"
                auditLine.data = line
                ew.write_event(auditLine)
            
            ew.log("INFO", f'Successfully indexed {str(len(new_audit_logs))} BigID audit logs.')
            
            # Create checkpoint 
            new_checkpoint = new_audit_logs[len(new_audit_logs) - 1]
            new_checkpoint_hash = hashlib.sha256(new_checkpoint.strip().encode())
            new_checkpoint_hash = new_checkpoint_hash.hexdigest()
            self.append_checkpoint(ew, new_checkpoint_hash, 'a+')
            ew.log("INFO", f'Done writing/appending new checkpoint.')
            
            # Trim checkpoint file only half of the time
            if random.random() < .5:
                self.trim_checkpoint(ew, 3000)
            
            
        except Exception as e:
            ew.log("ERROR", "Error streaming events: %s" % str(e))
            

if __name__ == "__main__":
    sys.exit(OneTrustAssessments().run(sys.argv))