import json
import sys
import requests
import socket
import re
import time
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
        base_url.required_on_edit = False
        scheme.add_argument(base_url)
        
        api_token = Argument("api_token")
        api_token.title = "API Token"
        api_token.data_type = Argument.data_type_string
        api_token.description = "OAuth2 Bearer Token"
        api_token.required_on_create = True
        api_token.required_on_edit = False
        scheme.add_argument(api_token)
        
        assessment_archival_state = Argument("assessment_archival_state")
        assessment_archival_state.title = "Archival State"
        assessment_archival_state.data_type = Argument.data_type_string
        assessment_archival_state.description = "Can only be one of the following: < ALL | ARCHIVED | NON_ARCHIVED > Invalid or misspelled value may result to errors."
        assessment_archival_state.required_on_create = True
        assessment_archival_state.required_on_edit = False
        scheme.add_argument(assessment_archival_state)
        
        test_mode = Argument("test_mode")
        test_mode.title = "Input Test Mode"
        test_mode.data_type = Argument.data_type_boolean
        test_mode.description = "When set to True, the script will only collect data based on the first page returned by the API server."
        test_mode.required_on_create = True
        test_mode.required_on_edit = False
        scheme.add_argument(test_mode)
        
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
    
    def get_assessment_list(self, ew, _base_url, _api_token, _archival_state, _page):
        
        url = f"{_base_url}/api/assessment/v2/assessments?assessmentArchivalState={_archival_state}&size=2000&page={_page}"

        ew.log("INFO", f"OneTrust API Call: GET {url}")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_token}"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                ew.log("ERROR", f"API call returned request_status_code={str(response.status_code)}. Failed to retrieve Assessment Summary from {_base_url}.")
                sys.exit(1)
            
            return response.json()
        except Exception as e:
            ew.log("ERROR", f"Error retrieving 2000 Assessment IDs from page={str(_page)}. err_msg=\"{str(e)}\"")
            sys.exit(1)

    def get_assessment_details(self, ew, _base_url, _api_token, _assessmentId):
        
        url = f"{_base_url}/api/assessment/v2/assessments/{_assessmentId}/export?ExcludeSkippedQuestions=true"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_token}"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                ew.log("ERROR", f"API call returned request_status_code={str(response.status_code)}. Failed to retrieve assessment detail of {_assessmentId} from {_base_url}. Moving on to next Assessment ID instead.")
                return None
            else:
                return response.json()
        except Exception as e:
            ew.log("ERROR", f"Error retrieving Assessment detail of {_assessmentId}. err_msg=\"{str(e)}\"")
            return None

    def assessment_json_bldr(self, ew, _data):
        assessmentJsonRetVal = {}

        assessmentJsonRetVal['assessmentId'] = self.NO_JSON_DATA
        if 'assessmentId' in _data:
            assessmentJsonRetVal['assessmentId'] = _data['assessmentId']

        assessmentJsonRetVal['assessmentNumber'] = self.NO_JSON_DATA
        if 'assessmentNumber' in _data:
            assessmentJsonRetVal['assessmentNumber'] = _data['assessmentNumber']

        assessmentJsonRetVal['lastUpdated'] = self.NO_JSON_DATA
        if 'lastUpdated' in _data:
            assessmentJsonRetVal['lastUpdated'] = _data['lastUpdated']

        assessmentJsonRetVal['submittedOn'] = self.NO_JSON_DATA
        if 'lastUpdated' in _data:
            assessmentJsonRetVal['submittedOn'] = _data['submittedOn']

        assessmentJsonRetVal['completedOn'] = self.NO_JSON_DATA
        if 'completedOn' in _data:
            assessmentJsonRetVal['completedOn'] = _data['completedOn']

        assessmentJsonRetVal['createdDT'] = self.NO_JSON_DATA
        if 'createdDT' in _data:
            assessmentJsonRetVal['createdDT'] = _data['createdDT']

        assessmentJsonRetVal['template'] = self.NO_JSON_DATA
        if 'template' in _data:
            if 'name' in _data['template']:
                assessmentJsonRetVal['templateName'] = _data['template']['name']

        assessmentJsonRetVal['title'] = self.NO_JSON_DATA
        if 'name' in _data:
            assessmentJsonRetVal['title'] = _data['name']

        assessmentJsonRetVal['orgGroup'] = self.NO_JSON_DATA
        if 'orgGroup' in _data:
            if 'name' in _data['orgGroup']:
                assessmentJsonRetVal['orgGroup'] = _data['orgGroup']['name']

        assessmentJsonRetVal['createdBy'] = self.NO_JSON_DATA
        if 'createdBy' in _data:
            if 'name' in _data['createdBy']:
                assessmentJsonRetVal['createdBy'] = _data['createdBy']['name']

        assessmentJsonRetVal['responseTitle'] = self.NO_JSON_DATA
        if 'sections' in _data:
            if len(_data['sections']) > 0:
                if 'questions' in _data['sections'][0]:
                    for question in _data['sections'][0]['questions']:
                        if 'content' in question['question']:
                            if question['question']['content'] == 'Please provide a request title':
                                if len(question['questionResponses']) > 0:
                                    if len(question['questionResponses'][0]['responses']) > 0:
                                        assessmentJsonRetVal['responseTitle'] = question['questionResponses'][0]['responses'][0]['response']
                                        break

        assessmentJsonRetVal['approvalInfo'] = []
        if 'approvers' in _data:
            for approvers in _data['approvers']:
                assessmentJsonRetVal['approvalInfo'].append({
                    "approvers": approvers['approver']['fullName'], 
                    "approvedOn": approvers['approvedOn'], 
                    "approverResult": approvers['resultName']
                    })

        assessmentJsonRetVal['respondent'] = self.NO_JSON_DATA
        if 'respondent' in _data:
            if 'name' in _data['respondent']:
                assessmentJsonRetVal['respondent'] = _data['respondent']['name']
        
        assessmentJsonRetVal['respondents'] = self.NO_JSON_DATA
        if 'respondents' in _data:
            respondent_names = [r['name'] for r in _data['respondents']]
            assessmentJsonRetVal['respondents'] = respondent_names

        assessmentJsonRetVal['status'] = self.NO_JSON_DATA
        if 'status' in _data:
            assessmentJsonRetVal['status'] = _data['status']

        assessmentJsonRetVal['result'] = self.NO_JSON_DATA
        if 'result' in _data:
            assessmentJsonRetVal['result'] = _data['result']

        assessmentJsonRetVal['riskLevel'] = self.NO_JSON_DATA
        if 'residualRiskScore' in _data:
            assessmentJsonRetVal['riskLevel'] = _data['residualRiskScore']
        
        return assessmentJsonRetVal

    def assessment_questions_json_bldr(self, ew, _data):
        
        questionsRetVal = {}
        questionsRetVal['assessmentId'] = _data['assessmentId']
        questionsRetVal['questionsAndAnswers'] = []

        if "sections" in _data:
            for section in _data['sections']:
                if "header" in section:
                    if "name" in section['header']:
                        sectionNameContent = section['header']['name']
                        if re.search("Frequently\sAsked\sQuestions?", sectionNameContent):
                            continue
                        questionsRetVal['sectionName'] = sectionNameContent
                    if "description" in section['header']:
                        questionsRetVal['description'] = section['header']['description']
                    if "sequence" in section['header']:
                        questionsRetVal['sequence'] = section['header']['sequence']
                if "questions" in section:
                    for question in section['questions']:
                        qna = {}
                        # Question key-val-pair
                        if "question" in question:
                            if "content" in question['question']:
                                qna['question'] = question['question']['content']
                            if "sequence" in question['question']:
                                qna['questionSeq'] = question['question']['sequence']
                                
                        # Responses key-val-pair (array)
                        allResponses = []
                        defaultResponse = "n/a"
                        if "questionResponses" in question:
                            for questionResponse in question['questionResponses']:
                                if "responses" in questionResponse:
                                    for response in questionResponse['responses']:
                                        if "response" in response:
                                            defaultResponse = response['response']
                                            allResponses.append(defaultResponse)
                        qna['responses'] = allResponses
                                    
                        questionsRetVal['questionsAndAnswers'].append(qna)
                                    
        return questionsRetVal

    def stream_events(self, inputs, ew):
        
        start = time.time()

        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = str(self.input_items["base_url"]).strip()
        api_token = str(self.input_items["api_token"]).strip()
        archival_state = str(self.input_items["assessment_archival_state"]).strip()
        test_mode = 0
        test_mode = self.input_items["test_mode"]

        if base_url[-1] == '/':
            base_url = base_url.rstrip(base_url[-1])
        
        ew.log("INFO", f"Streaming OneTrust Assessment Summary, Details, and Questions and Responses from base_url={base_url}. test_mode={str(test_mode)}")

        try:
            if api_token != self.MASK:
                self.encrypt_keys(base_url, api_token, session_key)
                self.mask_credentials(base_url, api_token, self.input_name, session_key)

            decrypted = self.decrypt_keys(base_url, session_key)
            self.CREDENTIALS = json.loads(decrypted)
            api_token = str(self.CREDENTIALS["apiToken"]).strip()

            # Assumes there at least 1 page
            assessment_ids_pages = 1
            page_flipper = 0
            apiScriptHost = socket.gethostname()

            ew.log("INFO", f"API credentials and other parameters retrieved. archival_state={archival_state}")
            
            all_assessments = {}
            all_assessments['content'] = []

            while page_flipper < assessment_ids_pages:

                assessment_ids_curpage = self.get_assessment_list(ew, base_url, api_token, archival_state, page_flipper)

                # At first iteration, get the total number of pages
                if page_flipper == 0:
                    if "page" in assessment_ids_curpage:
                        if "totalPages" in assessment_ids_curpage["page"]:
                            assessment_ids_pages = assessment_ids_curpage["page"]["totalPages"]
                            
                if int(test_mode) == 1:
                    ew.log("INFO", f"Test mode is enabled, so the collector will only perform GET call for page {page_flipper} and will not consume all {assessment_ids_pages} pages for Assessment Summary. Collection of Assessment Details and Questions/Answers will also be skipped.")
                    assessment_ids_pages = 1
                
                if "content" not in assessment_ids_curpage:
                    continue
                
                # Streaming all Assessment Summaries first
                for assessmentItem in assessment_ids_curpage["content"]:
                    assessmentItem["tenantHostname"] = base_url
                    assessmentItem["apiPage"] = page_flipper
                    assessmentItem["apiScriptHost"] = apiScriptHost
                    assessmentSummary = Event()
                    assessmentSummary.stanza = self.input_name
                    assessmentSummary.sourceType  = "onetrust:assessment:summary"
                    assessmentSummary.data = json.dumps(assessmentItem)
                    ew.write_event(assessmentSummary)
                    all_assessments["content"].append(assessmentItem)
                
                page_flipper += 1
            
            if int(test_mode) == 0:
                
                totalAssessments = len(all_assessments["content"]) if "content" in all_assessments and all_assessments is not None else 0
                
                ew.log("INFO", f"Test mode is disabled, so the collector will loop through all Assessment IDs to collect Assessment Details. Total API call expected: {str(totalAssessments)}")
                
                # Another round of looping the assessment_ids for Assessment Details
                for assessment in all_assessments["content"]:
                    if "assessmentId" not in assessment:
                        continue
                    assessmentId = assessment["assessmentId"]
                    fullAssDetail = self.get_assessment_details(ew, base_url, api_token, assessmentId)
                    if fullAssDetail is None: 
                        continue
                    trimmedAssDetail = self.assessment_json_bldr(ew, fullAssDetail)
                    trimmedAssDetail["tenantHostname"] = base_url
                    trimmedAssDetail["apiScriptHost"] = apiScriptHost
                    assessmentDetails = Event()
                    assessmentDetails.stanza = self.input_name
                    assessmentDetails.sourceType  = "onetrust:assessment:details"
                    assessmentDetails.data = json.dumps(trimmedAssDetail)
                    ew.write_event(assessmentDetails)
                    
                    # Streaming Question and Responses
                    assLastUpdated = "n/a"
                    if "lastUpdated" in assessment:
                        assLastUpdated = assessment["lastUpdated"]
                    assTemplate = "n/a"
                    if "templateName" in assessment:
                        assTemplate = assessment["templateName"]
                    trimmedAssQnA = self.assessment_questions_json_bldr(ew, fullAssDetail)
                    trimmedAssQnA["lastUpdated"] = assLastUpdated
                    trimmedAssQnA["templateName"] = assTemplate
                    assessmentQnA = Event()
                    assessmentQnA.stanza = self.input_name
                    assessmentQnA.sourceType  = "onetrust:assessment:qna"
                    assessmentQnA.data = json.dumps(trimmedAssQnA)
                    ew.write_event(assessmentQnA)

        except Exception as e:
            ew.log("ERROR", f"Error streaming events: err_msg=\"{str(e)}\"")
            
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        ew.log("INFO", f"Streaming OneTrust Assessment Summary and Details has been successful / completed in {str(elapsed)} ms.")

if __name__ == "__main__":
    sys.exit(OneTrustAssessments().run(sys.argv))