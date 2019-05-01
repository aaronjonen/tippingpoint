from __future__ import unicode_literals
from __future__ import print_function

import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

class TPClient:

    def __init__(self, server, username, password,verify=True,api_key=None):
        self.server = server
        self.username = username
        self.password = password
        self.verify=verify
        self.api_key=api_key
        if not (username and password and server):
            raise ValueError('You must supply server, username, and password')
        if not server.find('https://') ==0:
            raise ValueError("Server must be a url (eg. 'https://<server>")
        if not server[-1]=='/':
            server+='/'

    def req(self,method,url,ok_codes,data=None,additional_parameters=None,file_up=None):
        """
        :param method: String - GET, POST, DELETE
        :param url:  String
        :param ok_codes:  dict
        :param data: post data
        :param additional_parameters: dict - additional request parameters
        :return:
        """
        headers=None
        if self.api_key is not None:
            headers = {"X-SMS-API-KEY":self.api_key}
        files=None
        if file_up is not None:
            files = {'file':open(file_up.name,'rb')}

        r = requests.request(method=method,
                             url=url,
                             auth=(self.username,self.password),
                             verify=self.verify,
                             headers=headers,
                             data=data,
                             params=additional_parameters,
                             files=files)
        try:
            if r.status_code not in ok_codes:
                raise RuntimeError('Error %d (%s) (%s)' % (r.status_code,r.reason,r.content))
        except InsecureRequestWarning:
            pass
        return r

