from __future__ import unicode_literals
from __future__ import print_function
import os
import tempfile
from scapy.all import rdpcap
import json
import io


class UnknownHeader(Exception):
    def __init__(self,message):
        super(UnknownHeader,self).__init__(message)
        self.message = message


class Resource(object):
    GET="GET"
    POST="POST"

    def __init__(self,client):
        self.client=client
        self.method = Resource.GET
        self.status_codes={} # abstract
        self.data={}
        self.url = self.client.server+"{0}"
        self.additional_parameters = None # dict of additional parameters
        self.file=None #additional parameter for file uploads.

    def __iter(self):
        return self

    def __next__(self):
        return self.request()

    def _request_process_json_standard(self, response_data):
        """Handle JSON response

        This should be the most common response from the ThreatConnect API.

        Return:
            (string): The response data
            (string): The response status
        """
        data = response_data.get('data', {})
        status = response_data.get('status', 'Failure')
        return data, status

    def _request_process_octet(self, response):
        """Handle Document download.

        Return:
            (string): The data from the download
            (string): The status of the download
        """
        status = 'Failure'
        # Handle document download
        data = response.content
        if data:
            status = 'Success'

        return data, status
    def _request_process_pcap(self,response):
        """
        handle pcap download
        :param response:
        :return: dict of pcap info,status of response
        """
        status = 'Failure'
        # Handle document download
        data = response.content
        string_data= None
        if data:
            status = 'Success'
            data = rdpcap(io.BytesIO(data))
            l = [i.show(dump=True) for i in data]
            string_data = "\n-------END-------\n".join(l)

        return string_data, status

    def _request_process_text(self, response):
        """Handle Signature download.

        Return:
            (string): The data from the download
            (string): The status of the download
        """
        status = 'Failure'
        # Handle document download
        data = response.content
        if data:
            status = 'Success'

        return data, status

    def request(self):
        response = self.client.req(method=self.method,
                                   url=self.url,
                                   ok_codes=self.status_codes[self.method],
                                   data=None,
                                   additional_parameters=self.additional_parameters,
                                   file_up=self.file)
        status=None
        data=None
        if "content-type" in response.headers:
            if response.headers['content-type'] == 'application/pcap':
                data, status = self._request_process_pcap(response)
            elif response.headers['content-type'] == 'application/json':
                data, status = self._request_process_json_standard(response)
            elif response.headers['content-type'] == 'application/octet-stream':
                data, status = self._request_process_octet(response)
            elif 'text/plain' in response.headers['content-type'] :
                data, status = self._request_process_text(response)
            else:
                err = u'Failed Request: {}'.format(response.text)
                raise LookupError("unknown content type "+ err)
        else:
            data = None

        if response.status_code in self.status_codes[self.method]:
            status='Success'

        return {
            'data':data,
            'response':response,
            'status':status
        }


class DevicePacket(Resource):
    def __init__(self,client):
        super(DevicePacket,self).__init__(client)
        self.status_codes = {
            'GET':[200],
            'POST':[200]
        }
        self.url = self.url.format("pcaps/getByDevice")

    def packet_trace(self,device_id):
        self.method=Resource.GET
        self.additional_parameters = {"deviceId":device_id}


class EventPacket(Resource):

    def __init__(self,client):
        super(EventPacket,self).__init__(client)
        self.url = self.url.format("pcaps/getByEventIds")
        self.status_codes = {
            'GET':[200],
            'POST':[200]
        }
        self.file = tempfile.NamedTemporaryFile(delete=False)

    def packet_trace(self,event_ids=None):
        """
        :param event_ids: list of event ids
        :return:
        """
        self.method=Resource.POST
        self.file.write(','.join(event_ids))
        self.file.close()

    def __del__(self):
        try:
            os.remove(self.file.name)
        except  OSError:
            pass

class Info(Resource):
    def __init__(self,client):
        super(Info,self).__init__(client)
        self.url = self.url.format("smsAdmin/info?{}")
        self.status_codes = {
            'GET':[200],
            'POST':[200]
        }

    def version(self):
        self.url = self.url.format("request=version")
        self.method = Resource.GET

class VlnScanner(Resource):
    def __init__(self,client):
        super(VlnScanner,self).__init__(client)
        self.url = self.url.format("vulnscanner/{}")
        self.method = Resource.GET
        self.status_codes = {
            'GET':[200],
            'POST':[200]
        }

    def import_scan(self,vendor,product,version,runtime,filepath):
        """
        :param vendor:Name of the vulnerability management vendor. Use the SMSStandard
        value with the import method.
        :param product:Product name associated with the vulnerability scanner, and can be
        any value.
        :param version:
        :param runtime:
        :return:
        """
        self.url = self.url.format("convert")
        self.additional_parameters = {
            'vendor':vendor,
            'product':product,
            'version':version,
            'runtime':runtime
        }
        self.file=filepath
        self.method = Resource.POST
