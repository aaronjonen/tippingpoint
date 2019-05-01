
import unittest
import tippingpoint.client as cli
import tippingpoint.resource as resources
import os

SMSSERVER=os.environ["SMSSERVER"]
SMSUSER = os.environ["SMSUSER"]
SMSPASS = os.environ["SMSPASS"]
API = os.environ["api_key"]
DEVICE_ID = os.environ["DEVICE_ID"]
EVENT_ID = os.environ["EVENT_ID"]


class Authenticate(unittest.TestCase):

    def setUp(self):
        self.client = cli.TPClient(server=SMSSERVER,
                              username=SMSUSER,
                              password=SMSPASS,
                              verify=False)

    def test_authentiation(self):
        info = resources.Info(self.client)
        info.version()
        result = info.request()
        self.assertEqual(result["status"],"Success")

    def xxxxtest_device_packet(self):
        resource = resources.DevicePacket(self.client)
        resource.packet_trace(DEVICE_ID)
        result = resource.request()
        self.assertEqual(result["status"],"Success")

    def test_event_packet(self):
        resource = resources.EventPacket(self.client)
        resource.packet_trace([EVENT_ID])
        result = resource.request()
        self.assertEqual(result["status"],"Success")

    def xxxtest_upload(self):

        import datetime
        cur = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        curZ = cur[:-3]+'Z'

        upload = resources.VlnScanner(self.client)
        vendor="Qualys-CSV"
        product="Qualys"
        version="1.0"
        runtime=curZ
        file="./upload_report/Scan_Report_Demisto_20181004.csv"
        upload.import_scan(vendor=vendor,
                           product=product,
                           version=version,
                           runtime=runtime,
                           filepath=file)
        result = upload.request()
        self.assertEqual(result["status"],"Success")

if __name__ == "__main__":
    unittest.main()