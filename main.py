import os
import yaml
import base64
import email
import mimetypes
import json
import time
from google.cloud import secretmanager, storage

class Parse(object):
    def __init__(self, request):
        self._keys =  [
            "from",
            "attachments",
            "headers",
            "text",
            "envelope",
            "to",
            "html",
            "sender_ip",
            "attachment-info",
            "subject",
            "dkim",
            "SPF",
            "charsets",
            "content-ids",
            "spam_report",
            "spam_score",
            "email"
        ]
        self._request = request
        request.get_data(as_text=True)
        self._payload = request.form
        self._raw_payload = request.data

    def key_values(self):
        """
        Return a dictionary of key/values in the payload received from
        the webhook
        """
        key_values = {}
        for key in self.keys:
            if key in self.payload:
                key_values[key] = self.payload[key]
        return key_values

    def get_raw_email(self):
        """
        This only applies to raw payloads:
        https://sendgrid.com/docs/Classroom/Basics/Inbound_Parse_Webhook/setting_up_the_inbound_parse_webhook.html#-Raw-Parameters
        """
        if 'email' in self.payload:
            raw_email = email.message_from_string(self.payload['email'])
            return raw_email
        else:
            return None

    def attachments(self):
        """Returns an object with:
        type = file content type
        file_name = the name of the file
        contents = base64 encoded file contents"""
        attachments = None
        if 'attachment-info' in self.payload:
            attachments = self._get_attachments(self.request)
        # Check if we have a raw message
        raw_email = self.get_raw_email()
        if raw_email is not None:
            attachments = self._get_attachments_raw(raw_email)
        return attachments

    def _get_attachments(self, request):
        attachments = []
        for _, filestorage in request.files.items():
            attachment = {}
            if filestorage.filename not in (None, 'fdopen', '<fdopen>'):
                # filename = secure_filename(filestorage.filename)
                # TODO scrub file name
                filename = filestorage.filename
                attachment['type'] = filestorage.content_type
                attachment['file_name'] = filename
                attachment['contents'] = base64.b64encode(filestorage.read())
                attachments.append(attachment)
        return attachments

    def _get_attachments_raw(self, raw_email):
        attachments = []
        counter = 1
        for part in raw_email.walk():
            attachment = {}
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if not filename:
                ext = mimetypes.guess_extension(part.get_content_type())
                if not ext:
                    ext = '.bin'
                filename = 'part-%03d%s' % (counter, ext)
            counter += 1
            attachment['type'] = part.get_content_type()
            attachment['file_name'] = filename
            attachment['contents'] = part.get_payload(decode=False)
            attachments.append(attachment)
        return attachments

    @property
    def keys(self):
        return self._keys

    @property
    def request(self):
        return self._request

    @property
    def payload(self):
        return self._payload

    @property
    def raw_payload(self):
        return self._raw_payload

"""
EMAIL_DOMAIN = os.environ['EMAIL_DOMAIN']
BASE_DROP_ZONE = os.environ['BASE_DROP_ZONE']
ADDRESS_TO_STORAGE_MAP = os.environ['ADDRESS_TO_STORAGE_MAP']
"""

EMAIL_DOMAIN = 'parse.neustar.com'
BASE_DROP_ZONE = 'attachment-drop-zone'
ADDRESS_TO_STORAGE_MAP = {
    'client1': {
        'content_types': ['image/jpeg', 'text/plain', 'text/html'],
        'storage': 'client1'
    },
    'client2': {
        'content_types': ['.txt'],
        'storage': 'client2'
    }
}
def inbound_parse(request):
    parsed = Parse(request)
    parsed_dict = parsed.key_values()
    envelop_dict = json.loads(parsed_dict['envelope'])

    # endpoint must be public, so verify domain and address
    spl = envelop_dict['from'].split("@")
    if spl[1] != EMAIL_DOMAIN or spl[0] not in ADDRESS_TO_STORAGE_MAP.keys():
        print("ERROR: unknown sender: %s" % envelop_dict['from'])
        return "", 403

    client_config = ADDRESS_TO_STORAGE_MAP[spl[0]]
    # check for attachments
    attachments = parsed.attachments()
    if not len(attachments):
        # TODO return to sender
        print("ERROR: No attachments from sender: %s" % envelop_dict['from'])
    else:
        # process attachments
        save_attachments = []
        bad_attachments = []
        for a in attachments:
            if a['type'] in client_config['content_types']:
                save_attachments.append(a)
            else:
                bad_attachments.append(a)
        
        if len(bad_attachments):
            # TODO return to sender
            for a in bad_attachments:
                print("ERROR: Attachment(s) have wrong content type: %s" % '%s %s' % (a['file_name'], a['type']))
        else:
            # store attachments
            gcs = storage.Client()
            bucket = gcs.get_bucket(BASE_DROP_ZONE)
            timestamp = str(time.time()).split(".")[0]
    
            for a in save_attachments:
                gs_path = "%s/%s/%s" % (client_config['storage'], timestamp, a['file_name'])
                blob = bucket.blob(gs_path)
                blob.upload_from_string(
                    a['contents'],
                    content_type=a['type']
                )
    
    # must return 200 or sendgrid will resend
    return "OK", 200