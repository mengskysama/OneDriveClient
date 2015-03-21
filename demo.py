# -*- coding:utf-8 -*-

import locale
import argparse
import json
import os
import requests
import sys
import time
import urllib2
import re
import time
import chardet
from http import *
from urllib import quote

#Auth Url
AUTH_URL = 'https://login.live.com/oauth20_authorize.srf?client_id=000000' \
           '004814F854&scope=wl.signin%20wl.offline_access%20onedrive.rea' \
           'dwrite&response_type=code&redirect_uri=&response_type=code'

#Just For test
CLIENT_ID = '000000004814F854'
CLIENT_SECRET = 'fLyMjHuJVlTjbcauWlJq1It-vX2-xHMW'

OAUTH_URI = 'https://login.live.com/oauth20_token.srf'
REDIRECT_URI = ''
AUTH_CODE = ''
API_URI = 'https://api.onedrive.com/v1.0/'
client = requests.Session()
client.verify = False

def env2utf8(str):
    return unicode(str, locale.getdefaultlocale()[1]).encode('utf-8')

class DriveHTTPClientException(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return 'FileUploadException %s' % self.message


class DriveHTTPClient(object):

    def __init__(self, refresh_token, on_debug=False):
        self.refresh_token = refresh_token
        self._requests = requests.Session()
        if on_debug is True:
            self._requests.verify = False
        self.access_token = self.update_access_token()

    def update_access_token(self):
        data = {'client_id':CLIENT_ID,
                'client_secret':CLIENT_SECRET,
                'refresh_token':self.refresh_token,
                'redirect_uri':REDIRECT_URI,
                'grant_type':'refresh_token'
                }
        response = client.post(OAUTH_URI, data=data)
        r = json.loads(response.text)
        if 'error' in r:
            print(r['error_description'])
        return r['access_token']

    def request(self, method='GET', **kwargs):
        for i in range(3):
            if i == 2:
                raise DriveHTTPClientException('Authentication failed')
            args = dict(kwargs)
            if 'headers' in args:
                args['headers']['Authorization'] = 'bearer ' + self.access_token
            else:
                args['headers'] = {'Authorization': 'bearer ' + self.access_token}
            ret = getattr(self._requests, method.lower())(**dict(args))
            if ret.status_code == 401:
                print 'Authentication failed update_access_token...'
                self.access_token = self.update_access_token()
                continue
            break
        return ret
    

class FileUploadException(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return 'FileUploadException %s' % self.message

class FileUploadProgress(object):
    def __init__(self, range_begin, size):
        self.range_begin = range_begin
        self.size = size

    def progress(self):
        if self.size == 0:
            return 0
        return self.range_begin/float(self.size)

class FileUploadIOBase(object):
    
    def __init__(self, fd):
        self.fd = fd
        self.fd.seek(0)

    def read(self, begin, end):
        self.fd.seek(begin)
        return self.fd.read(end - begin)

        
class LargeFileUpload(object):

    def __init__(self,
                 client,
                 file_path,
                 remote_path,
                 ):
        """
            session requestes.Session()
            file_path local_path
            remote_path test/text.txt
        """
        self.client = client
        self._file = FileUploadIOBase(open(file_path, 'rb'))
        self._file_size = os.path.getsize(file_path)
        if self._file_size == 0:
            raise FileUploadException('Empty File')
        self.remote_path = remote_path
        self.pieces_size = 1024 * 1024 * 10
        self.uploadUrl = None
        self.progress = None
    
    def _parse_nextExpectedRanges(self, val):
        """
            "nextExpectedRanges": "0-"
            "nextExpectedRanges": "-200"
            "nextExpectedRanges": "12345-55232"
        """
        r = re.findall('(\d+|())-(\d+|())', val)
        range_0 = r[0][0]
        range_1 = r[0][2]
        if len(range_0) == 0:
            end = self._file_size
            return max(0, end - int(range_1)), end
        if len(range_1) == 0:
            end = self._file_size
            return 0, end
        return int(range_0), int(range_1)
            

    def _calc_current_pieces(self, progress):
        """
            calc which pieces need transfer
        """
        pieces_end = progress.range_begin + self.pieces_size
        if pieces_end > progress.size:
            pieces_end = progress.size
        return progress.range_begin, max(0, pieces_end - 1)
    
    def next_range(self):

        if self.uploadUrl is None:
            #get upload url
            # quote %
            resp = self.client.request('POST', url = API_URI + 'drive/root:/%s:/upload.createSession' % (quote(self.remote_path)))
            print resp.text
            js = json.loads(resp.text)
            self.uploadUrl = js['uploadUrl']
            #get next range
            if 'nextExpectedRanges' in js:
                range_next = self._parse_nextExpectedRanges(js['nextExpectedRanges'][0])
                progress = FileUploadProgress(range_next[0], self._file_size)
                self.progress = progress
        else:
            #PUT a pieces
            pieces_begin, pieces_end = self._calc_current_pieces(self.progress)
            h = {'Content-Range': 'bytes %s-%s/%s' % (pieces_begin, pieces_end, self.progress.size)}
            print h
            resp = None
            #data mem buffer
            data = self._file.read(pieces_begin, pieces_end + 1)
            for i in range(500):
                try:
                    resp = self.client.request('PUT', url=self.uploadUrl, headers=h, data=data)
                    js = json.loads(resp.text)
                    if resp.status_code in [200, 201, 202]:
                        break
                    if 416 == resp.status_code:
                        #if last PUT not return will happen
                        print 'Message: %s' % js['error']['message']
                        break
                    if 404 == resp.status_code:
                        raise FileUploadException('Path Not Found')
                    if 400 <= resp.status_code < 500:
                        raise FileUploadException('Message: %s' % js['error']['message'])
                except Exception, e:
                    if isinstance(e, FileUploadException):
                        raise
                    sec = min(2*i, 60)
                    print 'after %s sec try again...' % sec
                    time.sleep(sec)
            if resp is None or resp.status_code not in [200, 201, 202]:
                raise FileUploadException('status_code:%s' % resp.status_code)
            if 'nextExpectedRanges' in js:
                #That should never happen
                raise FileUploadException('nextExpected Get Ranges Situation')
            else:
                #Documents http://onedrive.github.io/items/upload_large_files.htm are not right.
                #there is no "nextExpectedRanges": ["2355-"] in response
                #Ex.{"expirationDateTime":"2015-03-27T14:37:54.2600993+00:00"}
                progress = FileUploadProgress(pieces_end + 1, self._file_size)
                self.progress = progress
                #get nextExpectedRanges
                #resp = self.client.request('get', url=self.uploadUrl)
        resp = None
        if 'id' in js:
            resp = js
        return self.progress, resp

def upload(client, file_path, remote_path):
    t1 = time.time()
    try:
        upload = LargeFileUpload(client, file_path, remote_path)
        resp = None
        while resp is None:
            tt = time.time()
            progress, resp = upload.next_range()
            if progress:
                speed = 10240 / (time.time()-tt)
                print "Upload %d%% complete. Speed: %s KB/s" % (int(progress.progress() * 100), speed)
        print resp
    except Exception, e:
        import traceback
        traceback.print_exc()
        #print str(e)
    t2 = time.time()
    print 'total time %s' % (t2-t1)

def authorize():
    code = raw_input('Get Code Form Here:\n' + AUTH_URL + '\n\nYou will see error page. than input the code=')
    data = {'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code'
            }
    r = client.post(OAUTH_URI, data=data)
    r = json.loads(r.text)
    if 'error' in r:
        print(r['error_description'])
        sys.exit(0)
    else:
        refresh_token = r['refresh_token']
        with open('.token','w') as f:
            f.write(refresh_token)
        print("Authorization successful...")

def main():
    parser = argparse.ArgumentParser(description='To upload files to OneDrive')
    parser.add_argument('--auth', nargs=1,  help="Authorize this app by pasting the authorization code ")
    parser.add_argument('src', nargs='?', help='fie path in local')
    parser.add_argument('dest', nargs='?', help='fie path of the upload location in OneDrive')
    args = parser.parse_args()
    
    if args.auth:
        authorize()
        sys.exit(0)

    local_path = os.path.expanduser(env2utf8(args.src))
    client = DriveHTTPClient(open('.token', 'r').read(-1), True)
    upload(client, local_path, env2utf8(args.dest))
                
if __name__ == '__main__':
    main() 
