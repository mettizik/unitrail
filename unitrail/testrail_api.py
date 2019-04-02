#
# TestRail API binding for Python 3.x (API v2, available since
# TestRail 3.0)
#
# Learn more:
#
# http://docs.gurock.com/testrail-api2/start
# http://docs.gurock.com/testrail-api2/accessing
#
# Copyright Gurock Software GmbH. See license.md for details.
#

import urllib.request
import urllib.error
from urllib import parse
import json
import base64


class APIClient:
    def __init__(self, project_id, url='localhost', user='admin', password='admin'):
        self.user = user
        self.password = password
        self.__url = url

        # The ID of Oxygen: OxyClouds project in TestRail is 5
        self.__project_id = project_id

    #
    # Send Get
    #
    # Issues a GET request (read) against the API and returns the result
    # (as Python dict).
    #
    # Arguments:
    #
    # uri                 The API method to call including parameters
    #                     (e.g. get_case/1)
    #
    def send_get(self, uri):
        return self.__send_request('GET', uri, None)

    #
    # Send POST
    #
    # Issues a POST request (write) against the API and returns the result
    # (as Python dict).
    #
    # Arguments:
    #
    # uri                 The API method to call including parameters
    #                     (e.g. add_case/1)
    # data                The data to submit as part of the request (as
    #                     Python dict, strings must be UTF-8 encoded)
    #
    def send_post(self, uri, data=None):
        return self.__send_request('POST', uri, data)

    def __send_request(self, method, uri, data):
        url = self.__url + uri
        request = urllib.request.Request(url)
        if (method == 'POST'):
            request.data = bytes(json.dumps(data), 'utf-8')
        auth = str(
            base64.b64encode(
                bytes('%s:%s' % (self.user, self.password), 'utf-8')
            ),
            'ascii'
        ).strip()
        request.add_header('Authorization', 'Basic %s' % auth)
        request.add_header('Content-Type', 'application/json')

        e = None
        try:
            response = urllib.request.urlopen(request).read()
        except urllib.error.HTTPError as ex:
            response = ex.read()
            e = ex

        if response:
            result = json.loads(response.decode("utf-8"))
        else:
            result = {}

        if e != None:
            if result and 'error' in result:
                error = '"' + result['error'] + '"'
            else:
                error = 'No additional error message received'
            raise APIError('TestRail API returned HTTP %s (%s)' %
                           (e.code, error))

        return result

    def get_cases(self, **kwargs):
        return self.send_get('get_cases/%s&%s' % (self.__project_id, parse.urlencode(kwargs)))

    def get_sections(self, **kwargs):
        return self.send_get('get_sections/%s&%s' % (self.__project_id, parse.urlencode(kwargs)))

    def add_run(self, name, description, case_ids):
        data = {
            'name': name,
            'description': description,
            'include_all': 0,
            'case_ids': case_ids
        }
        return self.send_post('add_run/' + self.__project_id, data)

    def get_run(self, testrun_id):
        return self.send_get('get_run/{}'.format(testrun_id))

    def close_run(self, testrun_id):
        return self.send_post('close_run/{}'.format(testrun_id))

    def get_tests(self, testrun_id):
        return self.send_get('get_tests/{}'.format(testrun_id))

    def send_results(self, test_id, **kwargs):
        return self.send_post('add_result/%s' % test_id, kwargs)


class APIError(Exception):
    pass
