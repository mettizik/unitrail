from logging import debug, info, warn
from junitparser import JUnitXml, TestCase, Failure, Skipped, Error
from testrail_api import APIClient
from enum import Enum


class TestStatus(Enum):
    Passed = 1
    Blocked = 2
    Untested = 3
    Retest = 4
    Failed = 5


def get_case_status(result: TestCase) -> TestStatus:
    return {
        'Failure': TestStatus.Failed,
        'Error': TestStatus.Failed,
        'Skipped': TestStatus.Untested,
        'NoneType': TestStatus.Passed
    }[result.result.__class__.__name__]


def result_to_payload(result: TestCase):
    payload = {}
    payload['status_id'] = get_case_status(result).value
    if payload['status_id'] != TestStatus.Untested:
        payload['comment'] = """
            Testsuite: {}
            Testcase: 
                {}
            ===========================
            Message: 
                {}
            Results details: 
                {}
            """.format(
            result.classname,
            result.name,
            '{}: {}'.format(
                result.result.type, result.result.message) if result.result is not None else 'Passed',
            result.result._elem.text if result.result is not None else ''
        )

    return payload


def push_results(results, testrail: APIClient):
    total_count = len(results.items())
    current_item = 0
    submitted_results = 0
    for test_id, related_info in results.items():
        results = related_info['results']
        test = related_info['test']
        if results:
            debug('Processing test "{}", found {} related result{}'.format(
                test['title'], len(results), '' if len(results) == 1 else 's'))
            for result in results:
                payload = result_to_payload(result)
                if payload['status_id'] != TestStatus.Untested.value:
                    testrail.send_results(test_id, **payload)

            submitted_results += 1
        current_item += 1
        debug('{}% cases processed'.format(
            int((current_item / total_count) * 100)))
    info('Submitted {} results to testrail. Estimated coverage: {}%'.format(
        submitted_results, int((submitted_results / total_count) * 100)))
