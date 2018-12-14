import re
from argparse import ArgumentParser, FileType, Action
from json import load
from logging import DEBUG, INFO, debug, info

from junitparser import JUnitXml, TestCase, TestSuite

from logging_utils import initialize_logger
from results_formatter import push_results
from testrail_api import APIClient
from testrail_filter import (apply_case_filter, apply_section_filter,
                             collect_children_sections, create_testrun)


def main(options):
    initialize_logger(loglevel=DEBUG if options.verbose else INFO)
    debug('Verbose logging is enabled')
    mapping = collect_full_mapping(options)
    debug(mapping)
    project_id = mapping["project"]
    client = APIClient(project_id, url=options.server, user=options.username,
                       password=options.password)

    if not options.testrun:
        info('Creating new test run since there is no testrun provided')
        testrun = create_testrun(client, mapping)
    else:
        info('Loading testrun {}'.format(options.testrun))
        testrun = client.get_run(options.testrun)

    testrun_id = testrun['id']
    info(
        ' -> Working with testrun ({}) "{}"'.format(testrun_id, testrun['name']))
    info(' -> See it in browser {}'.format(testrun['url']))

    tests = client.get_tests(testrun_id)

    test_results = read_test_results_from_report(options.reports)

    info('Mapping execution results to TestRail cases')
    mapped_results = map_results_to_cases(
        test_results, tests, mapping['mapping'])
    info('Pushing execution results to TestRail...')
    push_results(mapped_results, client)
    info('Test execution results are pushed to test run {}'.format(
        testrun['url']))


def key_val_to_dict(keys, value, output_dict):
    if keys:
        try:
            attr = output_dict[keys[0]]
        except KeyError:
            attr = None
        debug('{}: {}'.format(keys[0], attr))
        if type(attr) == dict:
            output_dict[keys[0]] = key_val_to_dict(keys[1:], value, attr)
        else:
            output_dict[keys[0]] = value

    return output_dict


def collect_full_mapping(options):
    original_mapping = load(options.mapping)
    for keystring, value in options.defines.items():
        keys = keystring.split('.')
        original_mapping = key_val_to_dict(keys, value, original_mapping)
    return original_mapping


def read_test_results_from_report(reports):
    test_results = []
    for report in reports:
        xml = JUnitXml.fromfile(report)
        for suite in xml:
            if type(suite) == TestSuite:
                debug('Parsed testsuite: {}'.format(suite.name))
                debug('Parsed {} test results'.format(len(suite)))
                test_results += [case for case in suite]
            elif type(suite) == TestCase:
                debug('Parsed testsuite: {}'.format(suite.name))
                debug('Parsed {} test results'.format(1))
                test_results += [suite]
    return test_results


def map_results_to_cases(test_results, tests, mapping):
    results = {}
    for test in tests:
        results[test['id']] = {
            'test': test,
            'results': get_results_for_test(test, test_results, mapping)
        }

    return results


def get_results_for_test(test, results, mapping):
    related_results = []
    if len(mapping) == 0 or 'case2test' in mapping:
        related_results += [
            result for result in results if result.name.lower() == test['title'].lower()]
    for mapper in [m for m in mapping if type(m) == dict]:
        mapped_results = []
        if mapper['case'] == test['title']:
            for pattern in mapper['tests']:
                title_pattern = re.compile(pattern.lower())
                mapped_results += [
                    result for result in results if title_pattern.match(result.name.lower())]
        related_results += merge_results(mapped_results, mapper)
    return related_results


def merge_results(mapped_results, mapper):
    merged = []
    matcher = mapper['matcher']
    if matcher == 'any':
        for result in mapped_results:
            if result.result is None:
                return [result]
    return merged


class StoreNameValuePair(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not getattr(namespace, 'defines'):
            setattr(namespace, 'defines', {})
        defines = getattr(namespace, 'defines')
        if type(values) != list:
            values = [values]
        for value in values:
            k, v = value.split('=')
            defines[k] = v


if __name__ == "__main__":
    parser = ArgumentParser(
        "testrail-unit", description="Fill test run in Testrail using xUnit XML report generated by automated tests")
    parser.add_argument(
        '-r', '--reports',
        required=True,
        nargs="+",
        type=str,
        help='xUnit reports to handle')
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Make logs verbose')

    parser.add_argument(
        '-s', '--server',
        type=str,
        default='http://testrail/index.php?/api/v2/',
        help='Set TestRail server address')

    parser.add_argument(
        '-u', '--username',
        type=str,
        default='durshlag-script',
        help='Username to authenticate in TestRail')

    parser.add_argument(
        '-p', '--password',
        type=str,
        default='EeDaN3C56g',
        help='Password to authenticate in TestRail')

    parser.add_argument(
        '-m', '--mapping',
        type=FileType('r', encoding='UTF-8'),
        required=True,
        help='JSON file with mapping of the testcases in report to scenarios in testrail')

    parser.add_argument(
        '-t', '--testrun',
        type=str,
        help='Existing testrun ID, if not exists - new one will be created'
    )

    parser.add_argument(
        '-D', '--defines',
        action=StoreNameValuePair,
        nargs='+',
        required=False,
        help='Define mapping parameters in dynamic from commandline'
    )

    options = parser.parse_args()
    main(options)
