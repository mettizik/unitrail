import re
from json import load
from logging import debug, info, error
from junitparser import JUnitXml, TestCase, TestSuite


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


def get_matched_tests(test, case_pattern, mapper_tests, results):
    if case_pattern.match(test['title'].lower()):
        for tests_pattern in mapper_tests:
            title_pattern = re.compile(tests_pattern.lower())
            return [result for result in results if title_pattern.match(result.name.lower())]
    return []


def get_results_for_test(test, results, mapping):
    related_results = []
    if len(mapping) == 0 or 'case2test' in mapping:
        related_results += [
            result for result in results if result.name.lower() == test['title'].lower()]
    for mapper in [m for m in mapping if type(m) == dict]:
        mapped_results = []
        if type(mapper['case']) == str:
            case_pattern = re.compile(mapper['case'].lower())
            mapped_results += get_matched_tests(test,
                                                case_pattern, mapper['tests'], results)
        elif type(mapper['case']) == list:
            for case in mapper['case']:
                case_pattern = re.compile(case.lower())
                mapped_results += get_matched_tests(test,
                                                    case_pattern, mapper['tests'], results)
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
