from argparse import ArgumentParser, FileType
import logging
from logging import debug, info, warn
from junitparser import JUnitXml
from testrail_api import APIClient
from json import load


class LogFormatter(logging.Filter):
    def filter(self, record):
        labels_dict = {
            logging.DEBUG: '[.]',
            logging.INFO: '[+]',
            logging.WARN: '[!]',
            logging.ERROR: '[-]',
            logging.FATAL:    '[ FATAL! ]',
            logging.CRITICAL: '[CRITICAL]'
        }
        record.level_label = labels_dict[record.levelno]

        return True


def initialize_logger(loglevel=logging.INFO, **kwargs):
    """
    Create a logger with specified name and loglevel
    """
    logger = logging.getLogger()

    logger.addFilter(LogFormatter())
    syslog = logging.StreamHandler()
    formatter = logging.Formatter('%(level_label)s %(message)s')
    syslog.setFormatter(formatter)
    logger.addHandler(syslog)
    logger.setLevel(loglevel)


def dump_report(options):
    for report in options.reports:
        try:
            xml = JUnitXml.fromfile(report)
            for suite in xml:
                debug('Parsed testsuite: {}'.format(suite.name))
                for case in suite:
                    debug('Parsed testcase: {} [{}]'.format(
                        case.name, case.result))
                    if case.result is not None:
                        debug('Result - {}: {}'.format(
                            case.result.type, case.result.message))
                        debug('Result - {}: {}'.format(
                            case.result.type, case.result._elem.text))
                    debug('Output: {} [{}]'.format(
                        case.name, case.system_out))
                    debug('Error: {} [{}]'.format(
                        case.name, case.system_err))
                info(suite.tests)
                info(suite.failures)
                info(suite.errors)
        except Exception as error:
            warn('Failed to parse report "{}". Error: {}'.format(report, error))


def main(options):
    initialize_logger(
        loglevel=logging.DEBUG if options.verbose else logging.INFO)
    debug('Verbose logging is enabled')
    mapping = load(options.mapping)
    project_id = mapping["project"]
    client = APIClient(project_id, url=options.server, user=options.username,
                       password=options.password)

    testrun = None
    if not options.testrun:
        debug('Loading test sections from TestRail...')
        sections = client.get_sections()
        filtered_sections = []
        debug('Done!')
        condition = mapping['filters']
        if 'section' in condition:
            filtered_sections = apply_section_filter(
                sections, condition['section'])
        debug('{} root sections are selected'.format(len(filtered_sections)))

        sections_to_parse = []
        for filtered_section in filtered_sections:
            sections_to_parse += collect_children_sections(
                sections, [filtered_section])
            sections_to_parse += [filtered_section]

        sections_ids = list(set([section['id']
                                 for section in sections_to_parse]))
        info('{} unique sections selected'.format(len(sections_ids)))
        debug('Loading cases for selected sections...')
        cases = [case for case in client.get_cases() if case['section_id']
                 in sections_ids]

        filtered_cases = []
        debug('Loaded {} cases totally'.format(len(cases)))
        if 'case' in condition:
            filtered_cases = apply_case_filter(cases, condition['case'])

        info('{} unique cases selected'.format(len(filtered_cases)))

        debug('Creating new testrun for cases {}'.format(filtered_cases))
        case_ids = [x['id'] for x in filtered_cases]

        testrun = client.add_run(mapping['testrun']['name'],
                                 mapping['testrun']['description'], case_ids)
    else:
        info('Loading testrun {}'.format(options.testrun))
        testrun = client.get_run(options.testrun)

    testrun_id = testrun['id']
    info(
        ' -> Working with testrun ({}) "{}"'.format(testrun_id, testrun['name']))
    info(' -> See it in browser {}'.format(testrun['url']))

    tests = client.get_tests(testrun_id)
    info(tests)


def collect_children_sections(sections, filtered_sections):
    results = []
    for accepted_section in filtered_sections:
        children = [
            section for section in sections if section['parent_id'] == accepted_section['id']]

        debug('There are {} children of {}'.format(
            len(children), accepted_section['name']))
        if children:
            results += children
            results += collect_children_sections(sections, children)

    return results


def apply_plain_filter(collection, condition):
    results = []
    for filter_key, filter_value in condition.items():
        debug('Applying {} filter condition "{}"'.format(
            filter_key, filter_value))
        for item in collection:
            if filter_key in item and item[filter_key] == filter_value:
                results.append(item)

    return results


def apply_case_filter(cases, condition):
    results = []
    debug('Applying case filter...')
    results = apply_plain_filter(cases, condition)
    debug('Filtered {} cases to {}'.format(len(cases), len(results)))
    return results


def apply_section_filter(sections, condition):
    results = []
    debug('Applying section filter...')
    results = apply_plain_filter(sections, condition)
    debug('Filtered {} sections to {}'.format(len(sections), len(results)))
    return results


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

    options = parser.parse_args()
    main(options)
