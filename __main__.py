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

    sections_ids = list(set([section['id'] for section in sections_to_parse]))
    info('{} unique sections selected'.format(len(sections_ids)))
    debug('Loading cases for selected sections...')
    cases = [case for case in client.get_cases() if case['section_id']
             in sections_ids]

    filtered_cases = []
    debug('Loaded {} cases totally'.format(len(cases)))
    if 'case' in condition:
        filtered_cases.append(apply_case_filters(cases, condition['case']))


def collect_children_sections(sections, filtered_sections):
    children = []
    for accepted_section in filtered_sections:
        children += [
            section for section in sections if section['parent_id'] == accepted_section['id']]
        if children:
            debug('{} are children of {}'.format(
                [x['name'] for x in children], accepted_section['name']))
            children += collect_children_sections(sections, children)

    return children


def apply_case_filters(cases, conditions):
    results = []
    for condition in conditions:
        results += apply_case_filter(cases, condition)

    return results


def apply_case_filter(cases, condition):
    results = []
    debug('Applying case filter...')
    for filter_key, filter_value in condition.items():
        debug('Applying {} filter condition "{}"'.format(
            filter_key, filter_value))
        results += [
            x for x in cases if filter_key in x and x[filter_key] == filter_value]
    debug('Filtered {} cases to {}'.format(len(cases), len(results)))
    return results


def apply_section_filters(sections, conditions):
    results = []
    for condition in conditions:
        results += apply_section_filter(sections, condition)

    return results


def apply_section_filter(sections, condition):
    results = []
    debug('Applying section filter...')
    if 'name' in condition:
        debug('Applying name filter condition "{}"'.format(condition['name']))
        results = [x
                   for x in sections if x['name'].lower() == condition['name'].lower()]
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

    options = parser.parse_args()
    main(options)
