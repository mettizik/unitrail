from logging import debug


def create_testrun(client, mapping):
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
    debug('{} unique sections selected'.format(len(sections_ids)))

    debug('Loading cases for selected sections...')
    cases = [case for case in client.get_cases() if case['section_id']
             in sections_ids]

    filtered_cases = []
    debug('Loaded {} cases totally'.format(len(cases)))
    if 'case' in condition:
        filtered_cases = apply_case_filter(cases, condition['case'])
    else:
        filtered_cases = cases
    debug('{} unique cases selected'.format(len(filtered_cases)))
    debug('Creating new testrun for selected cases')
    case_ids = [x['id'] for x in filtered_cases]

    return client.add_run(mapping['testrun']['name'],
                          mapping['testrun']['description'], case_ids)


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
