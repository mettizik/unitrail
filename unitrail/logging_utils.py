import logging


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
