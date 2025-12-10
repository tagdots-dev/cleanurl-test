LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'loggers': {
        'default': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
            'level': 'DEBUG',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'maxBytes': 50000,
            'backupCount': 2,
            'filename': 'app.log',
            'formatter': 'json',
            'level': 'DEBUG',
        },
    },
    'formatters': {
        'json': {
            'format': '{"_t": "%(asctime)s.%(msecs)03d", "_l": "%(levelname)s", "_f": "%(funcName)s", "_m": "%(filename)s:%(lineno)s", "_d": "%(message)s"}',  # noqa: E501
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
}
