# configs/constants.py

BLACKLIST_CONTROL_CHARACTERS = ['\n', '\r']
BLACKLIST_CIPHERS = ['ANON', 'EXPORT', 'NULL']
SOCKET_TIMEOUT = 5
TLD_LIVE_SOURCE = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TLD_TEMP_FALLBACK = [
    'COM', 'NET', 'ORG', 'AI', 'AT', 'AU', 'BE', 'BR', 'CA', 'CC', 'CH', 'CN', 'CO',
    'DE', 'ES', 'EU', 'FR', 'IN', 'IO', 'IR', 'IT', 'JP', 'NL', 'RU', 'UK', 'US',
]
WHITELIST_CHARS_IN_FQDN = r"^[a-zA-Z0-9\.\-]+$"
WHITELIST_HASHING_ALG = ('SHA256', 'SHA384', 'SHA512')
WHITELIST_SCHEME = ('https://')
WHITELIST_TLS_VERSION = ['TLSv1.3']
