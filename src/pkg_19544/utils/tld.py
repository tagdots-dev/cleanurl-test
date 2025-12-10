from urllib import error, request

from pkg_19544.configs.constants import TLD_LIVE_SOURCE, TLD_TEMP_FALLBACK


def get_tlds() -> list:
    try:
        with request.urlopen(TLD_LIVE_SOURCE) as response:
            html_bytes = response.read()
            html_string = html_bytes.decode('utf-8')
            list_tld = html_string.splitlines()[1:]
            return list_tld

    except (error.URLError, ValueError):  # pragma: no cover
        return TLD_TEMP_FALLBACK
