# ⭐ method: _sanitize_url_

### ✅ Purpose: sanitize URL.

Return sanitized URL
```
1. removes control characters.
2. encodes URL components (path, query, fragment).
```

<br>

### 💥 Running in Python interactive runtime environment

### Import client library
```
>>> from pkg_19544 import sanitize_url
```

### Run sanitize_url
```
>>> user_url = 'https://google.com/path1/path2/search?key1=value1&key2=value2#section'

>>> sanitize_url(user_url)
'https://google.com/path1/path2/search?key1=value1&key2=value2#section'
```

### Run sanitize_url (remove control characters)
```
>>> user_url = 'https://google.com/path1/path2/search?key1=value1&key2=abc\r\ndefg#section'

>>> sanitize_url(user_url)
'https://google.com/path1/path2/search?key1=value1&key2=abcdefg#section'
```

### Run sanitize_url (remove control characters and encode URL)
```
>>> user_url = 'https://google.com/path1/path2/search?key1=value1&key2=abc\r\ndef$g#section'

>>> sanitize_url(user_url)
'https://google.com/path1/path2/search?key1=value1&key2=abcdef%24g#section'
```
