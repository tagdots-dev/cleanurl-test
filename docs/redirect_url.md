# ⭐ _redirect_url_

### ✅ Purpose: get redirected URL address.

<br>

```
Return the combination of protocol, fqdn, and port with redirection, if any.
```

<br>

### 💥 Running in Python interactive runtime environment

### Import client library
```
>>> from pkg_19544 import redirect_url
```

### Run redirect_url
```
>>> user_url = 'https://google.com/search?q=hello+world'

>>> redirect_url(user_url)
'https://www.google.com'
```

### Run redirect_url (append optional trailing path)
```
>>> user_url = 'https://example.com/search?q=hello+world'

>>> redirect_url(user_url, trailing_path='/v1')
'https://example.com/v1'
```

### Run redirect_url (append optional trailing path and enable log)
```
>>> user_url = 'https://invalid-url.com/search?q=hello+world'

>>> redirect_url(user_url, trailing_path='/v1', enable_log=True)
False
```
