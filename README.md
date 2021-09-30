Allows reading macOS/iOS/iphoneOS/ipadOS `.binarycookie` files.

Based on http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/


```py
from binarycookie import parse

COOKIE_FILE = '/Users/luckydonald/Library/Cookies/Cookies.binarycookies'
# you may need to make a duplicate of that file to your desktop (or similar) due to macOS security blocking access in system folders.

with open(COOKIE_FILE, 'rb') as file:
    cookies = parse(file)
# end with

print(cookies)
```

Which may result in something like
```py
[
    Cookie(
        name='cookie_check', value='yes', domain='.paypal.com', path='/',
        expiry_date='Thu, 28 Sep 2028', cookie_flags='Secure; HttpOnly'
    ),
    Cookie(
        name='mobileClient', value='ios', domain='help.steampowered.com', path='/',
        expiry_date='Sat, 13 Sep 2031', cookie_flags='Unknown'
    ),
]
```
