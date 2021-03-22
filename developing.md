(WIP)

The auth server now sets SameSite=None on the Flask session cookies.
However, browsers will ignore them unless they are also marked Secure...
So we do that too. This means you need a cert for local development.

The easiest way (in the current branch) is to use the first method here:

https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https

```python
if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

This will now serve the app over https, but without a proper certificate.

So before you do anything, visit https://127.0.0.1:5000/index.json and bypass all the warnings.

Then you can load it into a client and it will work:

https://digirati-co-uk.github.io/iiif-auth-client/?sources=https://127.0.0.1:5000/index.json

There will be nasty "not secure" warnings, but this now mimics a live SSL environment.

You can also use self-signed certificates as in the above example.


