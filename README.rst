Py FIDO
=======

This library handles the registration and verification of FIDO U2F tokens. It
is implemented such that the data storage component is implementer dependant.

This project targets Python 3.5 and above and takes advantage of type hinting
introduced in 3.5.

Don't use this in production(yet)!

```
FLASK_APP=fido_u2f.sample.flask FLASK_ENV=development flask run --cert ../server.crt --key ../server.key
```
