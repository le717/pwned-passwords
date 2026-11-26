# pwned-passwords
> Pwned Passwords API wrapper

## Purpose
This project provides a simple Python API around the
[Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords).

## Usage
```py
import pwned_passwords


# Check a password for pwned-ness
# password: bytes | str
result: pwned_passwords.PwnedResults = pwned_passwords.check("password")

# Check the results
print(result.is_pwned)  # bool
print(result.times_pwned)  # int

# options: pwned_passwords.PwnedOptions | None
result: pwned_passwords.PwnedResults = pwned_passwords.check(
    "password",
    options=pwned_passwords.PwnedOptions(
        add_padding=True,  # Pad the API response with empty records
        mode="ntlm",  # Get NTLM hashes instead of SHA-1
        get_hashes=True,  # By default, the response hashes are not provided
    ),
)

# Print all of the hashes
print(result.hashes)  # list[pwned_passwords.PwnedHash]
```

### Django password validator
A [Django password validator](https://docs.djangoproject.com/en/6.1/topics/auth/passwords/#module-django.contrib.auth.password_validation)
is provided to assist with integration pwned-passwords into your Django project.

```py
# In settings.py

AUTH_PASSWORD_VALIDATORS = [
    # ... The rest of your validators
    {
        "NAME": "pwned_passwords.django.PwnedPasswordsValidator",
        "OPTIONS": {
            "add_padding": False  # bool, default: False
            "mode": "sha-1", # str, "sha-1" | "ntlm", default: "sha-1"
            "get_hashes": False,  # bool, default: False
            "ignore_algo_error": False  # bool, default: False
        }
    },
]
```

The optional configuration keys follow the library configuration defaults.

Setting the `ignore_algo_error` option to `True` causes the validator to ignore an
`pwned_passwords.exceptions.UnsupportedAlgoError` exception and pass the password (fail-open).

### NTLM support
NTLM hash support is dependent on platform support. By default, Python's `hashlib` module will be
used if provided by the platform.

The `[ntlm]` install group can be used to guarantee NTLM hash support. This is enabled using
[pyspnego](https://pypi.org/project/pyspnego/).

If no NTLM support is available but that hash format is specified, an
`pwned_passwords.exceptions.UnsupportedAlgoError` exception will be raised.

It is strongly recommended to stick with the SHA-1 hash default.

## License
Pwned Passwords API, created and maintained at [Have I Been Pwned](https://haveibeenpwned.com/).

Have I Been Pwned is not affiliated with nor endorses this project.

2023, 2026 [MIT](LICENSE)
