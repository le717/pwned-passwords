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

**Note**: NTLM hash support is dependent on platform support, with fallback support provided by [pyspnego](https://pypi.org/project/pyspnego/). It is recommended to stick with the SHA-1 hash default.


## License
Pwned Passwords API, created and maintained at [Have I Been Pwned](https://haveibeenpwned.com/).

Have I Been Pwned is not affiliated with nor endorses this project.

2023 [MIT](LICENSE)
