Changelog
=========

v0.7.0 (2026-01-02)
-------------------

New Features
~~~~~~~~~~~~

- Add privacy-preserving by-hash keyring lookup. When standard key lookup
  fails, patatt now falls back to looking up keys at a SHA256 hash-based
  path (``by-hash/XX/YYY...``), avoiding exposure of email addresses in
  directory structures.

- Add comprehensive Sphinx documentation for ReadTheDocs hosting at
  https://patatt.docs.kernel.org

- Add PEP 561 compliance with ``py.typed`` marker for better IDE and
  type checker support.

- Add docstrings to all public classes and functions for improved IDE
  integration.

Improvements
~~~~~~~~~~~~

- Convert path handling to use ``pathlib.Path`` for cleaner code and
  better cross-platform compatibility.

- Refactor codebase to pass ``mypy --strict`` type checking.

- Add pytest test framework with unit tests.

- Use walrus operator for cleaner assign-and-check patterns.

- Improve SSH signing failure messages for better debugging.

- Hook now refuses to run on cover letter templates.

Bug Fixes
~~~~~~~~~

- Fix validation for OpenPGP signatures without embedded public key data.

- Fix compatibility with Python versions before 3.12 (avoid ``@deprecated``
  decorator).

- Fix subprocess file descriptor leak.

- Avoid spuriously reading git config in certain conditions.

- Fix non-writable GNUPGHOME handling.

- Fix header line splitting at 75 characters instead of 78.

Thanks
~~~~~~

- Paul Moore
- Tamir Duberstein

v0.6.3 (2023-01-25)
-------------------

- Fix header line splitting at 75 characters instead of 78.

v0.6.2 (2022-08-25)
-------------------

- Better fix for non-writable GNUPGHOME handling.

v0.6.1 (2022-08-25)
-------------------

- Use NamedTemporaryFile for GPG keyring creation to fix issues with
  non-writable GNUPGHOME.

v0.6.0 (2022-08-22)
-------------------

- Initial stable release with support for ed25519, OpenPGP, and OpenSSH
  signature algorithms.
