patatt: cryptographic patch attestation for the masses
======================================================

Patatt is a Python library and CLI for adding end-to-end cryptographic
attestation to patches sent via email. It adapts the DKIM email signature
standard to include cryptographic signatures via the ``X-Developer-Signature``
header.

If your project workflow doesn't use patches sent via email, then you
don't need this and should simply start signing your tags and commits.

Features
--------

- DKIM-like signature headers that don't corrupt patch content
- Multiple signing algorithms: ed25519, OpenPGP, OpenSSH
- In-repository keyring management via git refs
- Automatic signing via git sendemail-validate hook

Installation
------------

Install using pipx (recommended)::

    pipx install patatt

Or with pip::

    pip install --user patatt

Quick Start
-----------

Generate a new ed25519 signing key::

    patatt genkey

Sign a patch::

    git format-patch -1 --stdout | patatt sign > signed.patch

Validate a signed patch::

    patatt validate signed.patch

Documentation
-------------

Full documentation is available at https://patatt.docs.kernel.org

Contributing
------------

Please send patches and support requests to tools@kernel.org.

Submissions must be made under the terms of the Linux Foundation
certificate of contribution and should include a Signed-off-by line.
See the DCO file for details.
