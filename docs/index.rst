patatt: Cryptographic Patch Attestation
=======================================

Patatt is a Python library and CLI for adding end-to-end cryptographic
attestation to patches sent via email. It adapts the DKIM email signature
standard to include cryptographic signatures via the ``X-Developer-Signature``
email header.

If your project workflow doesn't use patches sent via email, then you
don't need this and should simply start signing your tags and commits.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   overview
   contributor-guide
   maintainer-guide
   api
   faq

Quick Start
-----------

Install from PyPI using pipx (recommended)::

    pipx install patatt

Or with pip::

    pip install --user patatt

Generate a new ed25519 signing key::

    patatt genkey

Sign a patch::

    git format-patch -1 --stdout | patatt sign > signed-patch.eml

Validate a signed patch::

    patatt validate signed-patch.eml

Features
--------

- DKIM-like signature headers that don't corrupt patch content
- Multiple signing algorithms: ed25519, OpenPGP, OpenSSH
- In-repository keyring management via git refs
- Automatic signing via git sendemail-validate hook
- Privacy-preserving by-hash key lookup

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
