Overview
========

Basic Concepts
--------------

DKIM is a widely adopted standard for domain-level attestation of email
messages. It works by hashing the message body and certain individual
headers, and then creating a cryptographic signature of the resulting
hash. The receiving side obtains the public key of the sending domain
from its DNS record and checks the signature and header/body hashes. If
the signature verifies and the resulting hashes are identical, then
there is a high degree of assurance that neither the body of the message
nor any of the signed headers were modified in transit.

Patatt uses the exact same DKIM standard to hash the headers and the body
of the patch message, but uses a different set of fields and canonicalization
routines:

- the ``d=`` field is not used (no domain signatures involved)
- the ``q=`` field is not used (key lookup is left to the client)
- the ``c=`` field is not used (see below for canonicalization)
- the ``i=`` field is optional, but MUST be the canonical email address of
  the sender, if not the same as the From: field

Canonicalization
----------------

Patatt uses the "relaxed/simple" canonicalization as defined by the DKIM
standard, but the message is first parsed by the ``git-mailinfo`` command
in order to achieve the following:

- normalize any content-transfer-encoding modifications (convert back
  from base64/quoted-printable/etc into 8-bit)
- use any encountered in-body From: and Subject: headers to
  rewrite the outer message headers
- perform the subject-line normalization in order to strip content not
  considered by git-am when applying the patch (i.e. drop ``[PATCH .*]`` and
  other bracketed prefix content)

To achieve this, the message is passed through git-mailinfo with the
following flags::

    cat orig.msg | git mailinfo --encoding=utf-8 --no-scissors m p > i

Patatt then uses the data found in "i" to replace the From: and Subject:
headers of the original message, and concatenates "m" and "p" back
together to form the body of the message, which is then normalized using
CRLF line endings and the DKIM "simple" body canonicalization (any
trailing blank lines are removed).

Any other headers included in signing are modified using the "relaxed"
header canonicalization routines as defined in the DKIM RFC.

In other words, the body and some of the headers are normalized and
reconstituted using the ``git-mailinfo`` command, and then canonicalized
using DKIM's relaxed/simple standard.

Supported Signature Algorithms
------------------------------

DKIM standard mostly relies on RSA signatures, though RFC 8463 extends
it to support ED25519 keys as well. While it is possible to use any of
the DKIM-defined algorithms, patatt only supports the following
signing/hashing schemes:

ed25519-sha256
    Exactly as defined in RFC8463. Uses PyNaCl for cryptographic operations.

openpgp-sha256
    Uses OpenPGP (GnuPG) to create the signature. Can use any key type
    supported by GnuPG, including EDDSA keys.

openssh-sha256
    Uses OpenSSH signing capabilities (requires OpenSSH 8.0+). Supports
    passphrase-protected keys and hardware tokens (ed25519-sk).

.. note::

    Since GnuPG supports multiple signing key algorithms, openpgp-sha256
    signatures can be done using EDDSA keys as well. However, since OpenPGP
    output includes additional headers, the "ed25519-sha256" and
    "openpgp-sha256" schemes are not interchangeable even when ed25519 keys
    are used in both cases.

.. note::

    OpenSSH signature support was added in OpenSSH 8.0 and requires
    ssh-keygen that supports the ``-Y`` flag.

X-Developer-Key Header
----------------------

Patatt adds a separate ``X-Developer-Key:`` header with public key
information. It is merely informational and ISN'T and SHOULDN'T be used
for performing any kind of message validation (for obvious reasons). It
is included to make it easier for maintainers to obtain the
contributor's public key before performing whatever necessary
verification steps prior to its inclusion into their individual or
project-wide keyrings.

This also allows keeping a historical record of contributor keys via
list archive services such as lore.kernel.org and others.
