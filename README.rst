patatt: cryptographic patch attestation for the masses
======================================================

This utility allows an easy way to add end-to-end cryptographic
attestation to patches sent via mail. It does so by adapting the DKIM
email signature standard to include cryptographic developer signatures
via a separate X-Developer-Signature email header.

Basic concepts
--------------
DKIM is a widely adopted standard for domain-level attestation of email
messages. It works by hashing the message body and certain individual
headers, and then creating a cryptographic signature of the resulting
hash. The receiving side then downloads the public key of the sending
domain from its DNS record and checks the signature and header/body
hashes. If the signature verifies and the resulting hashes are
identical, then there is a high degree of assurance that neither the
body of the message nor any of the signed headers were modified in
transit.

This utility uses the exact same DKIM standard to hash the headers and
the body of the patch message, but uses a different set of fields and
canonicalization routines:

  - the d= field is not used (no domain signatures involved)
  - the q= field is not used (key lookup is handled differently)
  - the c= field is not used (see below for canonicalization)
  - the i= field is optional, but MUST be the canonical email address of
    the sender, if not the same as the From: field

Canonicalization
~~~~~~~~~~~~~~~~
Patatt uses the "relaxed/simple" canonicalization as defined by the DKIM
standard, but the message is first parsed by "git-mailinfo" in order to
achieve the following:

  - normalize any content-transfer-encoding modifications (convert back
    from base64/quoted-printable/etc into 8-bit)
  - use any encountered in-body From: and Subject: headers to
    rewrite the outer message headers
  - perform any subject-line normalization in order to strip content not
    considered by git-am when applying the patch

To achieve this, the message is passed through git-mailinfo with the
following flags::

    cat orig.msg | git mailinfo --encoding=utf-8 m p > i

Patatt then uses the data found in "i" to replace the From: and Subject:
headers of the original message, and concatenates "m" and "p" back
together to form the body of the message, which is then normalized using
CRLF line endings and the DKIM "simple" body canonicalization (any
trailing blank lines are removed).

Any other headers included in signing are canonicalized using the
"relaxed" header canonicalization routines defined in the DKIM standard.

In other words, the body and some of the headers are normalized and
reconstituted using the "git-mailinfo" command, and then canonicalized
using DKIM's relaxed/simple standard.

Supported Signature Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DKIM standard mostly relies on RSA signatures, though RFC 8463 extends
it to support ED25519 keys as well. While it is possible to use any of
the DKIM-defined algorithms, patatt only supports the following
two signing/hashing schemes:

  - ed25519-sha256: exactly as defined in RFC8463
  - openpgp-sha256: uses OpenPGP to create the signature

X-Developer-Key header
~~~~~~~~~~~~~~~~~~~~~~
Patatt adds a separate ``X-Developer-Key:`` header with public key
information. It is merely informational and ISN'T and SHOULDN'T be used
for performing any kind of message validation (for obvious reasons). It
is included to make it easier for maintainers to obtain the
contributor's public key for performing whatever necessary
verification steps prior to including it into their individual or
project-wide keyrings.

Getting started as contributor
------------------------------
It is very easy to start signing your patches with patatt.

Installing
~~~~~~~~~~
You can install from pip::

    pip install --user patatt

Make sure your PATH includes $HOME/.local/bin.

Alternatively, you can clone the repository and symlink patatt.sh into
your path::

    cd bin
    ln -s ~/path/to/patatt/patatt.sh patatt

After this, you should be able to run ``patatt --help`` without
specifying the full path to the repository.

Using PGP
~~~~~~~~~
If you already have a PGP key, you can simply start using it to sign
patches. Add the following to your ~/.gitconfig::

    [patatt]
        signingkey = openpgp:KEYID

The KEYID should be the 16-character identifier of your key, for
example::

    [patatt]
        signingkey = openpgp:E63EDCA9329DD07E

Using ed25519
~~~~~~~~~~~~~
If you don't already have a PGP key, you can opt to generate and use an
ed25519 key instead (see below for some considerations on pros and cons
of PGP vs ed25519 keys).

To generate a new keypair, run::

    patatt genkey

You will see an output similar to the following::

    Generating a new ed25519 keypair
    Wrote: /home/user/.local/share/patatt/private/20210505.key
    Wrote: /home/user/.local/share/patatt/public/20210505.pub
    Wrote: /home/user/.local/share/patatt/public/ed25519/example.org/user/default
    Add the following to your .git/config (or global ~/.gitconfig):
    ---
    [patatt]
        signingkey = ed25519:20210505
    ---
    Next, communicate the contents of the following file to the
    repository keyring maintainers for inclusion into the project:
    /home/user/.local/share/patatt/public/20210505.pub

Please make sure to back up your private key, located in ``~/.local/share/patatt/private``.
It is short enough to simply print out.

Next, just do as instructions say. If the project to which you are
contributing patches already uses patatt attestation, please work with
the project maintainers to add your public key to the repository. If
they aren't yet using patatt, just start signing your patches and
hopefully the project will start keeping its own keyring in the future.

Testing if it's working
~~~~~~~~~~~~~~~~~~~~~~~
To test if it's working::

    $ git format-patch -1 --stdout | patatt sign > /tmp/test

If you didn't get an error message, then the process was successful. You
can review /tmp/test to see that X-Developer-Signature and
X-Developer-Key headers were successfully added.

You can now validate your own message::

    $ patatt validate /tmp/test

Automatic signing via the sendemail-validate hook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If everything is working well, you can start automatically signing all
outgoing patches sent via git-send-email::

    $ echo 'patatt sign --hook "{$1}"' > .git/hooks/sendemail-validate
    $ chmod a+x .git/hooks/sendemail-validate

PGP vs ed25519 keys
~~~~~~~~~~~~~~~~~~~
If you don't already have a PGP key, you may wonder whether it makes
sense to create a new PGP key or start using standalone ed25519 keys.

Reasons to choose PGP:

- you can protect the PGP private key with a passphrase (gpg-agent will
  manage it for you)
- you can move your PGP key to an OpenPGP-compliant smartcard to further
  protect your key from being leaked/stolen
- you can use your PGP keys to sign git tags/commits, not just patches

If you choose to create a new PGP key, you can follow the following
guide:
https://github.com/lfit/itpol/blob/master/protecting-code-integrity.md

Reasons to choose standalone ed25519 keys:

- much smaller signatures, especially compared to PGP RSA keys
- implements the DKIM ed25519 signing standard
- faster crypto

If you choose ed25519 keys, you will need to make sure that PyNaCl is
installed (pip install should have already taken care of it for you).

Getting started as git repository maintainer
--------------------------------------------
Coming.
