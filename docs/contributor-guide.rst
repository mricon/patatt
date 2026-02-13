Contributor Guide
=================

This guide covers how to set up patatt for signing your patches.

Installation
------------

Install from PyPI using pipx (recommended)::

    pipx install patatt

Or with pip::

    pip install --user patatt

If using pip, make sure your PATH includes ``$HOME/.local/bin``.

Alternatively, clone the repository and symlink patatt.sh into your path::

    cd bin
    ln -s ~/path/to/patatt/patatt.sh patatt

After this, you should be able to run ``patatt --help`` without
specifying the full path to the repository.

Signing with PGP
----------------

If you already have a PGP key, you can simply start using it to sign
patches. Add the following to your ``~/.gitconfig``::

    [patatt]
        signingkey = openpgp:KEYID

The KEYID should be the 16-character identifier of your key, for
example::

    [patatt]
        signingkey = openpgp:E63EDCA9329DD07E

Signing with OpenSSH
--------------------

If you have OpenSSH version 8.0+, then you can use your ssh keys for
generating and verifying signatures. There are several upsides to using
openssh as opposed to generic ed25519:

- you can passphrase-protect your ssh keys
- passphrase-protected keys will benefit from ssh-agent caching
- you can use hardware tokens and ed25519-sk keys for higher protection
- you are much more likely to remember to back up your ssh keys

To start using openssh signatures with patatt, add the following to your
``~/.gitconfig``::

    [patatt]
        signingkey = openssh:~/.ssh/my_key_id.pub
        selector = my_key_id

Note that the person verifying openssh signatures must also run the
version of openssh that supports this functionality.

Signing with ed25519
--------------------

If you don't already have a PGP key, you can opt to generate and use a
new ed25519 key instead.

To generate a new keypair, run::

    patatt genkey

You will see output similar to::

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

Please make sure to back up your new private key, located in
``~/.local/share/patatt/private``. It is short enough to simply
print/write out for storing offline.

Next, just do as instructions say. If the project for which you are
contributing patches already uses patatt attestation, please work with
the project maintainers to add your public key to the repository. If
they aren't yet using patatt, just start signing your patches and
hopefully the project will start keeping its own keyring in the future.

Testing Your Setup
------------------

To test if signing is working::

    git format-patch -1 --stdout | patatt sign > /tmp/test

If you didn't get an error message, then the process was successful. You
can review ``/tmp/test`` to see that ``X-Developer-Signature`` and
``X-Developer-Key`` headers were successfully added.

You can validate your own message::

    patatt validate /tmp/test

Automatic Signing with git-send-email
-------------------------------------

If everything is working well, you can start automatically signing all
outgoing patches sent via git-send-email. Inside the repo you want enabled
for signing, run::

    patatt install-hook

Or you can do it manually::

    echo 'patatt sign --hook "${1}"' > "$(git rev-parse --git-dir)/hooks/sendemail-validate"
    chmod a+x "$(git rev-parse --git-dir)/hooks/sendemail-validate"

Choosing a Key Type
-------------------

If you don't already have a PGP key that is used in your project, you
may wonder whether it makes sense to create a new PGP key, reuse your
OpenSSH key, or start using standalone ed25519 keys.

Reasons to choose PGP
~~~~~~~~~~~~~~~~~~~~~

- You can protect the PGP private key with a passphrase (gpg-agent will
  manage it for you so you only need to enter it once per session)
- You can move your PGP key to an OpenPGP-compliant smartcard to further
  protect your key from being leaked/stolen
- You can use PGP keys to sign git tags/commits, not just mailed patches

If you choose to create a new PGP key, you can use the following guide:
https://github.com/lfit/itpol/blob/master/protecting-code-integrity.md

Reasons to choose OpenSSH keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- You can protect openssh keys with a passphrase and rely on ssh-agent
  passphrase caching
- You can use ssh keys with u2f hardware tokens for additional
  protection of your private key data
- Since version 2.34 git can also use ssh keys to sign tags and commits

Reasons to choose a standalone ed25519 key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Much smaller signatures, especially compared to PGP RSA keys
- Implements the DKIM ed25519 signing standard
- Faster operation

If you choose ed25519 keys, you will need to make sure that PyNaCl is
installed (pip install should have already taken care of it for you).
