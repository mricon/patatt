Maintainer Guide
================

Patatt implements basic signature validation, but it's a tool aimed
primarily at contributors. If you are processing mailed-in patches, then
you should look into using `b4 <https://b4.docs.kernel.org>`_, which aims
at making the entire process easier. B4 properly recognizes
X-Developer-Signature headers starting with version 0.7.0 and uses the
patatt library as well.

That said, keyring management as discussed below applies both to patatt
and b4.

In-Git Public Key Management
----------------------------

The trickiest part of all decentralized PKI schemes is not the crypto
itself, but public key distribution and management. PGP famously tried
to solve this problem by relying on cross-key certification and
keyservers, but the results were not encouraging.

On the other hand, within the context of git repositories, we already
have a suitable mechanism for distributing developer public keys, which
is the repository itself. Consider this:

- git is already decentralized and can be mirrored to multiple
  locations, avoiding any single points of failure
- all contents are already versioned and key additions/removals can be
  audited and "git blame'd"
- git commits themselves can be cryptographically signed, which allows a
  small subset of developers to act as "trusted introducers" to many
  other contributors (mimicking the "keysigning" process)

The idea of using git itself for keyring management was originally
suggested by the `did:git project <https://github.com/dhuseby/did-git-spec/blob/master/did-git-spec.md>`_,
though we do not currently implement the proposed standard itself.

Keyring Structure
-----------------

The keyring is structured as follows::

    topdir/                          # e.g. ".keys"
    └── keytype/                     # e.g. "ed25519" or "openpgp"
        └── address-domainname/      # e.g. "example.org"
            └── address-localpart/   # e.g. "developer"
                └── selector         # e.g. "default"

The main reasoning behind this structure was to make it easy for
multiple project maintainers to manage keys without causing any
unnecessary git merge complications. Keeping all public keys in
individual files helps achieve this goal.

Example Lookup
~~~~~~~~~~~~~~

For the following signature::

    From: Konstantin Ryabitsev <konstantin@linuxfoundation.org>
    X-Developer-Signature: v=1; a=ed25519-sha256; t=1620240207; l=2577;
     h=from:subject; bh=yqviDBgyf3/dQgHcBe3B7fTP39SuKnYInPBxnOiuGcA=;
     b=Xzd0287MvPE9NLX7xbQ6xnyrvqQOMK01mxHnrPmm1f6O7KKyogc8YH6IAlwIPdo+jk1CkdYYQsyZ
     sS0cJdX2B4uTmV9mxOe7hssjtjLcj5/NU9zAw6WJARybaNAKH8rv

The key would be found in the following subpath::

    .keys/ed25519/linuxfoundation.org/konstantin/default

If ``i=`` and ``s=`` fields are specified in the signature::

    X-Developer-Signature: v=1; a=ed25519-sha256; t=1620244687; l=12645;
     i=mricon@kernel.org; s=20210505; h=from:subject;
     bh=KRCBcYiMdeoSX0l1XJ2YzP/uJhmym3Pi6CmbN9fs4aM=;
     b=sSY2vXzju7zU3KK4VQ5vFa5iPpDr3nrf221lnpq2+uuXmCODlAsgoqDmjKUBmbPtlY1Bcb2N0XZQ
     0KX+OShCAAwB5U1dtFtRnB/mgVibMxwl68A7OivGIVYe491yll5q

Then the path would reflect those parameters::

    .keys/ed25519/kernel.org/mricon/20210505

Privacy-Preserving By-Hash Lookup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For privacy-conscious deployments, patatt also supports looking up keys
by hash. Instead of storing keys at the standard path, you can store them
at a path based on the SHA256 hash of the keypath.

The **keypath** is the standard lookup path constructed from the signature
fields: ``keytype/domain/local/selector``. For example, a signature with
``a=ed25519-sha256``, ``i=mricon@kernel.org``, and ``s=20210505`` would
have the keypath::

    ed25519/kernel.org/mricon/20210505

The by-hash path is computed by taking the SHA256 hash of this keypath
string and splitting it into a 2-character prefix and 62-character
remainder::

    by-hash/XX/YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

For the example above::

    $ echo -n "ed25519/kernel.org/mricon/20210505" | sha256sum
    0c58e579105c2971ce31d4d97f65628b986c04033f4934592a60b8687b0fd828

    # Store the key at:
    by-hash/0c/58e579105c2971ce31d4d97f65628b986c04033f4934592a60b8687b0fd828

This avoids exposing email addresses in the directory structure while
still allowing key lookup. Patatt automatically tries the by-hash path
as a fallback when the standard path lookup fails.

Key File Formats
~~~~~~~~~~~~~~~~

**ed25519 keys**: The file contains just the base64-encoded public key.

**openpgp keys**: ASCII-armored public key export::

    gpg -a --export --export-options export-minimal keyid

**openssh keys**: Single line in standard openssh pubkey format::

    ssh-ed25519 AAAAC3N... comment@or-hostname

Whose Keys to Add
-----------------

It does not really make sense to require cryptographic attestation for
patches submitted by occasional contributors. The only keys added to the
keyring should be those of the core maintainers who have push access to
the "canonical" repository location, plus the keys belonging to regular
contributors with a long-term ongoing relationship with the project.

Managing Keyrings: Small Teams
------------------------------

For smaller repositories with a handful of core maintainers, it makes
sense to keep the keyring in the main branch, together with all other
project files.

Managing Keyrings: Large Teams
------------------------------

For large teams with thousands of regular contributors and teams of
subsystem maintainers (e.g. the Linux kernel), it does not make sense to
have a centrally managed keyring tracked in the main repository.
Instead, each subsystem maintainer team should manage their own keyring
in a separate ref of their own repository.

Creating a Keyring Ref
~~~~~~~~~~~~~~~~~~~~~~

To create a blank new ref called ``refs/meta/keyring``::

    git symbolic-ref HEAD refs/meta/keyring
    git reset --hard
    mkdir ed25519 openpgp

Individual public key files can then be added and committed following
the same structure as described above. Keeping the keyring outside the
regular development branch ensures that it doesn't interfere with
submitted pull requests or git-format-patch operations. Keeping the ref
under ``refs/meta/`` will hide it from most GUI interfaces, but if that
is not the goal, then it can be stored in ``refs/heads`` just like any
other branch.

Updating a Keyring Ref
~~~~~~~~~~~~~~~~~~~~~~

To commit and push the files after adding them::

    git commit -asS
    git push origin HEAD:refs/meta/keyring
    # Switch back to the development environment
    git checkout regular-branch

To make changes to an existing keyring ref::

    git fetch origin refs/meta/keyring
    # Verify that the commit is signed
    git verify-commit FETCH_HEAD
    git checkout FETCH_HEAD
    # make any changes to the keys
    git commit -asS
    git push origin HEAD:refs/meta/keyring
    git checkout regular-branch

Alternatively, if key additions/updates are frequent enough, the remote
ref can be checked out into its own workdir and set up for proper
remote tracking.

Configuring Keyring Sources
---------------------------

To use the keyring with patatt or b4, configure the ``keyringsrc`` setting
(can be specified multiple times and will be checked in order)::

    [patatt]
        # Empty ref means "use currently checked out ref in this repo"
        keyringsrc = ref:::.keys
        # Use a dedicated ref in this repo called refs/meta/keyring
        keyringsrc = ref::refs/meta/keyring:
        # Use a ref in a different repo
        keyringsrc = ref:~/path/to/another/repo:refs/heads/main:.keys
        # Use a regular dir on disk
        keyringsrc = ~/git/korg-pgpkeys/.keyring

For b4, use the same configuration under the ``[b4]`` section.

Default Keyring Locations
~~~~~~~~~~~~~~~~~~~~~~~~~

The following locations are checked by default::

    ref:::.keys
    ref:::.local-keys
    ref::refs/meta/keyring:
    $XDG_DATA_HOME/patatt/public

The ``:::`` means "whatever ref is checked out in the current repo",
and ``$XDG_DATA_HOME`` usually points at ``$HOME/.local/share``.
