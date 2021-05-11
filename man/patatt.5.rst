PATATT
======
-----------------------------------------
DKIM-like cryptographic patch attestation
-----------------------------------------

:Author:    mricon@kernel.org
:Date:      2021-05-11
:Copyright: The Linux Foundation and contributors
:License:   MIT-0
:Version:   0.2.0
:Manual section: 5

SYNOPSIS
--------
patatt {sign,validate,genkey} [options]

DESCRIPTION
-----------
This tools allows cryptographically signing patches sent via email
by using DKIM-like message headers. This approach is both effective and
doesn't interfere with other code review tools the way inline or
detached PGP signatures do. For a full overview of core concepts and
considerations, please see README.

If you already have a PGP key configured for signing git tags or
commits, then you should be able to use patatt without any additional
configuration. Try running the following in any git repository::

    git format-patch -1 --stdout | patatt sign

If patatt is not finding your PGP key, try adding the following to your
~/.gitconfig::

    [user]
        signingkey = [yourkeyid]

To find out your keyid, run ``gpg --list-secret-keys``. If you want to
use a specific subkey, you can specify the subkey ID with a ``!`` at the
end.

USING AS A GIT HOOK
-------------------
If you use ``git-send-email`` for sending patches, then you can get
them automatically signed via the ``sendemail-validate`` hook::

    $ echo 'patatt sign --hook "${1}"' >> .git/hooks/sendemail-validate
    $ chmod a+x .git/hooks/sendemail-validate

SUBCOMMANDS
-----------
* *patatt sign*: sign stdin or RFC2822 files passed as arguments
* *patatt validate*: basic validation for signed messages
* *patatt genkey*: generate a new ed25519 keypair

You can run ``patatt [subcommand] --help`` to see a summary of flags for
each subcommand.

SUPPORT
-------
Please email tools@linux.kernel.org with support requests.
