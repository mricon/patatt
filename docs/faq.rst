Frequently Asked Questions
==========================

Why is this library even needed?
--------------------------------

Why not simply PGP-sign all patches?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PGP-signing patches causes important problems for reviewers. If a patch
is inline-signed, then this not only adds textual headers/footers, but
adds additional escaping in the protected body, converting all ``^-``
sequences into ``^- -``, which corrupts patches.

MIME-signing is better, but has several other downsides:

- messages are now sent as multipart mime structures, which causes some
  tooling to no longer properly handle the patch content
- the signature attachments may be stripped/quarantined by email
  gateways that don't properly recognize OpenPGP mime signatures
- the From/Subject headers are rarely included into protected content,
  even though they are crucial parts of what ends up going into a git
  commit

These considerations have resulted in many projects specifically
requesting that patches should NOT be sent PGP-signed.

Why not just rely on proper code review?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Code review is a crucial step of the development process and patatt does
not aim to replace it. However, there are several areas where the
process can be abused by malicious parties in the absence of end-to-end
cryptographic attestation:

1. **Delegation trust**: A maintainer who struggles with code review volume
   may delegate parts of their duties to a submaintainer. If that person
   submits aggregated patch series to the maintainer after performing that
   work, there must be a mechanism to ensure that none of the reviewed
   patches have been modified between when they were reviewed by the trusted
   submaintainer and when the upstream developer applies them to their tree.
   Up to now, the only mechanism to ensure this was via signed pull requests
   -- with patatt this is now also possible with regular patch series.

2. **Review-to-apply integrity**: It is important to ensure that what
   developer reviews is what actually ends up being applied to their git
   tree. Linux development process consists of collecting follow-up trailers
   (Tested-by, Reviewed-by, etc), so various tooling exists to aggregate
   these trailers and create the collated patch series containing all
   follow-up tags (see b4, patchwork, etc). Patatt signing provides a
   mechanism to ensure that what that developer reviewed and approved and
   what they applied to their tree is the exact same code and hasn't been
   maliciously modified in-between review and "git am" (e.g. by archival
   services such as lore.kernel.org, mail hosting providers, someone with
   access to the developer's inbox, etc).

3. **Impersonation prevention**: An attacker may attempt to impersonate a
   well-known developer by submitting malicious code, perhaps with the hope
   that it receives less scrutiny and is accepted without rigorous code
   review. Even if this attempt is unsuccessful (and it most likely would
   be), this may cause unnecessary reputation damage to the person being
   impersonated. Cryptographic signatures (and lack thereof) will help the
   developer quickly establish that the attack was performed without their
   involvement.

Why not just rely on DKIM?
~~~~~~~~~~~~~~~~~~~~~~~~~~

DKIM standard is great, but there are several places where it falls a
bit short when it comes to patch attestation:

1. **Weak sender verification**: The signing is done by the mail gateways
   that may or may not be properly checking that the "From:" header matches
   the identity of the authenticated user. For example, a service that allows
   free account registration may not check that alice@example.org sends
   outgoing email with "bob@example.org" in the "From:" field, which would
   allow Alice to impersonate Bob and have the messages arrive with a valid
   DKIM signature.

2. **Key management concerns**: DKIM is usually seen as merely a spam
   reduction mechanism, so there's usually little incentive for
   infrastructure administrators to be too strict about how they handle the
   private keys used for DKIM signing. Most likely, they are just stored on
   disk without a passphrase and accessible by the SMTP daemon.

3. **Whitespace canonicalization**: DKIM's "relaxed" canonicalization
   standard for message bodies replaces all multiple whitespace characters
   with a single space before the body hash is signed. This poses significant
   problems for patches where whitespace is syntactically significant (Python,
   Makefiles, etc). A "return True" with a different indent will pass DKIM
   signature check and may introduce a serious security vulnerability.

4. **Typosquatting attacks**: DKIM doesn't prevent typosquatting attacks.
   For example, an attacker attempting to impersonate
   known.developer@companyname.com may send an email from
   known.developer@company-name.com or any other similar-looking address or
   domain, with valid DKIM signatures in every case.

Getting Support
---------------

Please send patches and support requests to tools@kernel.org.

Submissions must be made under the terms of the Linux Foundation
certificate of contribution and should include a Signed-off-by: line.
Please read the DCO file for the full legal definition of what that implies.
