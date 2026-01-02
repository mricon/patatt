Library Reference
=================

This section documents the public API for using patatt as a library.

Core Classes
------------

PatattMessage
~~~~~~~~~~~~~

.. autoclass:: patatt.PatattMessage
   :members:
   :undoc-members:
   :show-inheritance:

DevsigHeader
~~~~~~~~~~~~

.. autoclass:: patatt.DevsigHeader
   :members:
   :undoc-members:
   :show-inheritance:

Exceptions
----------

.. autoexception:: patatt.Error
   :members:
   :show-inheritance:

.. autoexception:: patatt.SigningError
   :show-inheritance:

.. autoexception:: patatt.ConfigurationError
   :show-inheritance:

.. autoexception:: patatt.ValidationError
   :show-inheritance:

.. autoexception:: patatt.NoKeyError
   :show-inheritance:

.. autoexception:: patatt.BodyValidationError
   :show-inheritance:

Public Functions
----------------

Signing and Validation
~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: patatt.sign_message

.. autofunction:: patatt.validate_message

Key Management
~~~~~~~~~~~~~~

.. autofunction:: patatt.make_pkey_path

.. autofunction:: patatt.make_byhash_path

.. autofunction:: patatt.get_public_key

Configuration
~~~~~~~~~~~~~

.. autofunction:: patatt.get_main_config

.. autofunction:: patatt.get_data_dir

Constants
---------

Result Codes
~~~~~~~~~~~~

The following constants are returned by :func:`validate_message` to indicate
the validation result:

.. py:data:: patatt.RES_VALID
   :value: 0

   Signature is valid.

.. py:data:: patatt.RES_BADSIG
   :value: 1

   Signature verification failed.

.. py:data:: patatt.RES_NOKEY
   :value: 2

   Public key not found in any keyring.

.. py:data:: patatt.RES_NOSIG
   :value: 3

   Message has no signatures.

.. py:data:: patatt.RES_ERROR
   :value: 4

   Error during validation (e.g., malformed signature).

Usage Examples
--------------

Signing a Message
~~~~~~~~~~~~~~~~~

.. code-block:: python

   import patatt

   # Read a patch file
   with open('patch.eml', 'rb') as f:
       msgdata = f.read()

   # Sign with ed25519 key
   signed = patatt.sign_message(
       msgdata,
       algo='ed25519',
       keyinfo='path/to/private.key',
       identity='user@example.com',
       selector='default'
   )

   # Write signed message
   with open('signed-patch.eml', 'wb') as f:
       f.write(signed)

Validating a Message
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import patatt

   # Read a signed patch
   with open('signed-patch.eml', 'rb') as f:
       msgdata = f.read()

   # Get keyring sources from config
   config = patatt.get_main_config()
   sources = config.get('keyringsrc', [])

   # Validate all signatures
   results = patatt.validate_message(msgdata, sources)

   for result in results:
       code, identity, timestamp, key_source, algo, errors = result
       if code == patatt.RES_VALID:
           print(f"Valid signature from {identity}")
       elif code == patatt.RES_NOKEY:
           print(f"No public key for {identity}")
       elif code == patatt.RES_BADSIG:
           print(f"Bad signature from {identity}: {errors}")

Working with PatattMessage Directly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import patatt

   # Parse a message
   with open('patch.eml', 'rb') as f:
       pm = patatt.PatattMessage(f.read())

   # Check if signed
   if pm.signed:
       # Get all signatures
       for sig in pm.get_sigs():
           print(f"Signed by: {sig.get_field_as_str('i')}")
           print(f"Algorithm: {sig.get_field_as_str('a')}")

   # Sign the message
   pm.sign(
       algo='ed25519',
       keyinfo='path/to/key',
       identity='user@example.com',
       selector='default'
   )

   # Get signed message bytes
   signed_bytes = pm.as_bytes()

Key Path Utilities
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import patatt

   # Get standard keyring path
   path = patatt.make_pkey_path('ed25519', 'user@example.com', 'default')
   # Returns: Path('ed25519/example.com/user/default')

   # Get privacy-preserving by-hash path
   byhash = patatt.make_byhash_path('ed25519', 'user@example.com', 'default')
   # Returns: Path('by-hash/XX/YYY...')

   # Look up a public key
   try:
       key_data, key_source = patatt.get_public_key(
           '/path/to/keyring',
           'ed25519',
           'user@example.com',
           'default'
       )
   except KeyError:
       print("Key not found")
