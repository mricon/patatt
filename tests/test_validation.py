import pytest
import os
import tempfile
from pathlib import Path

from patatt import PatattMessage, sign_message, validate_message, RES_VALID

@pytest.mark.parametrize("sample_file", [
    "ed25519-signed.txt",
    "pgp-signed.txt",
    "openssh-signed.txt"
])
def test_validate(sample_file: str) -> None:
    """Test validation of an ed25519 signed message from samples directory."""
    # Path to the sample file
    toplevel = Path(__file__).parent.parent
    sample_path = os.path.join(toplevel, 'samples', sample_file)
    sources_path = os.path.join(toplevel, '.keys')

    # Read the signed message
    with open(sample_path, 'rb') as f:
        signed_data = f.read()

    # # Create a PatattMessage object from the signed data
    # message = PatattMessage(signed_data)

    # Validate the message
    results = validate_message(signed_data, [sources_path])

    # Check validation results
    assert results, "Validation should return results"

    # At least one valid signature should be found
    valid_signatures = [r for r in results if r[0] == RES_VALID]
    assert valid_signatures, "Should find at least one valid signature"

    # Print validation details for debugging
    print(f"Found {len(valid_signatures)} valid signatures:")
    for result in valid_signatures:
        status, algo, keytype, identity, selector, errors = result
        print(f"  - {keytype} signature by {identity} ({selector})")
