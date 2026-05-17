"""Speed up route tests by no-op'ing time.sleep calls.

The retry logic in api_client._post uses time.sleep(5/30/120) between
attempts. The route tests exercise those retry branches but don't need
the real wall-clock delays — patching sleep here keeps the route suite
fast enough to run as part of the coverage measurement loop.
"""

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _no_sleep():
    """Replace time.sleep with a no-op for the duration of every route test."""
    with patch('time.sleep', return_value=None):
        yield
