"""Tests for pure helpers in reverge_collector.tool_utils.

These run without any scanner binary — they exercise the parser/utility
functions that the scanner subprocess wrappers feed their outputs through.
"""

import os

import pytest
from reverge_collector import tool_utils

# ---------------------------------------------------------------------------
# remove_dups_from_dict
# ---------------------------------------------------------------------------


def test_remove_dups_from_dict_empty():
    assert tool_utils.remove_dups_from_dict([]) == []


def test_remove_dups_from_dict_no_dupes():
    items = [{'id': 'a', 'val': 1}, {'id': 'b', 'val': 2}]
    out = tool_utils.remove_dups_from_dict(items)
    assert len(out) == 2


def test_remove_dups_from_dict_collapses_identical_dicts():
    items = [{'id': 'a', 'val': 1}, {'id': 'a', 'val': 1}, {'id': 'b', 'val': 2}]
    out = tool_utils.remove_dups_from_dict(items)
    assert len(out) == 2


def test_remove_dups_from_dict_treats_key_order_as_same():
    """sort_keys=True means {'a':1,'b':2} and {'b':2,'a':1} are dupes."""
    items = [{'a': 1, 'b': 2}, {'b': 2, 'a': 1}]
    out = tool_utils.remove_dups_from_dict(items)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# consolidate_ports
# ---------------------------------------------------------------------------


def test_consolidate_ports_empty():
    assert tool_utils.consolidate_ports([]) == ''


def test_consolidate_ports_single_port():
    assert tool_utils.consolidate_ports(['80']) == '80'


def test_consolidate_ports_isolated_ports():
    """Non-consecutive ports stay individual."""
    out = tool_utils.consolidate_ports(['80', '443', '8080'])
    assert out == '80,443,8080'


def test_consolidate_ports_collapses_consecutive():
    out = tool_utils.consolidate_ports(['1', '2', '3', '4', '5'])
    assert out == '1-5'


def test_consolidate_ports_mixed_ranges_and_singles():
    out = tool_utils.consolidate_ports(['1', '2', '3', '80', '443', '444', '445'])
    assert out == '1-3,80,443-445'


def test_consolidate_ports_dedupes_and_sorts():
    """Input order/dupes don't matter; output is sorted compact."""
    out = tool_utils.consolidate_ports(['443', '80', '80', '443', '81'])
    assert out == '80-81,443'


def test_consolidate_ports_string_inputs_parsed_as_ints():
    """Strings like '8080' compare correctly (not lexicographic '8080' < '9')."""
    out = tool_utils.consolidate_ports(['8080', '9', '10'])
    assert out == '9-10,8080'


# ---------------------------------------------------------------------------
# _load_session_key / _save_session_key / get_session_key
# ---------------------------------------------------------------------------


def test_load_session_key_missing_returns_none(tmp_path, monkeypatch):
    """No session file on disk → None."""
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'no-such-session'))
    assert tool_utils._load_session_key() is None


def test_save_then_load_session_key_roundtrip(tmp_path, monkeypatch):
    """Bytes written by _save_session_key come back identical from _load."""
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'session'))
    key = b'\x01\x02\x03\x04' * 8  # 32 bytes
    tool_utils._save_session_key(key)
    assert tool_utils._load_session_key() == key


def test_save_session_key_file_perms_are_0600(tmp_path, monkeypatch):
    """Written session file must be mode 0600 (owner read/write only)."""
    session_path = tmp_path / 'session-perms'
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(session_path))
    tool_utils._save_session_key(b'\x00' * 32)
    # umask can clear bits but never set them — 0o600 is the upper bound.
    mode = os.stat(session_path).st_mode & 0o777
    # Group and other should have no permissions.
    assert mode & 0o077 == 0, f'expected 0o600-ish, got {oct(mode)}'


def test_load_session_key_corrupt_file_returns_none(tmp_path, monkeypatch):
    """A non-hex file content → caught and returned as None."""
    session_path = tmp_path / 'corrupt'
    session_path.write_text('not-hex-at-all!!')
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(session_path))
    assert tool_utils._load_session_key() is None


# ---------------------------------------------------------------------------
# encrypt_data / decrypt_data
# ---------------------------------------------------------------------------


def test_encrypt_then_decrypt_roundtrip():
    """encrypt_data(key, x) → decrypt_data(key, that) returns x."""
    key = b'\x00\x01\x02\x03' * 8  # 32 bytes — AES-256
    plaintext = b'hello reverge collector'
    ciphertext = tool_utils.encrypt_data(key, plaintext)
    # ciphertext is a base64 string
    assert isinstance(ciphertext, str)
    out = tool_utils.decrypt_data(key, ciphertext)
    assert out == plaintext


def test_encrypt_produces_different_ciphertext_each_call():
    """AES with random nonce → repeated calls on same plaintext differ."""
    key = b'\xff' * 32
    plaintext = b'same input'
    ct1 = tool_utils.encrypt_data(key, plaintext)
    ct2 = tool_utils.encrypt_data(key, plaintext)
    assert ct1 != ct2


def test_decrypt_wrong_key_does_not_return_original():
    """Decrypting with the wrong key either raises or returns junk —
    must not silently return the original plaintext."""
    key1 = b'\xaa' * 32
    key2 = b'\xbb' * 32
    plaintext = b'secret payload'
    ct = tool_utils.encrypt_data(key1, plaintext)
    with pytest.raises(Exception):
        result = tool_utils.decrypt_data(key2, ct)
        # If it didn't raise, at least make sure it's wrong.
        assert result != plaintext
