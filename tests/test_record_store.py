"""Tests for the RecordStore class in reverge_collector.record_store.

RecordStore is the auto-indexed backing store that consolidates the 38+
mapping dicts that used to live directly on ScanData. The store reads
each record class's _indices declaration to maintain indices generically.
"""

from reverge_collector import data_model
from reverge_collector.record_store import RecordStore

# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_record_store_init_creates_empty_universal_map():
    rs = RecordStore()
    assert rs.scan_obj_map == {}


def test_record_store_init_creates_all_documented_indices():
    """All the per-type maps that ScanData properties forward to exist as empty dicts."""
    rs = RecordStore()
    for attr in (
        'subnet_map',
        'host_map',
        'host_ip_id_map',
        'domain_name_map',
        'domain_host_id_map',
        'port_map',
        'port_host_map',
        'component_map',
        'path_map',
        'screenshot_map',
        'http_endpoint_map',
        'collection_module_map',
        'vulnerability_map',
        'certificate_map',
    ):
        assert getattr(rs, attr) == {}


# ---------------------------------------------------------------------------
# add() — always populates scan_obj_map regardless of indices
# ---------------------------------------------------------------------------


def test_add_records_universal_map_regardless_of_type():
    """Any record type lands in scan_obj_map keyed by id."""
    rs = RecordStore()
    h = data_model.Host(id='h1')
    h.ipv4_addr = '1.2.3.4'
    rs.add(h)
    assert rs.scan_obj_map == {'h1': h}


def test_add_host_populates_ip_and_id_indices():
    """Host has indices: host_ip_id_map (map_id) and host_map (map)."""
    rs = RecordStore()
    h = data_model.Host(id='h1')
    h.ipv4_addr = '10.0.0.1'
    rs.add(h)
    assert rs.host_map == {'h1': h}
    assert rs.host_ip_id_map == {'10.0.0.1': 'h1'}


def test_add_subnet_populates_subnet_map():
    rs = RecordStore()
    s = data_model.Subnet(id='s1')
    s.subnet = '192.168.0.0'
    s.mask = '24'
    rs.add(s)
    assert rs.subnet_map == {'s1': s}


def test_add_domain_appends_to_host_list_index():
    """Domain's list index is keyed on parent.id (host)."""
    rs = RecordStore()
    d1 = data_model.Domain(parent_id='hh', id='d1')
    d1.name = 'a.example.com'
    d2 = data_model.Domain(parent_id='hh', id='d2')
    d2.name = 'b.example.com'
    rs.add(d1)
    rs.add(d2)
    assert len(rs.domain_host_id_map['hh']) == 2
    assert rs.domain_name_map['a.example.com'] is d1
    assert rs.domain_name_map['b.example.com'] is d2


def test_add_port_uses_set_mode_for_port_host_map():
    """Port's port_host_map index uses set mode: key=port, value=parent_id."""
    rs = RecordStore()
    p = data_model.Port(parent_id='h', id='p1')
    p.port = '443'
    p.proto = 6
    rs.add(p)
    assert 'h' in rs.host_id_port_map
    assert rs.host_id_port_map['h'] == [p]


def test_add_skips_index_when_key_func_returns_none():
    """If the key_func returns None, that index entry is silently skipped."""
    rs = RecordStore()
    # A Domain with no name → domain_name_map key_func returns None.
    d = data_model.Domain(parent_id='h', id='d1')
    d.name = None
    rs.add(d)
    # Universal map still populated.
    assert rs.scan_obj_map == {'d1': d}
    # But domain_name_map gets no entry.
    assert rs.domain_name_map == {}


def test_add_host_runs_pre_index_to_preserve_credential():
    """Host has a _pre_index hook that copies credential from previous Host
    with the same IP. Adding a 2nd host with same IP → credential carried over."""
    rs = RecordStore()
    h1 = data_model.Host(id='h1')
    h1.ipv4_addr = '5.5.5.5'
    h1.credential = {'credential_id': 'preserved'}
    rs.add(h1)
    # Second host with same IP, no credential.
    h2 = data_model.Host(id='h2')
    h2.ipv4_addr = '5.5.5.5'
    rs.add(h2)
    assert h2.credential == {'credential_id': 'preserved'}


# ---------------------------------------------------------------------------
# get + query + remove
# ---------------------------------------------------------------------------


def test_get_returns_record_by_id():
    rs = RecordStore()
    h = data_model.Host(id='hh')
    h.ipv4_addr = '1.1.1.1'
    rs.add(h)
    assert rs.get('hh') is h


def test_get_returns_none_for_unknown_id():
    rs = RecordStore()
    assert rs.get('no-such-id') is None


def test_query_by_index_name():
    rs = RecordStore()
    h = data_model.Host(id='hh')
    h.ipv4_addr = '7.7.7.7'
    rs.add(h)
    assert rs.query('host_map', 'hh') is h


def test_query_unknown_index_returns_none():
    rs = RecordStore()
    assert rs.query('no_such_index', 'k') is None


def test_query_unknown_key_returns_none():
    rs = RecordStore()
    assert rs.query('host_map', 'no-such-host') is None


def test_remove_drops_from_universal_map():
    rs = RecordStore()
    h = data_model.Host(id='hh')
    h.ipv4_addr = '1.2.3.4'
    rs.add(h)
    rs.remove('hh')
    assert rs.get('hh') is None


def test_remove_unknown_id_is_noop():
    rs = RecordStore()
    rs.remove('nothing-here')  # must not raise
