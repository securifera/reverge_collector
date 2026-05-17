"""Direct parser tests for the heaviest scanner modules (nmap, naabu).

These tests skip the integration paths in tests/routes/ and exercise the
``parse_X`` functions in isolation with fixture XML/JSONL inputs.
"""

from __future__ import annotations

import json


# ===========================================================================
# nmap
# ===========================================================================


NMAP_XML_BASIC = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV target" start="1700000000" version="7.99" xmloutputversion="1.05">
  <host starttime="1700000001" endtime="1700000010">
    <status state="up" reason="user-set"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="www.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.41" tunnel="" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="1700000010" elapsed="9"/></runstats>
</nmaprun>
"""


def test_parse_nmap_xml_emits_host_ports_domain(tmp_path):
    from reverge_collector.data_model import (
        ApplicationProtocol,
        Domain,
        Host,
        Port,
    )
    from reverge_collector.nmap_scan import parse_nmap_xml

    f = tmp_path / 'nmap.xml'
    f.write_text(NMAP_XML_BASIC)
    records = parse_nmap_xml(str(f), tool_instance_id='tid', tool_id='toolid')

    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    domains = [r for r in records if isinstance(r, Domain)]
    protos = [r for r in records if isinstance(r, ApplicationProtocol)]

    # Each open port emits its own Host (the parser repeats per open port)
    assert hosts
    assert hosts[0].ipv4_addr == '93.184.216.34'

    # Only OPEN ports are emitted (closed 22 skipped)
    port_nums = sorted({p.port for p in ports})
    assert port_nums == ['443', '80']

    # Domain from <hostname>
    assert any(d.name == 'www.example.com' for d in domains)

    # ApplicationProtocol from service name="http"
    assert any(p.name == 'http' for p in protos)
    # collection_tool_instance_id is propagated
    for r in records:
        assert r.collection_tool_instance_id == 'tid'


def test_parse_nmap_xml_with_no_open_ports(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    xml = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>
    <hostnames/><ports/></host>
</nmaprun>"""
    f = tmp_path / 'n.xml'
    f.write_text(xml)
    records = parse_nmap_xml(str(f))
    # No open ports → no records (parser walks per-open-port)
    assert records == []


def test_parse_nmap_xml_with_ipv6(tmp_path):
    from reverge_collector.data_model import Host
    from reverge_collector.nmap_scan import parse_nmap_xml

    xml = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="2606:2800:220:1:248:1893:25c8:1946" addrtype="ipv6"/>
    <hostnames/>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
  </host>
</nmaprun>"""
    f = tmp_path / 'n.xml'
    f.write_text(xml)
    records = parse_nmap_xml(str(f))
    hosts = [r for r in records if isinstance(r, Host)]
    assert hosts
    assert hosts[0].ipv6_addr  # ipv6 set, not ipv4
    assert hosts[0].ipv4_addr is None


# ===========================================================================
# naabu
# ===========================================================================


def test_parse_naabu_output_basic(tmp_path):
    from reverge_collector.data_model import Domain, Host, Port
    from reverge_collector.naabu_scan import parse_naabu_output

    f = tmp_path / 'naabu.jsonl'
    f.write_text(
        json.dumps(
            {
                'host': 'www.example.com',
                'ip': '93.184.216.34',
                'port': 443,
                'protocol': 'tcp',
                'tls': True,
            }
        )
        + '\n'
        + json.dumps(
            {
                'host': '1.1.1.1',  # same as ip → no domain emitted
                'ip': '1.1.1.1',
                'port': 80,
                'protocol': 'tcp',
                'tls': False,
            }
        )
        + '\n'
    )

    records = parse_naabu_output(str(f), tool_instance_id='tid')
    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    domains = [r for r in records if isinstance(r, Domain)]

    assert len(hosts) == 2
    assert len(ports) == 2
    # Only the first entry (host != ip) emits a Domain
    assert len(domains) == 1
    assert domains[0].name == 'www.example.com'

    # TLS=true → port.secure=True
    secure_ports = [p for p in ports if p.secure]
    assert len(secure_ports) == 1
    assert secure_ports[0].port == '443'


def test_parse_naabu_output_skips_blank_and_malformed_lines(tmp_path):
    from reverge_collector.data_model import Host
    from reverge_collector.naabu_scan import parse_naabu_output

    f = tmp_path / 'naabu.jsonl'
    f.write_text(
        '\n'  # blank line
        '   \n'  # whitespace
        'not json\n'
        + json.dumps({'host': 'x.com', 'ip': '1.2.3.4', 'port': 80})
        + '\n'
        # Missing port — should be skipped
        + json.dumps({'host': 'no-port.com', 'ip': '5.6.7.8'})
        + '\n'
    )
    records = parse_naabu_output(str(f), tool_instance_id='tid')
    hosts = [r for r in records if isinstance(r, Host)]
    assert len(hosts) == 1
    assert hosts[0].ipv4_addr == '1.2.3.4'


def test_parse_naabu_output_skips_invalid_ip(tmp_path):
    from reverge_collector.naabu_scan import parse_naabu_output

    f = tmp_path / 'naabu.jsonl'
    f.write_text(
        json.dumps({'host': 'bogus', 'ip': 'definitely-not-an-ip', 'port': 80})
        + '\n'
    )
    assert parse_naabu_output(str(f), tool_instance_id='tid') == []


def test_parse_naabu_output_cpe_extraction(tmp_path):
    from reverge_collector.data_model import ApplicationProtocol, Cpe
    from reverge_collector.naabu_scan import parse_naabu_output

    f = tmp_path / 'naabu.jsonl'
    f.write_text(
        json.dumps(
            {
                'host': 'www.example.com',
                'ip': '52.4.7.15',
                'port': 443,
                'protocol': 'tcp',
                'tls': True,
                'name': 'http',
                'product': 'Apache httpd',
                'cpes': ['cpe:/a:apache:http_server/'],
            }
        )
        + '\n'
    )
    records = parse_naabu_output(str(f), tool_instance_id='tid')

    protos = [r for r in records if isinstance(r, ApplicationProtocol)]
    cpes = [r for r in records if isinstance(r, Cpe)]

    # Service name "http" → ApplicationProtocol
    assert any(p.name == 'http' for p in protos)
    # Product "Apache httpd" → Cpe (with vendor 'apache' from CPE)
    apache = [c for c in cpes if c.product == 'apache httpd']
    assert len(apache) == 1
    assert apache[0].vendor == 'apache'


def test_cpe22_to_cpe23_conversion():
    from reverge_collector.naabu_scan import _cpe22_to_cpe23

    # Basic conversion: cpe:/a:vendor:product/  →  cpe:2.3:a:vendor:product:*:*:...
    out = _cpe22_to_cpe23('cpe:/a:apache:http_server/')
    assert out == 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'

    # With version
    out = _cpe22_to_cpe23('cpe:/a:openbsd:openssh:9.6p1/')
    assert out == 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'

    # Operating system part
    out = _cpe22_to_cpe23('cpe:/o:linux:linux_kernel:5.10/')
    assert out.startswith('cpe:2.3:o:linux:linux_kernel:5.10:')

    # Not a CPE 2.2 binding → returned as-is
    assert _cpe22_to_cpe23('plain-string') == 'plain-string'
    assert _cpe22_to_cpe23('cpe:2.3:a:already:cpe23') == 'cpe:2.3:a:already:cpe23'
