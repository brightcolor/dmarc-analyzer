"""
Shared test fixtures.
Uses an in-memory SQLite database for isolation.
"""
import os

# The app engine must never point at a real database file during tests
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.models import Base
from app.database import get_db
from app.main import app
from app.security import hash_password, generate_inbound_token
from app.config import settings

# Force SQLite for tests
TEST_DB_URL = "sqlite:///:memory:"

@pytest.fixture(scope="session")
def engine():
    eng = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    from sqlalchemy import event
    @event.listens_for(eng, "connect")
    def set_pragma(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)


@pytest.fixture(scope="function")
def db(engine) -> Session:
    SessionTest = sessionmaker(bind=engine)
    session = SessionTest()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def org(db):
    from app.models import Organization
    o = Organization(name="Test Org", slug="test-org", is_active=True)
    db.add(o)
    db.flush()
    return o


@pytest.fixture
def admin_user(db, org):
    from app.models import User, OrganizationMembership
    u = User(
        email="admin@example.com",
        password_hash=hash_password("testpass123"),
        is_superadmin=True,
        is_active=True,
        email_verified=True,
    )
    db.add(u)
    db.flush()
    db.add(OrganizationMembership(user_id=u.id, organization_id=org.id, role="org_admin"))
    db.flush()
    return u


@pytest.fixture
def inbound_address(db, org):
    from app.models import InboundMailAddress
    token = generate_inbound_token(12)
    addr = InboundMailAddress(
        organization_id=org.id,
        address=f"test-{token}@reports.example.org",
        token=token,
        status="active",
        purpose="org_report",
    )
    db.add(addr)
    db.flush()
    return addr


@pytest.fixture
def domain(db, org):
    from app.models import Domain
    d = Domain(organization_id=org.id, name="example.com", is_active=True)
    db.add(d)
    db.flush()
    return d


# ── Sample DMARC XML ──────────────────────────────────────────────────────────

SAMPLE_DMARC_XML = b"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>Google Inc.</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>test-report-001</report_id>
    <date_range>
      <begin>1700000000</begin>
      <end>1700086399</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
        <selector>default</selector>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.5</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>evil.com</domain>
        <result>fail</result>
      </dkim>
      <spf>
        <domain>evil.com</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>
"""

SPF_PASS_DKIM_FAIL_XML = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Test Sender</org_name>
    <report_id>spf-pass-dkim-fail-001</report_id>
    <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip>
      <count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>other.com</domain><result>fail</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
"""

BROKEN_XML = b"<?xml version='1.0'?><feedback><broken"

XXE_XML = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<feedback><report_metadata>&xxe;</report_metadata></feedback>
"""

DUPLICATE_REPORT_XML = SAMPLE_DMARC_XML  # same report_id = test-report-001

# RFC 9990 (DMARCbis) report with namespace and every new field
DMARCBIS_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>example.net</org_name>
    <email>dmarc-reports@example.net</email>
    <report_id>bis-report-001</report_id>
    <date_range><begin>1790000000</begin><end>1790086399</end></date_range>
    <generator>Example Reporter 3.1</generator>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <discovery_method>treewalk</discovery_method>
    <p>reject</p>
    <sp>quarantine</sp>
    <np>reject</np>
    <testing>y</testing>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.20</source_ip>
      <count>7</count>
      <policy_evaluated>
        <disposition>pass</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>s2026</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><scope>mfrom</scope><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.30</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason><type>policy_test_mode</type><comment>t=y</comment></reason>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.org</domain><selector>x1</selector><result>fail</result></dkim>
      <spf><domain>example.org</domain><scope>mfrom</scope><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>
"""

# RFC 9990 content without the namespace declaration (seen in practice)
DMARCBIS_NO_NAMESPACE_XML = DMARCBIS_XML.replace(
    b' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"', b""
).replace(b"bis-report-001", b"bis-report-002")

# RFC 7489 report with a legacy namespace some reporters declare
LEGACY_NAMESPACE_XML = SAMPLE_DMARC_XML.replace(
    b"<feedback>", b'<feedback xmlns="http://dmarc.org/dmarc-xml/0.1">'
).replace(b"test-report-001", b"legacy-ns-001")
