"""Tests for SMTP inbound validation (RCPT TO checks, rate limiting)."""
import pytest

from app.services.inbound_address import validate_for_smtp
from smtp_inbound.validator import (
    ValidationResult,
    record_and_check_ip_rate,
    record_and_check_recipient_rate,
)


# ── validate_for_smtp ──────────────────────────────────────────────────────────

class TestValidateForSmtp:
    def test_unknown_recipient_rejected(self, db):
        accepted, reason, addr = validate_for_smtp(db, "nobody@reports.example.org")
        assert accepted is False
        assert "550" in reason
        assert "unknown" in reason.lower() or "recipient" in reason.lower()

    def test_active_recipient_accepted(self, db, inbound_address):
        accepted, reason, addr = validate_for_smtp(db, inbound_address.address)
        assert accepted is True
        assert addr is not None
        assert addr.id == inbound_address.id

    def test_disabled_recipient_rejected(self, db, inbound_address):
        inbound_address.status = "disabled"
        db.flush()
        accepted, reason, addr = validate_for_smtp(db, inbound_address.address)
        assert accepted is False
        assert "550" in reason
        assert "disabled" in reason.lower()

    def test_revoked_recipient_rejected(self, db, inbound_address):
        inbound_address.status = "revoked"
        db.flush()
        accepted, reason, addr = validate_for_smtp(db, inbound_address.address)
        assert accepted is False
        assert "550" in reason
        assert "disabled" in reason.lower()

    def test_inactive_status_rejected(self, db, inbound_address):
        inbound_address.status = "pending"
        db.flush()
        accepted, reason, addr = validate_for_smtp(db, inbound_address.address)
        assert accepted is False
        assert "550" in reason

    def test_inactive_org_rejected(self, db, inbound_address, org):
        org.is_active = False
        db.flush()
        accepted, reason, addr = validate_for_smtp(db, inbound_address.address)
        assert accepted is False
        assert "550" in reason
        assert "organization" in reason.lower() or "disabled" in reason.lower()

    def test_inactive_domain_rejected(self, db, org):
        """Address bound to a disabled domain is rejected."""
        from app.models import Domain, InboundMailAddress
        from app.security import generate_inbound_token

        domain = Domain(organization_id=org.id, name="inactive.example.com", is_active=False)
        db.add(domain)
        db.flush()

        token = generate_inbound_token(12)
        addr = InboundMailAddress(
            organization_id=org.id,
            domain_id=domain.id,
            address=f"test-{token}@reports.example.org",
            token=token,
            status="active",
            purpose="domain_report",
        )
        db.add(addr)
        db.flush()

        accepted, reason, result_addr = validate_for_smtp(db, addr.address)
        assert accepted is False
        assert "550" in reason

    def test_case_insensitive_lookup(self, db, inbound_address):
        upper = inbound_address.address.upper()
        accepted, _, _ = validate_for_smtp(db, upper)
        assert accepted is True

    def test_accepted_returns_correct_org_id(self, db, inbound_address, org):
        _, _, addr = validate_for_smtp(db, inbound_address.address)
        assert addr.organization_id == org.id

    def test_revoked_never_accepted(self, db, inbound_address):
        """Revoked addresses must never be accepted even if other conditions are met."""
        inbound_address.status = "revoked"
        db.flush()
        accepted, _, _ = validate_for_smtp(db, inbound_address.address)
        assert accepted is False


# ── Rate limiting ──────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_ip_rate_limit_allows_under_limit(self):
        # Use a unique IP to avoid interference from other tests
        allowed = record_and_check_ip_rate("192.0.2.250", limit_per_hour=100)
        assert allowed is True

    def test_ip_rate_limit_blocks_over_limit(self):
        ip = "192.0.2.251"
        limit = 3
        for _ in range(limit):
            record_and_check_ip_rate(ip, limit_per_hour=limit)
        # The (limit+1)th attempt should be blocked
        result = record_and_check_ip_rate(ip, limit_per_hour=limit)
        assert result is False

    def test_recipient_rate_limit_allows_under_limit(self):
        addr = "unique-test-addr-allow@reports.example.org"
        result = record_and_check_recipient_rate(addr, limit_per_hour=50)
        assert result is True

    def test_recipient_rate_limit_blocks_over_limit(self):
        addr = "unique-test-addr-block@reports.example.org"
        limit = 2
        for _ in range(limit):
            record_and_check_recipient_rate(addr, limit_per_hour=limit)
        result = record_and_check_recipient_rate(addr, limit_per_hour=limit)
        assert result is False

    def test_different_ips_dont_share_counter(self):
        record_and_check_ip_rate("10.0.0.1", limit_per_hour=2)
        record_and_check_ip_rate("10.0.0.1", limit_per_hour=2)
        # 10.0.0.2 is independent — should still be allowed
        result = record_and_check_ip_rate("10.0.0.2", limit_per_hour=2)
        assert result is True
