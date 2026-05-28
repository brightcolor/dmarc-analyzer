"""Tests for MIME/attachment parser: zip-bomb, path traversal, gzip, XXE."""
import gzip
import io
import zipfile
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from app.services.mime_parser import (
    MAX_UNZIPPED_SIZE,
    MAX_ZIP_FILES,
    MimeParseError,
    ZipBombError,
    _safe_gunzip,
    _safe_unzip,
    extract_dmarc_attachments,
    parse_mail_headers,
)
from tests.conftest import SAMPLE_DMARC_XML


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_zip(entries: dict[str, bytes]) -> bytes:
    """Build an in-memory ZIP with the given filename → content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_gz(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(data)
    return buf.getvalue()


def _make_email(attachment_data: bytes, filename: str, content_type: str = "application/octet-stream") -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "reports@google.com"
    msg["To"] = "dmarc@reports.example.org"
    msg["Subject"] = "Report Domain: example.com"
    msg["Message-ID"] = "<test-001@google.com>"
    msg.attach(MIMEText("DMARC report attached.", "plain"))
    att = MIMEApplication(attachment_data, _subtype="octet-stream")
    att.add_header("Content-Disposition", "attachment", filename=filename)
    att.set_type(content_type)
    msg.attach(att)
    return msg.as_bytes()


# ── _safe_gunzip ───────────────────────────────────────────────────────────────

class TestSafeGunzip:
    def test_valid_gz(self):
        data = _make_gz(SAMPLE_DMARC_XML)
        result = _safe_gunzip(data)
        assert result == SAMPLE_DMARC_XML

    def test_gz_bomb_raises(self):
        # Generate payload larger than MAX_UNZIPPED_SIZE
        big_data = b"A" * (MAX_UNZIPPED_SIZE + 1)
        gz_data = _make_gz(big_data)
        with pytest.raises(ZipBombError):
            _safe_gunzip(gz_data)

    def test_bad_gzip_raises(self):
        with pytest.raises(Exception):
            _safe_gunzip(b"notgzipdata")


# ── _safe_unzip ────────────────────────────────────────────────────────────────

class TestSafeUnzip:
    def test_valid_zip_single_xml(self):
        data = _make_zip({"report.xml": SAMPLE_DMARC_XML})
        entries = _safe_unzip(data)
        assert len(entries) == 1
        name, content = entries[0]
        assert name == "report.xml"
        assert content == SAMPLE_DMARC_XML

    def test_skips_non_xml_files(self):
        data = _make_zip({
            "report.xml": SAMPLE_DMARC_XML,
            "readme.txt": b"ignore me",
        })
        entries = _safe_unzip(data)
        names = [e[0] for e in entries]
        assert "report.xml" in names
        assert "readme.txt" not in names

    def test_too_many_files_raises(self):
        entries = {f"file{i}.xml": b"<a/>" for i in range(MAX_ZIP_FILES + 1)}
        data = _make_zip(entries)
        with pytest.raises(MimeParseError):
            _safe_unzip(data)

    def test_path_traversal_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.xml", b"<evil/>")
            zf.writestr("good.xml", SAMPLE_DMARC_XML)
        data = buf.getvalue()
        entries = _safe_unzip(data)
        names = [e[0] for e in entries]
        assert "../evil.xml" not in names
        assert "good.xml" in names

    def test_zip_bomb_raises(self):
        big_data = b"A" * (MAX_UNZIPPED_SIZE + 1)
        data = _make_zip({"bomb.xml": big_data})
        with pytest.raises((ZipBombError, MimeParseError)):
            _safe_unzip(data)

    def test_gz_inside_zip(self):
        gz_data = _make_gz(SAMPLE_DMARC_XML)
        data = _make_zip({"report.xml.gz": gz_data})
        entries = _safe_unzip(data)
        assert len(entries) == 1
        assert entries[0][0].endswith(".gz")


# ── extract_dmarc_attachments ──────────────────────────────────────────────────

class TestExtractDmarcAttachments:
    def test_plain_xml_attachment(self):
        raw = _make_email(SAMPLE_DMARC_XML, "report.xml", "application/xml")
        attachments = extract_dmarc_attachments(raw)
        assert len(attachments) == 1
        assert attachments[0].data == SAMPLE_DMARC_XML
        assert attachments[0].filename == "report.xml"

    def test_gz_attachment(self):
        gz = _make_gz(SAMPLE_DMARC_XML)
        raw = _make_email(gz, "report.xml.gz", "application/gzip")
        attachments = extract_dmarc_attachments(raw)
        assert len(attachments) == 1
        assert attachments[0].data == SAMPLE_DMARC_XML

    def test_zip_attachment(self):
        zip_data = _make_zip({"report.xml": SAMPLE_DMARC_XML})
        raw = _make_email(zip_data, "report.zip", "application/zip")
        attachments = extract_dmarc_attachments(raw)
        assert len(attachments) == 1
        assert attachments[0].data == SAMPLE_DMARC_XML

    def test_zip_attachment_has_source_filename(self):
        zip_data = _make_zip({"report.xml": SAMPLE_DMARC_XML})
        raw = _make_email(zip_data, "google_report.zip", "application/zip")
        attachments = extract_dmarc_attachments(raw)
        assert attachments[0].source_filename == "google_report.zip"

    def test_sha256_set(self):
        import hashlib
        raw = _make_email(SAMPLE_DMARC_XML, "report.xml", "application/xml")
        attachments = extract_dmarc_attachments(raw)
        expected = hashlib.sha256(SAMPLE_DMARC_XML).hexdigest()
        assert attachments[0].sha256 == expected

    def test_no_attachments_returns_empty(self):
        msg = MIMEMultipart()
        msg["From"] = "test@example.com"
        msg["To"] = "dmarc@example.com"
        msg.attach(MIMEText("No attachments.", "plain"))
        attachments = extract_dmarc_attachments(msg.as_bytes())
        assert attachments == []

    def test_zip_bomb_propagates(self):
        big_data = b"A" * (MAX_UNZIPPED_SIZE + 1)
        zip_data = _make_zip({"bomb.xml": big_data})
        raw = _make_email(zip_data, "bomb.zip", "application/zip")
        with pytest.raises((ZipBombError, MimeParseError)):
            extract_dmarc_attachments(raw)

    def test_gz_bomb_propagates(self):
        big_data = b"A" * (MAX_UNZIPPED_SIZE + 1)
        gz_data = _make_gz(big_data)
        raw = _make_email(gz_data, "bomb.xml.gz", "application/gzip")
        with pytest.raises(ZipBombError):
            extract_dmarc_attachments(raw)


# ── parse_mail_headers ─────────────────────────────────────────────────────────

class TestParseMailHeaders:
    def test_extracts_from(self):
        raw = _make_email(b"", "r.xml")
        headers = parse_mail_headers(raw)
        assert headers["from"] == "reports@google.com"

    def test_extracts_to(self):
        raw = _make_email(b"", "r.xml")
        headers = parse_mail_headers(raw)
        assert headers["to"] == "dmarc@reports.example.org"

    def test_extracts_subject(self):
        raw = _make_email(b"", "r.xml")
        headers = parse_mail_headers(raw)
        assert "example.com" in headers["subject"]

    def test_extracts_message_id(self):
        raw = _make_email(b"", "r.xml")
        headers = parse_mail_headers(raw)
        assert "test-001" in headers["message_id"]

    def test_garbage_returns_empty_dict(self):
        headers = parse_mail_headers(b"\x00\x01garbage")
        assert isinstance(headers, dict)
