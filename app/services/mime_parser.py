"""
Safe MIME parser for DMARC report emails.
Extracts DMARC attachments from incoming SMTP messages.
"""
import gzip
import hashlib
import io
import logging
import zipfile
import zlib
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message

from app.config import settings

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".xml", ".xml.gz", ".gz", ".zip"}

# gzip format: magic bytes and the zlib window setting that expects a gzip header
GZIP_MAGIC = b"\x1f\x8b"
GZIP_WBITS = 16 + zlib.MAX_WBITS
GZIP_CHUNK = 65536


@dataclass
class ExtractedAttachment:
    filename: str
    content_type: str
    data: bytes
    sha256: str
    source_filename: str | None = None  # original name if from ZIP


class MimeParseError(Exception):
    pass


class ZipBombError(MimeParseError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_unzip(zip_bytes: bytes) -> list[tuple[str, bytes]]:
    """
    Safely extract XML files from a ZIP.
    Protects against zip bombs and path traversal.
    """
    results = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        if len(names) > settings.ARCHIVE_MAX_FILES:
            raise MimeParseError(
                f"Das ZIP-Archiv enthält {len(names)} Dateien, erlaubt sind höchstens {settings.ARCHIVE_MAX_FILES}"
            )

        total_unzipped = 0
        for name in names:
            info = zf.getinfo(name)
            # Reject path traversal
            if ".." in name or name.startswith("/"):
                logger.warning("ZIP contains suspicious path: %s", name)
                continue

            # Check declared uncompressed size (can be spoofed, checked again on read)
            if info.file_size > settings.ARCHIVE_MAX_UNPACKED_BYTES:
                raise ZipBombError(
                    f"Der ZIP-Eintrag {name!r} gibt {info.file_size} Bytes an, "
                    f"erlaubt sind höchstens {settings.ARCHIVE_MAX_UNPACKED_BYTES}"
                )

            lower = name.lower()
            if not any(lower.endswith(ext) for ext in (".xml", ".xml.gz", ".gz")):
                logger.debug("Skipping non-XML ZIP entry: %s", name)
                continue

            try:
                # Read with size limit to catch bombs
                with zf.open(name) as f:
                    data = bytearray()
                    chunk = f.read(65536)
                    while chunk:
                        data.extend(chunk)
                        total_unzipped += len(chunk)
                        if total_unzipped > settings.ARCHIVE_MAX_UNPACKED_BYTES:
                            raise ZipBombError(
                                f"Der Inhalt des ZIP-Archivs überschreitet {settings.ARCHIVE_MAX_UNPACKED_BYTES} Bytes"
                            )
                        chunk = f.read(65536)
                results.append((name, bytes(data)))
            except (zipfile.BadZipFile, KeyError) as exc:
                logger.warning("Could not extract %s from ZIP: %s", name, exc)

    return results


def _safe_gunzip(gz_bytes: bytes) -> bytes:
    """
    Decompress gzip data with size limit.
    Reads concatenated members and ignores trailing bytes that start no new member:
    some reporters (Mimecast) append a line break after the gzip stream.
    """
    limit = settings.ARCHIVE_MAX_UNPACKED_BYTES
    out = bytearray()
    remaining = gz_bytes
    members = 0
    while remaining[:2] == GZIP_MAGIC:
        decompressor = zlib.decompressobj(wbits=GZIP_WBITS)
        pending = remaining
        while True:
            piece = decompressor.decompress(pending, GZIP_CHUNK)
            out.extend(piece)
            if len(out) > limit:
                raise ZipBombError(f"Der entpackte GZ-Inhalt überschreitet {limit} Bytes")
            pending = decompressor.unconsumed_tail
            if decompressor.eof:
                break
            if not pending and not piece:
                raise gzip.BadGzipFile("Die GZ-Datei endet mitten im Inhalt")
        remaining = decompressor.unused_data
        members += 1
    if members == 0:
        raise gzip.BadGzipFile("Die Datei ist keine GZ-Datei")
    if remaining.strip():
        logger.warning("Ignoring %d bytes after the gzip data", len(remaining))
    return bytes(out)


def extract_dmarc_attachments(raw_mail: bytes) -> list[ExtractedAttachment]:
    """
    Parse a raw MIME email and extract DMARC report attachments.
    Returns a list of ExtractedAttachment objects ready for parsing.
    """
    try:
        msg: Message = message_from_bytes(raw_mail)
    except Exception as exc:
        raise MimeParseError(f"Die Mail ließ sich nicht lesen: {exc}") from exc

    attachments: list[ExtractedAttachment] = []

    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        filename = part.get_filename() or ""
        lower_fn = filename.lower()

        # Identify DMARC attachment candidates
        is_candidate = (
            content_disposition in ("attachment", "inline")
            or "xml" in content_type
            or "zip" in content_type
            or "gzip" in content_type
            or "x-gzip" in content_type
            or lower_fn.endswith((".xml", ".xml.gz", ".gz", ".zip"))
        )
        if not is_candidate:
            continue

        try:
            payload = part.get_payload(decode=True)
        except Exception as exc:
            logger.warning("Could not decode attachment %s: %s", filename, exc)
            continue

        if not payload:
            continue

        if len(payload) > settings.ARCHIVE_MAX_ATTACHMENT_BYTES:
            logger.warning("Attachment %s too large (%d bytes), skipping", filename, len(payload))
            continue

        try:
            extracted = _process_attachment(filename or "attachment", content_type, payload)
            attachments.extend(extracted)
        except ZipBombError:
            raise
        except Exception as exc:
            logger.warning("Error processing attachment %s: %s", filename, exc)
            # Don't crash – log and skip unsupported attachments

    return attachments


def _process_attachment(
    filename: str, content_type: str, data: bytes
) -> list[ExtractedAttachment]:
    lower = filename.lower()

    if lower.endswith(".zip"):
        entries = _safe_unzip(data)
        results = []
        for name, entry_data in entries:
            inner = _process_attachment(name, "application/octet-stream", entry_data)
            for att in inner:
                att.source_filename = filename
            results.extend(inner)
        return results

    if lower.endswith(".xml.gz") or lower.endswith(".gz"):
        try:
            xml_data = _safe_gunzip(data)
        except gzip.BadGzipFile as exc:
            raise MimeParseError(f"{filename} ist keine gültige GZ-Datei: {exc}") from exc
        plain_name = filename[:-3] if lower.endswith(".gz") else filename
        return [ExtractedAttachment(
            filename=plain_name,
            content_type="application/xml",
            data=xml_data,
            sha256=sha256_hex(xml_data),
        )]

    if lower.endswith(".xml") or "xml" in content_type:
        return [ExtractedAttachment(
            filename=filename,
            content_type="application/xml",
            data=data,
            sha256=sha256_hex(data),
        )]

    logger.debug("Unsupported attachment type: %s (%s)", filename, content_type)
    return []


def parse_mail_headers(raw_mail: bytes) -> dict:
    """Extract relevant headers from a raw MIME message."""
    try:
        msg = message_from_bytes(raw_mail)
    except Exception:
        return {}
    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
    }
