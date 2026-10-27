"""Static tables used by the parser."""

import string

# Common file name extensions: a bare "invoice.pdf" in a text is a file name, not a domain. An extension which is a TLD (zip, mov, sh, py, ...)
# is not a file name for the parser, whether it is listed here or not (the public suffix list decides), so this table does not go stale.
FILE_EXTENSIONS = frozenset(
    """
    7z asp aspx avi bak bat bin bmp bz2 cfg cgi cmd cpl crt css csv dat db dll doc docm docx dotm dotx eml eot exe flv gif gz hta htm html ico img ini iso
    jar jpeg jpg js jsp json lnk log mkv mp3 mp4 mpg msg msi odp ods odt otf pdf php png pot potm potx ppt pptm pptx ps1 psd rar rtf scr svg sys tar tgz
    tif tiff tmp ttf txt vbe vbs wav webp wmv woff woff2 wsf xls xlsb xlsm xlsx xml xz yaml yml
    """.split()
)

# Attachments which carry links or run something (scripts, shortcuts, web pages, SVG, invitations): they are scanned like the text of the e-mail.
# Data formats (XML, JSON, CSV, logs, ...) are left out on purpose: they are full of namespace and schema URLs and of data nobody wants as indicators.
TEXT_ATTACHMENT_EXTENSIONS = tuple(
    f'.{extension}'
    for extension in """
    bat cmd eml hta htm html ics js jse mht mhtml php ps1 psm1 py rtf sh shtml svg txt url vbe vbs wsf wsh xhtml
    """.split()
)
TEXT_ATTACHMENT_CONTENT_TYPES = frozenset(
    """
    application/hta application/javascript application/rtf application/x-javascript application/x-sh application/xhtml+xml image/svg+xml
    """.split()
)

# Attachments (not inline text) larger than this are not scanned as text; the size is the one of the encoded payload.
MAX_TEXT_ATTACHMENT_SIZE = 10 * 1024 * 1024

# File name extensions of programs and scripts, used to detect disguised executables.
EXECUTABLE_EXTENSIONS = frozenset('bat cmd com cpl dll exe hta jar js jse lnk msi pif ps1 reg scr vbe vbs wsf wsh'.split())

# File name extensions of documents and pictures, which a disguised executable is claiming to be.
DECOY_EXTENSIONS = frozenset('bmp csv doc docm docx gif htm html jpeg jpg pdf png ppt pptm pptx rtf tif tiff txt xls xlsm xlsx'.split())

EXECUTABLE_MIME_TYPES = frozenset(
    """
    application/vnd.microsoft.portable-executable application/x-dosexec application/x-executable application/x-msdownload
    application/x-mach-binary application/x-sharedlib application/x-pie-executable
    """.split()
)

# Header values longer than this are not run through the structured header parsers of the stdlib (their cost grows with the square of the length).
# Real headers are far shorter: RFC 5322 recommends lines of 78 and limits them to 998 characters.
MAX_PARSED_HEADER_SIZE = 8 * 1024

# Defence in depth against messages made of huge numbers of header fields (MSL-2026-030). Structured parsing of a header field costs up to
# about 0.6 ms (address and Received fields), so even with linear parsing a message of small fields keeps a worker busy in proportion to its
# size. At most this many header fields and this many bytes of header values, counted over the message and all its MIME parts in order, are
# run through the structured header parsers. The fields beyond are kept with their raw value, like values longer than MAX_PARSED_HEADER_SIZE,
# and the message gets a HeaderParsingLimitDefect. Real messages have from a few dozen to a few hundred header fields.
MAX_PARSED_HEADER_FIELDS = 10_000
MAX_PARSED_HEADER_BYTES = 2 * 1024 * 1024

# The first occurrence of these fields in the message and in each MIME part is always parsed, whatever the limits above: the analysis relies on
# them and the MIME structure is built from the Content-* fields, so junk fields in front of them must not push them out of the limits.
ALWAYS_PARSED_HEADERS = frozenset(
    """
    from sender reply-to to cc bcc subject date message-id in-reply-to return-path
    mime-version content-type content-disposition content-transfer-encoding content-id content-description
    """.split()
)

# Characters allowed in a header field name (RFC 5322 ftext): printable ASCII except space and colon.
FIELD_NAME_BYTES = (string.ascii_letters + string.digits + string.punctuation.replace(':', '')).encode()
