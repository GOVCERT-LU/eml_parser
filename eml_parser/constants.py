"""Static tables used by the parser."""

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
