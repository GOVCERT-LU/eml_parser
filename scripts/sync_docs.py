#!/usr/bin/env python3
"""Copy README.md and CHANGELOG.md to docs/, so the documentation shows them without a second copy to maintain.

Run by the `sync-docs` prek hook. The hook fails if it had to change a file, stage the result and commit again.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE_URL = 'https://github.com/GOVCERT-LU/eml_parser/blob/master/'

# source in the project root -> page in docs/
PAGES = {
    'README.md': 'index.md',
    'CHANGELOG.md': 'changelog.md',
}

# Relative links which have a page in the documentation, all others point to the repository.
DOC_LINKS = dict(PAGES)

LINK = re.compile(r'\]\((?!https?://|#|mailto:)([^)\s]+)\)')


def rewrite_links(text: str) -> str:
    """Make the relative links of a file in the project root work from docs/.

    Args:
        text: Markdown text.

    Returns:
        str: The text, with links to files of the repository pointing to the pages of the documentation or to GitHub.
    """

    def target(match: re.Match[str]) -> str:
        path = match.group(1)
        return f']({DOC_LINKS.get(path, BASE_URL + path)})'

    return LINK.sub(target, text)


def main() -> int:
    """Write the pages, return 1 if any of them changed."""
    changed = 0

    for source, page in PAGES.items():
        header = f'<!-- Generated from {source} by scripts/sync_docs.py (prek hook sync-docs), do not edit. -->\n\n'
        text = header + rewrite_links((ROOT / source).read_text(encoding='utf-8'))
        destination = ROOT / 'docs' / page

        if not destination.exists() or destination.read_text(encoding='utf-8') != text:
            destination.write_text(text, encoding='utf-8')
            print(f'Updated docs/{page} from {source}')  # noqa: T201
            changed = 1

    return changed


if __name__ == '__main__':
    sys.exit(main())
