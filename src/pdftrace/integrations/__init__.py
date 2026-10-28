"""Adapters around external tools and third-party libraries.

Nothing outside this package imports Poppler, pdfminer/pdfplumber or fontTools
directly, so an integration can be replaced or mocked without touching the
analyzers or the GUI.
"""
