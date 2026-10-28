from pdftrace.analyzers.metadata import MetadataAnalyzer, parse_xmp


def test_info_and_custom(analyses) -> None:  # type: ignore[no-untyped-def]
    m = analyses["simple"].metadata
    assert m.info_value("Author") == "Tester"
    assert m.info_value("Title") == "<script>alert(1)</script>"
    assert [c.field for c in m.custom] == ["CaseRef"]
    assert all(v.source == "pdf_info_dictionary" for v in m.info)
    assert m.xmp_present is False
    assert m.pdf_version == "1.4" and m.page_count == 1


def test_xmp_and_comparison(analyses) -> None:  # type: ignore[no-untyped-def]
    m = analyses["rich"].metadata
    assert m.xmp_present
    assert m.xmp_value("dc:creator") == "Bob"
    assert m.xmp_value("xmp:CreatorTool") == "FixtureWriter"
    status = {c.field: c.status for c in m.comparisons}
    assert status["Author"] == "difference"
    assert status["CreationDate"] == "match"  # same instant, different syntax
    assert status["Producer"] == "match"


def test_earlier_revision_recovered(analyses) -> None:  # type: ignore[no-untyped-def]
    revisions = analyses["incremental"].metadata.info_revisions
    assert [r.values["Author"] for r in revisions] == ["Carol", "Alice"]
    assert revisions[1].source.startswith("earlier_revision")


def test_xmp_structures() -> None:
    raw = b"""<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
      xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmpMM:DocumentID="uuid:1">
    <xmpMM:History><rdf:Seq><rdf:li rdf:parseType="Resource"><stEvt:action>saved</stEvt:action>
    <stEvt:when>2020-01-01T00:00:00Z</stEvt:when></rdf:li></rdf:Seq></xmpMM:History>
    </rdf:Description></rdf:RDF></x:xmpmeta>"""
    values = {v.field: v.value for v in parse_xmp(raw)}
    assert values["xmpMM:DocumentID"] == "uuid:1"
    assert values["xmpMM:History[1]/stEvt:action"] == "saved"
    assert values["xmpMM:History[1]/stEvt:when"] == "2020-01-01T00:00:00Z"


def test_standalone_analyzer(pdfs) -> None:  # type: ignore[no-untyped-def]
    result = MetadataAnalyzer().run_standalone(pdfs["rich"])
    assert result.section == "metadata" and result.payload.info_value("Author") == "Alice"


def test_xmp_with_entities_is_refused() -> None:
    import xml.etree.ElementTree as ET

    import pytest

    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x:xmpmeta xmlns:x="adobe:ns:meta/">&a;</x:xmpmeta>'
    with pytest.raises(ET.ParseError):
        parse_xmp(bomb)
