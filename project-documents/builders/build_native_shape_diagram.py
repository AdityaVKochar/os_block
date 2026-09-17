from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls
from docx.shared import Inches


DOCUMENTS_DIR = Path(__file__).resolve().parents[1]
OUTPUT = DOCUMENTS_DIR / "B-SCAF_Architecture_Native_Shapes.docx"


def text_runs(text: str, size: int = 20, bold: bool = True) -> str:
    lines = text.split("\n")
    body = []
    for index, line in enumerate(lines):
        body.append(
            "<w:r>"
            "<w:rPr>"
            '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
            f'<w:b w:val="{1 if bold else 0}"/>'
            f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
            "</w:rPr>"
            f"<w:t>{escape(line)}</w:t>"
            "</w:r>"
        )
        if index < len(lines) - 1:
            body.append("<w:r><w:br/></w:r>")
    return "".join(body)


def shape(shape_id: str, x: int, y: int, width: int, height: int, text: str,
          fill: str = "#FFFFFF", radius: str = "12%", font_size: int = 20,
          bold: bool = True, stroke: str = "#000000", stroke_weight: str = "1.5pt") -> str:
    return f"""
    <v:roundrect id="{shape_id}" style="position:absolute;left:{x}px;top:{y}px;width:{width}px;height:{height}px"
        arcsize="{radius}" fillcolor="{fill}" strokecolor="{stroke}" strokeweight="{stroke_weight}">
      <v:textbox inset="8pt,5pt,8pt,5pt" style="mso-fit-shape-to-text:false">
        <w:txbxContent>
          <w:p>
            <w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="0"/></w:pPr>
            {text_runs(text, font_size, bold)}
          </w:p>
        </w:txbxContent>
      </v:textbox>
    </v:roundrect>"""


def label(shape_id: str, x: int, y: int, width: int, height: int, text: str,
          font_size: int = 24, bold: bool = True) -> str:
    return f"""
    <v:rect id="{shape_id}" style="position:absolute;left:{x}px;top:{y}px;width:{width}px;height:{height}px"
        filled="f" stroked="f">
      <v:textbox inset="2pt,2pt,2pt,2pt" style="mso-fit-shape-to-text:false">
        <w:txbxContent>
          <w:p>
            <w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="0"/></w:pPr>
            {text_runs(text, font_size, bold)}
          </w:p>
        </w:txbxContent>
      </v:textbox>
    </v:rect>"""


def connector(line_id: str, points: list[tuple[int, int]], arrow: bool = True,
              weight: str = "1.7pt") -> str:
    point_string = " ".join(f"{x},{y}" for x, y in points)
    end_arrow = 'endarrow="block"' if arrow else ""
    return f"""
    <v:polyline id="{line_id}" style="position:absolute" points="{point_string}"
        filled="f" strokecolor="#000000" strokeweight="{weight}">
      <v:stroke {end_arrow} joinstyle="round"/>
    </v:polyline>"""


def build_diagram_xml() -> str:
    items = []

    # Title and trust-boundary containers.
    items.append(label("title", 40, 15, 1720, 55, "B-SCAF: Lightweight Permissioned System-Call Audit Architecture", 30))
    groups = [
        ("g1", 20, 90, 365, 915, "1. EVENT SOURCE"),
        ("g2", 405, 90, 490, 915, "2. TRUSTED PROCESSING"),
        ("g3", 915, 90, 430, 915, "3. INTEGRITY LEDGER"),
        ("g4", 1365, 90, 395, 915, "4. INDEPENDENT AUDIT"),
    ]
    for shape_id, x, y, width, height, heading in groups:
        items.append(shape(shape_id, x, y, width, height, "", "#F4F4F4", "4%", 18, False, "#000000", "1.2pt"))
        items.append(label(f"{shape_id}_heading", x + 10, y + 12, width - 20, 40, heading, 20))

    # Event source.
    items.extend([
        shape("applications", 65, 190, 275, 105, "Linux Applications\nand Processes", "#FFFFFF", font_size=20),
        shape("syscalls", 65, 405, 275, 105, "Security-Relevant\nSystem Calls", "#FFFFFF", font_size=20),
        shape("collector", 65, 630, 275, 120, "auditd / eBPF /\nJSONL Collector", "#FFFFFF", font_size=20),
    ])
    items.extend([
        connector("a1", [(202, 295), (202, 405)]),
        connector("a2", [(202, 510), (202, 630)]),
    ])

    # Trusted processing.
    items.extend([
        shape("policy", 465, 165, 370, 115, "Allow-List and\nSensitive-Field Redaction", "#FFFFFF", font_size=19),
        shape("normalizer", 465, 365, 370, 105, "Canonical Event\nNormalization", "#FFFFFF", font_size=20),
        shape("hashchain", 465, 565, 370, 105, "SHA-256 Event\nHash Chain", "#FFFFFF", font_size=20),
        shape("eventstore", 465, 780, 370, 115, "Append-Only Raw\nEvent Store", "#FFFFFF", font_size=20),
    ])
    items.extend([
        connector("a3", [(340, 690), (420, 690), (420, 222), (465, 222)]),
        connector("a4", [(650, 280), (650, 365)]),
        connector("a5", [(650, 470), (650, 565)]),
        connector("a6", [(650, 670), (650, 780)]),
    ])

    # Integrity ledger.
    items.extend([
        shape("merkle", 965, 170, 330, 105, "Merkle Batch\nBuilder", "#FFFFFF", font_size=20),
        shape("checkpoint", 965, 385, 330, 135, "Checkpoint Block\nMerkle Root + Previous\nBlock Hash", "#FFFFFF", font_size=19),
        shape("signer", 965, 675, 145, 115, "Ed25519\nSigner", "#FFFFFF", font_size=19),
        shape("ledger", 1150, 675, 145, 115, "Checkpoint\nLedger", "#FFFFFF", font_size=19),
    ])
    items.extend([
        connector("a7", [(835, 617), (925, 617), (925, 222), (965, 222)]),
        connector("a8", [(1130, 275), (1130, 385)]),
        connector("a9", [(1037, 675), (1037, 590), (1085, 520)]),
        connector("a10", [(1215, 520), (1222, 675)]),
    ])

    # Independent audit and witness.
    items.extend([
        shape("witness", 1410, 170, 305, 110, "Permissioned\nRemote Witness", "#FFFFFF", font_size=20),
        shape("proof", 1410, 405, 305, 110, "Offline Merkle\nProof Verifier", "#FFFFFF", font_size=20),
        shape("verifier", 1410, 705, 305, 120, "Full Local\nIntegrity Verifier", "#FFFFFF", font_size=20),
    ])
    items.extend([
        connector("a11", [(1295, 742), (1348, 742), (1348, 225), (1410, 225)]),
        connector("a12", [(1295, 452), (1410, 460)]),
        connector("a13", [(1295, 750), (1410, 765)]),
        connector("a14", [(835, 837), (1370, 837), (1370, 790), (1410, 790)]),
    ])

    items.append(label(
        "note", 300, 940, 1180, 42,
        "Raw system-call events remain local. Only signed checkpoint metadata is replicated to the witness.",
        18, False,
    ))

    return "".join(items)


def build_document():
    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width = Inches(11.69)
    section.page_height = Inches(8.27)
    section.top_margin = Inches(0.25)
    section.bottom_margin = Inches(0.25)
    section.left_margin = Inches(0.25)
    section.right_margin = Inches(0.25)
    section.header_distance = Inches(0.1)
    section.footer_distance = Inches(0.1)

    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_after = 0

    pict_xml = f"""
    <w:pict xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        xmlns:v="urn:schemas-microsoft-com:vml"
        xmlns:o="urn:schemas-microsoft-com:office:office">
      <v:group id="bscaf_architecture" coordorigin="0,0" coordsize="1800,1030"
          style="position:relative;width:10.95in;height:6.65in" filled="f" stroked="f">
        {build_diagram_xml()}
      </v:group>
    </w:pict>
    """
    run = paragraph.add_run()
    run._r.append(parse_xml(pict_xml))

    doc.core_properties.title = "B-SCAF Architecture Diagram"
    doc.core_properties.subject = "Native editable Word shape diagram"
    doc.core_properties.author = ""
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build_document()
