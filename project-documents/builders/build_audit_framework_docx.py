from pathlib import Path
import re
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.section import WD_SECTION
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

DOCUMENTS_DIR = Path(__file__).resolve().parents[1]
SOURCE = DOCUMENTS_DIR / "Blockchain_System_Call_Audit_Framework.txt"
OUTPUT = DOCUMENTS_DIR / "Blockchain_System_Call_Audit_Framework.docx"


def set_run_font(run, size=None, bold=None):
    run.font.name = "Times New Roman"
    run._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
    run._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
    run.font.color.rgb = RGBColor(0, 0, 0)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold


def add_hyperlink(paragraph, text, url, size=10):
    part = paragraph.part
    rel_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), rel_id)
    new_run = OxmlElement("w:r")
    r_pr = OxmlElement("w:rPr")
    r_fonts = OxmlElement("w:rFonts")
    r_fonts.set(qn("w:ascii"), "Times New Roman")
    r_fonts.set(qn("w:hAnsi"), "Times New Roman")
    r_pr.append(r_fonts)
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "000000")
    r_pr.append(color)
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    r_pr.append(underline)
    sz = OxmlElement("w:sz")
    sz.set(qn("w:val"), str(int(size * 2)))
    r_pr.append(sz)
    new_run.append(r_pr)
    text_el = OxmlElement("w:t")
    text_el.text = text
    new_run.append(text_el)
    hyperlink.append(new_run)
    paragraph._p.append(hyperlink)


def add_text_with_doi(paragraph, text, size=10):
    match = re.search(r"(https://doi\.org/\S+)$", text)
    if match:
        prefix = text[:match.start()]
        r = paragraph.add_run(prefix)
        set_run_font(r, size=size)
        add_hyperlink(paragraph, match.group(1), match.group(1), size=size)
    else:
        r = paragraph.add_run(text)
        set_run_font(r, size=size)


def configure_styles(doc):
    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name = "Times New Roman"
    normal._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
    normal.font.size = Pt(11)
    normal.font.color.rgb = RGBColor(0, 0, 0)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.15

    for name, size, before, after in [("Heading 1", 14, 12, 6), ("Heading 2", 12, 10, 4), ("Heading 3", 11, 8, 3)]:
        style = styles[name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True

    for name in ("List Bullet", "List Number"):
        style = styles[name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
        style.font.size = Pt(11)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_after = Pt(3)
        style.paragraph_format.line_spacing = 1.15


def add_page_number(section):
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Page ")
    set_run_font(run, size=10)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    p._p.append(field)


def is_h1(line):
    return bool(re.match(r"^\d+\. [A-Z][A-Z /-]+$", line))


def is_h2(line):
    return bool(re.match(r"^[A-D]\. [A-Z].+$", line)) or line in {"PROJECT BRIEF (humanized, presentation-ready)"}


def main():
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)
    section.header_distance = Inches(0.49)
    section.footer_distance = Inches(0.49)
    configure_styles(doc)
    add_page_number(section)

    lines = [line.strip() for line in SOURCE.read_text(encoding="utf-8").splitlines()]
    title = lines[0]
    subtitle = lines[1]
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(title)
    set_run_font(r, size=16, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(16)
    r = p.add_run(subtitle)
    set_run_font(r, size=12, bold=False)

    in_bibliography = False
    for line in lines[2:]:
        if not line or line == "END OF DOCUMENT":
            continue
        if line == "PROJECT BRIEF (humanized, presentation-ready)":
            continue
        if line == "11. VERIFIED RECENT PAPER BIBLIOGRAPHY (40 PAPERS)":
            in_bibliography = True
        if is_h1(line):
            p = doc.add_paragraph(style="Heading 1")
            r = p.add_run(line)
            set_run_font(r, size=14, bold=True)
            continue
        if is_h2(line):
            p = doc.add_paragraph(style="Heading 2")
            r = p.add_run(line)
            set_run_font(r, size=12, bold=True)
            continue
        if line.startswith("• "):
            p = doc.add_paragraph(style="List Bullet")
            r = p.add_run(line[2:])
            set_run_font(r, size=11)
            continue
        if re.match(r"^\d+\. ", line) and in_bibliography:
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.15)
            p.paragraph_format.first_line_indent = Inches(-0.15)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.05
            add_text_with_doi(p, line, size=10)
            continue
        if line.startswith(("Phase ", "Objective ")):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.space_after = Pt(4)
            match = re.match(r"^([^:]+):\s*(.*)$", line)
            if match:
                r = p.add_run(match.group(1) + ": ")
                set_run_font(r, size=11, bold=True)
                r = p.add_run(match.group(2))
                set_run_font(r, size=11)
            else:
                r = p.add_run(line)
                set_run_font(r, size=11)
            continue
        if line.startswith("    ") or "-->" in line or line.startswith("|"):
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.35)
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(line)
            set_run_font(r, size=10)
            continue
        p = doc.add_paragraph()
        if line.startswith("Selection note:") or line.startswith("Novelty claim,") or line.startswith("Suggested block fields:"):
            r = p.add_run(line)
            set_run_font(r, size=11, bold=line.startswith(("Selection note:", "Suggested block fields:")))
        else:
            add_text_with_doi(p, line, size=11)

    doc.core_properties.title = title
    doc.core_properties.subject = "Blockchain-based system call audit framework"
    doc.core_properties.author = ""
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
