"""Native, editable Word charts for the final report (no pictures).

Each graph is a real Word chart: a DrawingML chart part whose numbers live in
an embedded Excel workbook, generated with python-pptx's chart engine and
placed inline with python-docx. In Word you can click a chart to restyle it,
or choose Edit Data to see and change the numbers behind it.

Only the essential results are charted: live overhead and replay throughput.
The attack results are a colour-coded table in the report. Colours follow the
validated palette (blue, orange); gridlines and axes stay quiet, values are
labelled on the bars, and a legend appears only when two series share a chart.
"""

from __future__ import annotations

from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.opc.part import Part
from docx.oxml import parse_xml as parse_docx_xml
from docx.oxml.ns import nsdecls
from lxml import etree
from pptx.chart.chart import Chart
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION, XL_TICK_MARK
from pptx.oxml import parse_xml as parse_chart_xml
from pptx.util import Pt

BLUE, ORANGE = RGBColor(0x2A, 0x78, 0xD6), RGBColor(0xEB, 0x68, 0x34)
INK, INK_2, MUTED = RGBColor(0x0B, 0x0B, 0x0B), RGBColor(0x52, 0x51, 0x4E), RGBColor(0x89, 0x87, 0x81)
GRID, AXIS = RGBColor(0xE1, 0xE0, 0xD9), RGBColor(0xC3, 0xC2, 0xB7)
FONT = "Arial"
EMU_PER_INCH = 914400
CHART_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml"
XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DRAWING = (
    "<w:drawing {ns}>"
    '<wp:inline distT="0" distB="0" distL="0" distR="0">'
    '<wp:extent cx="{cx}" cy="{cy}"/>'
    '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
    '<wp:docPr id="{shape_id}" name="Chart {shape_id}"/>'
    "<wp:cNvGraphicFramePr/>"
    '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
    '<c:chart r:id="{rid}"/>'
    "</a:graphicData></a:graphic>"
    "</wp:inline></w:drawing>"
)
LABELS = {"plain log": "Plain log", "hash chain only": "Hash chain only", "plain log + fsync/100": "Plain log + fsync per 100"}


def insert_chart(doc, chart_type, data: CategoryChartData, configure, width: float = 6.3, height: float = 2.8):
    """Add a centred paragraph holding a native chart built from `data` and styled by `configure`."""
    space = parse_chart_xml(data.xml_bytes(chart_type))
    configure(Chart(space, None))
    # The embedded workbook will be the chart part's first (and only) relationship.
    external = space.get_or_add_externalData()
    external.rId = "rId1"
    external.get_or_add_autoUpdate().set("val", "0")
    package = doc.part.package
    blob = etree.tostring(space, xml_declaration=True, encoding="UTF-8", standalone=True)
    chart_part = Part(package.next_partname("/word/charts/chart%d.xml"), CHART_CONTENT_TYPE, blob, package)
    chart_rid = doc.part.relate_to(chart_part, RT.CHART)
    workbook = Part(package.next_partname("/word/embeddings/Microsoft_Excel_Worksheet%d.xlsx"), XLSX_CONTENT_TYPE, data.xlsx_blob, package)
    if chart_part.relate_to(workbook, RT.PACKAGE) != "rId1":
        raise RuntimeError("embedded workbook did not get the expected relationship id")
    drawing = parse_docx_xml(DRAWING.format(
        ns=nsdecls("w", "wp", "a", "c", "r"), cx=int(width * EMU_PER_INCH), cy=int(height * EMU_PER_INCH),
        shape_id=doc.part.next_id, rid=chart_rid,
    ))
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.keep_with_next = True
    paragraph.add_run()._r.append(drawing)
    return paragraph


def _style_text(font, size=8, color=INK_2, bold=False):
    font.name = FONT
    font.size = Pt(size)
    font.bold = bold
    font.color.rgb = color


def _quiet_axes(chart, value_title: str, number_format: str) -> None:
    """Recessive chrome: hairline grid, no value-axis line, muted tick labels."""
    _style_text(chart.font)
    value = chart.value_axis
    value.minimum_scale = 0
    value.has_major_gridlines = True
    value.major_gridlines.format.line.color.rgb = GRID
    value.major_gridlines.format.line.width = Pt(0.75)
    value.format.line.fill.background()
    value.major_tick_mark = XL_TICK_MARK.NONE
    value.tick_labels.number_format = number_format
    value.tick_labels.number_format_is_linked = False
    _style_text(value.tick_labels.font, color=MUTED)
    value.has_title = True
    value.axis_title.text_frame.text = value_title
    _style_text(value.axis_title.text_frame.paragraphs[0].runs[0].font)
    category = chart.category_axis
    category.format.line.color.rgb = AXIS
    category.major_tick_mark = XL_TICK_MARK.NONE
    _style_text(category.tick_labels.font)


def live_overhead(doc, live: dict):
    """Median workload time per setup, labelled with the slowdown against no tracing."""
    phases = [("baseline", "No tracing"), ("tracing only", "eBPF tracing only"), ("B-SCAF", "B-SCAF capture + 3 witnesses")]
    overview = live["overview"]
    data = CategoryChartData(number_format="0.00")
    data.categories = [name for _, name in phases]
    data.add_series("Median workload time (s)", [round(overview[key]["workload_seconds"], 3) for key, _ in phases])

    def configure(chart: Chart) -> None:
        chart.has_title = False
        chart.has_legend = False
        plot = chart.plots[0]
        plot.gap_width = 120
        plot.vary_by_categories = False
        series = plot.series[0]
        series.format.fill.solid()
        series.format.fill.fore_color.rgb = BLUE
        for index, (key, _) in enumerate(phases):
            seconds, slowdown = overview[key]["workload_seconds"], overview[key]["slowdown_percent"]
            label = series.points[index].data_label
            label.position = XL_LABEL_POSITION.OUTSIDE_END
            label.text_frame.text = f"{seconds:.2f} s" if key == "baseline" else f"{seconds:.2f} s ({slowdown:+.0f}%)"
            _style_text(label.text_frame.paragraphs[0].runs[0].font, color=INK)
        _quiet_axes(chart, "Workload time (s)", "0.0")

    return insert_chart(doc, XL_CHART_TYPE.COLUMN_CLUSTERED, data, configure, height=2.7)


def throughput(doc, real: dict):
    """Events per second per configuration; baselines in orange, B-SCAF in blue."""
    rows = list(reversed(real["bench"]["results"]))  # horizontal bars draw bottom-up; keep the table's order top-down
    data = CategoryChartData(number_format="#,##0")
    data.categories = [LABELS.get(row["label"], row["label"]) for row in rows]
    data.add_series("Baseline logging", [round(row["events_per_second"]) if row["mode"] != "bscaf" else None for row in rows])
    data.add_series("B-SCAF", [round(row["events_per_second"]) if row["mode"] == "bscaf" else None for row in rows])

    def configure(chart: Chart) -> None:
        chart.has_title = False
        plot = chart.plots[0]
        plot.gap_width = 60
        plot.overlap = 100  # one bar per configuration: each row has a value in only one series
        plot.vary_by_categories = False
        for series, color in zip(plot.series, (ORANGE, BLUE)):
            series.format.fill.solid()
            series.format.fill.fore_color.rgb = color
        plot.has_data_labels = True
        labels = plot.data_labels
        labels.number_format = "#,##0"
        labels.number_format_is_linked = False
        labels.position = XL_LABEL_POSITION.OUTSIDE_END
        _style_text(labels.font, color=INK)
        chart.has_legend = True
        chart.legend.position = XL_LEGEND_POSITION.BOTTOM
        chart.legend.include_in_layout = False
        _style_text(chart.legend.font)
        _quiet_axes(chart, "Events per second (one core)", "#,##0")

    return insert_chart(doc, XL_CHART_TYPE.BAR_CLUSTERED, data, configure, height=3.3)
