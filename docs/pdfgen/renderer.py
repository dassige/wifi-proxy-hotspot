"""
tech-doc-pdf renderer
=====================
Reusable PDF building engine for technical documentation.
Called by the generated build script; never run directly.

Usage (from build script):
    from renderer import DocBuilder
    b = DocBuilder(output_path, title, subtitle, version, org)
    b.title_bar()
    b.section("1", "Overview")
    b.body("Some introductory text.")
    b.table(["Col A", "Col B"], [["r1c1", "r1c2"]], col_ratios=[0.4, 0.6])
    b.code("sudo apt update\nsudo apt upgrade")
    b.note("This is an informational note.")
    b.warning("This is a warning.")
    b.bullets(["Item one", "Item two"])
    b.step("Step 1 — Do something", body="Optional body text.", code="some command")
    b.spacer(4)
    b.build()
"""

import datetime
from reportlab import rl_config
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable
)

# ── Palette ────────────────────────────────────────────────────────────────
NEAR_BLACK  = colors.HexColor('#1e1e1e')   # code block bg
WHITE       = colors.white
DARK_GREY   = colors.HexColor('#333333')
MID_GREY    = colors.HexColor('#555555')
LIGHT_GREY  = colors.HexColor('#f2f2f2')
BORDER_GREY = colors.HexColor('#cccccc')
HEADER_BG   = colors.HexColor('#1a5276')   # title bar — same blue as section headings
SECTION_BG  = colors.HexColor('#1a5276')   # blue section heading
NOTE_BG     = colors.HexColor('#fff8e1')
NOTE_BORDER = colors.HexColor('#f0a500')
WARN_BG     = colors.HexColor('#fff3f3')
WARN_BORDER = colors.HexColor('#cc0000')

W, H = A4
MARGIN_L  = 20 * mm
MARGIN_R  = 20 * mm
MARGIN_T  = 18 * mm
MARGIN_B  = 18 * mm
CONTENT_W = W - MARGIN_L - MARGIN_R


# ── Custom Flowables ───────────────────────────────────────────────────────

class TitleBar(Flowable):
    def __init__(self, title, subtitle=None, width=CONTENT_W):
        super().__init__()
        self.title    = title
        self.subtitle = subtitle
        self._width   = width
        self._height  = 54 if subtitle else 36

    def wrap(self, aw, ah): return self._width, self._height

    def draw(self):
        c = self.canv
        c.setFillColor(HEADER_BG)
        c.rect(0, 0, self._width, self._height, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('Helvetica-Bold', 14)
        c.drawString(10, self._height - 22, self.title)
        if self.subtitle:
            c.setFont('Helvetica', 8)
            c.setFillColor(colors.HexColor('#aaaaaa'))
            c.drawString(10, 8, self.subtitle)


class SectionHeading(Flowable):
    def __init__(self, number, text, width=CONTENT_W):
        super().__init__()
        self.number  = number
        self.text    = text
        self._width  = width
        self._height = 18

    def wrap(self, aw, ah): return self._width, self._height

    def draw(self):
        c = self.canv
        c.setFillColor(SECTION_BG)
        c.roundRect(0, 0, self._width, self._height, 3, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('Helvetica-Bold', 9)
        label = f"{self.number}.  {self.text}" if self.number else self.text
        c.drawString(8, 5, label)


class CodeBlock(Flowable):
    LINE_H  = 12
    PADDING = 8

    def __init__(self, code, width=CONTENT_W):
        super().__init__()
        self.lines   = code.strip().split('\n')
        self._width  = width
        self._height = len(self.lines) * self.LINE_H + self.PADDING * 2

    def wrap(self, aw, ah): return self._width, self._height

    def draw(self):
        c = self.canv
        c.setFillColor(NEAR_BLACK)
        c.roundRect(0, 0, self._width, self._height, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('Courier', 7.5)
        y = self._height - self.PADDING - 9
        for line in self.lines:
            c.drawString(self.PADDING, y, line)
            y -= self.LINE_H


class CalloutBox(Flowable):
    """Note (amber) or Warning (red) callout box with wrapped text."""
    PAD = 8
    LINE_H = 11

    def __init__(self, text, style='note', width=CONTENT_W):
        super().__init__()
        self.text    = text
        self.style   = style
        self._width  = width
        # Estimate wrapped height
        prefix       = '■ WARNING:  ' if style == 'warning' else '■ NOTE:  '
        full_text    = prefix + text
        chars_w      = int((width - self.PAD * 2) / 5.2)
        lines        = max(1, -(-len(full_text) // chars_w))  # ceil div
        self._height = lines * self.LINE_H + self.PAD * 2

    def wrap(self, aw, ah): return self._width, self._height

    def draw(self):
        c      = self.canv
        bg     = WARN_BG     if self.style == 'warning' else NOTE_BG
        border = WARN_BORDER if self.style == 'warning' else NOTE_BORDER
        prefix = '■ WARNING:  ' if self.style == 'warning' else '■ NOTE:  '

        c.setFillColor(bg)
        c.roundRect(0, 0, self._width, self._height, 4, fill=1, stroke=0)
        c.setStrokeColor(border)
        c.setLineWidth(1)
        c.roundRect(0, 0, self._width, self._height, 4, fill=0, stroke=1)

        # Draw prefix in bold colour
        c.setFont('Helvetica-Bold', 8)
        c.setFillColor(border)
        prefix_w = c.stringWidth(prefix, 'Helvetica-Bold', 8)
        c.drawString(self.PAD, self._height - self.PAD - 8, prefix)

        # Draw body text in dark grey, word-wrapped
        c.setFont('Helvetica', 8)
        c.setFillColor(DARK_GREY)
        max_w   = self._width - self.PAD * 2
        words   = self.text.split()
        lines   = []
        current = ''
        for word in words:
            test = (current + ' ' + word).strip()
            if c.stringWidth(prefix + test if not lines else test, 'Helvetica', 8) <= max_w - (prefix_w if not lines else 0):
                current = test
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)

        y = self._height - self.PAD - 8
        for i, line in enumerate(lines):
            x = self.PAD + prefix_w if i == 0 else self.PAD
            c.drawString(x, y, line)
            y -= self.LINE_H


# ── Paragraph styles ───────────────────────────────────────────────────────
BODY_STYLE = ParagraphStyle(
    'body', fontName='Helvetica', fontSize=8.5, leading=13,
    textColor=MID_GREY, spaceBefore=2, spaceAfter=4,
)
STEP_STYLE = ParagraphStyle(
    'step', fontName='Helvetica', fontSize=8.5, leading=13,
    textColor=MID_GREY, leftIndent=10, spaceBefore=1, spaceAfter=3,
)
BULLET_STYLE = ParagraphStyle(
    'bullet', fontName='Helvetica', fontSize=8.5, leading=12,
    textColor=MID_GREY, leftIndent=14, spaceBefore=1, spaceAfter=2,
)


def _make_table(headers, rows, col_widths):
    data = [headers] + rows
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0),  colors.HexColor('#aed6f1')),
        ('TEXTCOLOR',      (0, 0), (-1, 0),  colors.HexColor('#1a1a1a')),
        ('FONTNAME',       (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',           (0, 0), (-1, -1), 0.4, BORDER_GREY),
        ('LEFTPADDING',    (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',   (0, 0), (-1, -1), 6),
        ('TOPPADDING',     (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 4),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME',       (0, 1), (-1, -1), 'Helvetica'),
        ('TEXTCOLOR',      (0, 1), (-1, -1), DARK_GREY),
    ]))
    return t


def _make_footer(doc_title, version, org, gen_date):
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor('#888888'))
        canvas.setFont('Helvetica', 7)
        canvas.drawString(
            MARGIN_L, MARGIN_B - 6,
            f"{doc_title}  •  {version}  •  {org}  •  Generated {gen_date}"
        )
        canvas.drawRightString(W - MARGIN_R, MARGIN_B - 6, f"Page {doc.page}")
        canvas.setStrokeColor(BORDER_GREY)
        canvas.setLineWidth(0.4)
        canvas.line(MARGIN_L, MARGIN_B, W - MARGIN_R, MARGIN_B)
        canvas.restoreState()
    return _footer


# ── Public builder API ─────────────────────────────────────────────────────

class DocBuilder:
    """Fluent builder — call methods to append elements, then call build()."""

    def __init__(self, output_path, title, subtitle=None,
                 version='v1.0', org='', gen_date=None, author=''):
        self.output_path = output_path
        self.doc_title   = title
        self.subtitle    = subtitle
        self.version     = version
        self.org         = org
        today            = datetime.date.today()
        self.gen_date    = gen_date or f'{today.day} {today.strftime("%B %Y")}'
        self._story      = []

        self._doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=MARGIN_L, rightMargin=MARGIN_R,
            topMargin=MARGIN_T + 6 * mm, bottomMargin=MARGIN_B + 8 * mm,
            title=title, author=author, subject=subtitle or '', creator='',
        )

    # ── Elements ────────────────────────────────────────────────────────────

    def title_bar(self):
        """Render the black title bar (auto-called from build if not added manually)."""
        self._story.append(TitleBar(self.doc_title, self.subtitle))
        self._story.append(Spacer(1, 6 * mm))
        return self

    def section(self, number, text):
        """Blue section heading. Pass number='' to omit the number prefix."""
        self._story.append(SectionHeading(number, text))
        self._story.append(Spacer(1, 2 * mm))
        return self

    def body(self, text):
        """Plain body paragraph. Supports basic ReportLab XML: <b>, <i>."""
        self._story.append(Paragraph(text, BODY_STYLE))
        return self

    def bullets(self, items):
        """Unordered bullet list from a plain Python list of strings."""
        for item in items:
            self._story.append(Paragraph(f'• {item}', BULLET_STYLE))
        return self

    def code(self, text):
        """Dark-background monospace code block. No line numbers."""
        self._story.append(CodeBlock(text))
        self._story.append(Spacer(1, 2 * mm))
        return self

    def note(self, text):
        """Amber informational callout box (■ NOTE)."""
        self._story.append(CalloutBox(text, style='note'))
        self._story.append(Spacer(1, 2 * mm))
        return self

    def warning(self, text):
        """Red warning callout box (■ WARNING)."""
        self._story.append(CalloutBox(text, style='warning'))
        self._story.append(Spacer(1, 2 * mm))
        return self

    def table(self, headers, rows, col_ratios=None):
        """
        Table with black header row and alternating white/light-grey body rows.
        col_ratios: list of fractions summing to 1.0, e.g. [0.35, 0.65].
        If omitted, columns are evenly spaced.
        """
        n = len(headers)
        if col_ratios:
            col_widths = [CONTENT_W * r for r in col_ratios]
        else:
            col_widths = [CONTENT_W / n] * n
        self._story.append(_make_table(headers, rows, col_widths))
        self._story.append(Spacer(1, 3 * mm))
        return self

    def step(self, title, body=None, code=None):
        """
        Numbered/titled step with optional body text and optional code block.
        E.g. step("Step 1 — Install dependencies", body="Run:", code="pip install x")
        """
        self._story.append(Paragraph(f'<b>{title}</b>', STEP_STYLE))
        if body:
            self._story.append(Paragraph(body, STEP_STYLE))
        if code:
            self._story.append(Spacer(1, 1 * mm))
            self._story.append(CodeBlock(code))
        self._story.append(Spacer(1, 3 * mm))
        return self

    def spacer(self, mm_height=4):
        """Insert vertical whitespace (in mm)."""
        self._story.append(Spacer(1, mm_height * mm))
        return self

    def build(self):
        """Render and write the PDF to output_path."""
        footer_fn = _make_footer(self.doc_title, self.version, self.org, self.gen_date)
        # Reproducible output: no build-time timestamp (or local timezone) in
        # the PDF metadata, so the same source always gives the same file.
        rl_config.invariant = 1
        self._doc.build(
            self._story,
            onFirstPage=footer_fn,
            onLaterPages=footer_fn,
        )
        return self.output_path
