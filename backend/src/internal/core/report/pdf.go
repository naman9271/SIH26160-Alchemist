package report

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	pdfPageWidth  = 612.0
	pdfPageHeight = 792.0
	pdfTopY       = 714.0
	pdfBottomY    = 58.0
)

type pdfLine struct {
	kind string
	text string
}

type pdfPage struct {
	kind  string
	lines []pdfLine
}

func buildReportPDF(document reportDocument) []byte {
	pages := layoutReport(document)
	objects := []string{"<</Type/Catalog/Pages 2 0 R>>"}
	kids := make([]string, len(pages))
	for index := range pages {
		kids[index] = fmt.Sprintf("%d 0 R", 3+index*2)
	}
	objects = append(objects, fmt.Sprintf("<</Type/Pages/Count %d/Kids[%s]>>", len(pages), strings.Join(kids, " ")))
	fontObject := 3 + len(pages)*2
	for index, page := range pages {
		pageObject := 3 + index*2
		contentObject := pageObject + 1
		objects = append(objects, fmt.Sprintf("<</Type/Page/Parent 2 0 R/MediaBox[0 0 %.0f %.0f]/Resources<</Font<</F1 %d 0 R/F2 %d 0 R/F3 %d 0 R/F4 %d 0 R>>>>/Contents %d 0 R>>", pdfPageWidth, pdfPageHeight, fontObject, fontObject+1, fontObject+2, fontObject+3, contentObject))
		stream := renderPDFPage(page, index+1, len(pages), document)
		objects = append(objects, fmt.Sprintf("<</Length %d>>stream\n%s\nendstream", len(stream), stream))
	}
	objects = append(objects,
		"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
		"<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>",
		"<</Type/Font/Subtype/Type1/BaseFont/Courier>>",
		"<</Type/Font/Subtype/Type1/BaseFont/Courier-Bold>>",
	)
	infoObject := len(objects) + 1
	objects = append(objects, fmt.Sprintf("<</Title(%s)/Author(Alchemist)/Subject(IPSEC VPN Traffic and AI Analysis Report)/Creator(Alchemist Core Report Service)>>", escapeReportPDF(document.Title)))

	var output bytes.Buffer
	output.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for index, object := range objects {
		offsets[index+1] = output.Len()
		fmt.Fprintf(&output, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := output.Len()
	fmt.Fprintf(&output, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&output, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&output, "trailer\n<</Size %d/Root 1 0 R/Info %d 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, infoObject, xref)
	return output.Bytes()
}

func layoutReport(document reportDocument) []pdfPage {
	pages := []pdfPage{{kind: "cover"}, {kind: "contents"}}
	firstPage := map[string]int{}
	for _, section := range document.Sections {
		page := pdfPage{kind: "content", lines: []pdfLine{{kind: "section", text: section.Title}}}
		y := pdfTopY - lineHeight("section")
		appendLine := func(line pdfLine) {
			height := lineHeight(line.kind)
			if y-height < pdfBottomY {
				pages = append(pages, page)
				page = pdfPage{kind: "content", lines: []pdfLine{{kind: "section-continuation", text: section.Title + " (continued)"}}}
				y = pdfTopY - lineHeight("section-continuation")
			}
			page.lines = append(page.lines, line)
			y -= height
		}
		firstPage[section.Title] = len(pages) + 1
		for _, paragraph := range section.Paragraphs {
			for _, line := range wrapReportText(paragraph, 96) {
				appendLine(pdfLine{kind: "body", text: line})
			}
			appendLine(pdfLine{kind: "space"})
		}
		for _, item := range section.Items {
			appendLine(pdfLine{kind: "item-heading", text: item.Heading})
			for _, line := range wrapReportText(item.Body, 92) {
				appendLine(pdfLine{kind: "body-indent", text: line})
			}
			appendLine(pdfLine{kind: "space"})
		}
		for _, table := range section.Tables {
			header := formatTableLine(table.Headers, table.Widths)
			appendLine(pdfLine{kind: "table-header", text: header})
			for _, row := range table.Rows {
				appendLine(pdfLine{kind: "table-row", text: formatTableLine(row, table.Widths)})
			}
			appendLine(pdfLine{kind: "space"})
		}
		pages = append(pages, page)
	}
	contents := []pdfLine{{kind: "section", text: "Table of Contents"}, {kind: "body", text: "Only sections supported by available analysis data are included."}, {kind: "space"}}
	for index, section := range document.Sections {
		contents = append(contents, pdfLine{kind: "toc", text: fmt.Sprintf("%02d  %-62s  %d", index+1, truncateText(section.Title, 62), firstPage[section.Title])})
	}
	pages[1].lines = contents
	return pages
}

func lineHeight(kind string) float64 {
	switch kind {
	case "section":
		return 38
	case "section-continuation":
		return 30
	case "item-heading":
		return 19
	case "body", "body-indent":
		return 14
	case "table-header", "table-row", "toc":
		return 17
	case "space":
		return 9
	default:
		return 14
	}
}

func formatTableLine(cells []string, widths []int) string {
	if len(widths) != len(cells) {
		widths = make([]int, len(cells))
		for index := range widths {
			widths[index] = max(8, 94/len(cells))
		}
	}
	parts := make([]string, len(cells))
	for index, cell := range cells {
		cell = strings.Join(strings.Fields(asciiPDF(cell)), " ")
		cell = truncateText(cell, widths[index])
		parts[index] = fmt.Sprintf("%-*s", widths[index], cell)
	}
	return strings.TrimRight(strings.Join(parts, " | "), " ")
}

func renderPDFPage(page pdfPage, number, total int, document reportDocument) string {
	var builder strings.Builder
	builder.WriteString("1 1 1 rg 0 0 612 792 re f\n")
	if page.kind == "cover" {
		return renderCover(document)
	}
	builder.WriteString("0.035 0.055 0.075 rg 0 748 612 44 re f\n")
	builder.WriteString("0.10 0.75 0.62 rg 0 744 612 4 re f\n")
	writePDFTextColor(&builder, "F2", 9, 48, 765, "ALCHEMIST / IPSEC VPN ANALYSIS", "0.88 0.98 0.95 rg")
	writePDFText(&builder, "F1", 8, 48, 30, fmt.Sprintf("Analysis %s", document.AnalysisID))
	writePDFText(&builder, "F1", 8, 500, 30, fmt.Sprintf("PAGE %d / %d", number, total))
	builder.WriteString("0.82 0.86 0.89 RG 48 45 m 564 45 l S\n")
	y := pdfTopY
	rowIndex := 0
	for _, line := range page.lines {
		height := lineHeight(line.kind)
		switch line.kind {
		case "section":
			writePDFTextColor(&builder, "F2", 20, 48, y-21, line.text, "0.08 0.48 0.36 rg")
			builder.WriteString(fmt.Sprintf("0.10 0.75 0.62 RG 1.4 w 48 %.1f m 564 %.1f l S\n", y-31, y-31))
		case "section-continuation":
			writePDFText(&builder, "F2", 15, 48, y-18, line.text)
		case "item-heading":
			builder.WriteString(fmt.Sprintf("0.94 0.97 0.96 rg 48 %.1f 516 18 re f\n", y-15))
			writePDFText(&builder, "F2", 9, 54, y-11, line.text)
		case "body":
			writePDFText(&builder, "F1", 9, 48, y-10, line.text)
		case "body-indent":
			writePDFText(&builder, "F1", 9, 58, y-10, line.text)
		case "table-header":
			builder.WriteString(fmt.Sprintf("0.06 0.20 0.18 rg 48 %.1f 516 16 re f\n", y-14))
			writePDFTextColor(&builder, "F4", 7, 53, y-10, line.text, "0.90 1.00 0.97 rg")
			rowIndex = 0
		case "table-row":
			if rowIndex%2 == 0 {
				builder.WriteString(fmt.Sprintf("0.955 0.97 0.975 rg 48 %.1f 516 16 re f\n", y-14))
			}
			writePDFText(&builder, "F3", 7, 53, y-10, line.text)
			builder.WriteString(fmt.Sprintf("0.88 0.90 0.92 RG .4 w 48 %.1f m 564 %.1f l S\n", y-15, y-15))
			rowIndex++
		case "toc":
			writePDFText(&builder, "F3", 9, 52, y-11, line.text)
		}
		y -= height
	}
	return builder.String()
}

func renderCover(document reportDocument) string {
	var builder strings.Builder
	builder.WriteString("0.025 0.045 0.06 rg 0 0 612 792 re f\n")
	builder.WriteString("0.10 0.75 0.62 rg 0 0 18 792 re f\n")
	builder.WriteString("0.08 0.25 0.22 rg 382 512 230 280 re f\n")
	builder.WriteString("0.10 0.75 0.62 RG 1 w 410 545 150 150 re S\n")
	writePDFTextColor(&builder, "F2", 10, 52, 704, "ALCHEMIST / SECURITY ANALYSIS", "0.38 0.92 0.80 rg")
	for index, line := range wrapReportText(document.Title, 31) {
		writePDFTextColor(&builder, "F2", 27, 52, 610-float64(index*34), line, "0.94 0.98 1.00 rg")
	}
	writePDFTextColor(&builder, "F1", 15, 52, 492, document.Subtitle, "0.72 0.82 0.86 rg")
	builder.WriteString("0.10 0.75 0.62 RG 2 w 52 465 m 324 465 l S\n")
	metadata := [][2]string{{"ANALYSIS TYPE", document.AnalysisType}, {"GENERATED", formatTime(document.GeneratedAt)}, {"ANALYSIS ID", document.AnalysisID}, {"INPUT", document.InputInfo}}
	y := 390.0
	for _, row := range metadata {
		writePDFTextColor(&builder, "F2", 8, 52, y, row[0], "0.38 0.92 0.80 rg")
		for index, line := range wrapReportText(row[1], 66) {
			writePDFTextColor(&builder, "F1", 10, 170, y-float64(index*13), line, "0.90 0.94 0.96 rg")
		}
		y -= 52
	}
	writePDFTextColor(&builder, "F1", 8, 52, 48, "Evidence-led analysis. ESP payloads are never decrypted.", "0.62 0.70 0.74 rg")
	return builder.String()
}

func writePDFText(builder *strings.Builder, font string, size int, x, y float64, value string) {
	writePDFTextColor(builder, font, size, x, y, value, "0.06 0.12 0.16 rg")
}

func writePDFTextColor(builder *strings.Builder, font string, size int, x, y float64, value, color string) {
	fmt.Fprintf(builder, "BT %s /%s %d Tf %.1f %.1f Td (%s) Tj ET\n", color, font, size, x, y, escapeReportPDF(value))
}

func truncateText(value string, width int) string {
	if width <= 0 || len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

func wrapReportText(value string, width int) []string {
	value = strings.Join(strings.Fields(asciiPDF(value)), " ")
	if width <= 0 || len(value) <= width {
		return []string{value}
	}
	lines := []string{}
	for len(value) > width {
		cut := strings.LastIndex(value[:width+1], " ")
		if cut <= 0 {
			cut = width
		}
		lines = append(lines, strings.TrimSpace(value[:cut]))
		value = strings.TrimSpace(value[cut:])
	}
	if value != "" {
		lines = append(lines, value)
	}
	return lines
}

func asciiPDF(value string) string {
	var builder strings.Builder
	for _, char := range strings.ToValidUTF8(value, "?") {
		if char >= 32 && char <= 126 {
			builder.WriteRune(char)
		} else if char == '\n' || char == '\r' || char == '\t' {
			builder.WriteByte(' ')
		} else {
			builder.WriteByte('?')
		}
	}
	return builder.String()
}

func escapeReportPDF(value string) string {
	value = asciiPDF(value)
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	return strings.ReplaceAll(value, ")", "\\)")
}
