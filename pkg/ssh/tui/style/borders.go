package style

import (
	"fmt"
	"strings"

	stdslices "slices"

	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/slices"
)

/*
OuterBlockBorder
𜵊🮂🮂𜶘
▌  ▐
𜷀▂▂𜷕

InnerBlockBorder
𜺠▂▂𜺣
▐  ▌
▐  ▌
𜺫🮂🮂𜺨

RoundedBorder
╭──╮
│  │
╰──╯
*/

var OuterBlockBorder = lipgloss.Border{
	Top:         "🮂",
	Bottom:      "▂",
	Left:        "▌",
	Right:       "▐",
	TopLeft:     "𜵊",
	TopRight:    "𜶘",
	BottomLeft:  "𜷀",
	BottomRight: "𜷕",
}

var InnerBlockBorder = lipgloss.Border{
	Top:         "▂",
	Bottom:      "🮂",
	Left:        "▐",
	Right:       "▌",
	TopLeft:     "𜺠",
	TopRight:    "𜺣",
	BottomLeft:  "𜺫",
	BottomRight: "𜺨",
}

var RoundedBorder = lipgloss.Border{
	Top:         "─",
	Left:        "│",
	Right:       "│",
	Bottom:      "─",
	TopRight:    "╮",
	TopLeft:     "╭",
	BottomRight: "╯",
	BottomLeft:  "╰",
}

var SingleLineRoundedBorder = lipgloss.Border{
	Left:  "\uE0B6", // NF left rounded half circle (non-standard)
	Right: "\uE0B4", // NF right rounded half circle (non-standard)
}

func RenderBorderTitles(view string, borderStyle lipgloss.Border, leftTitle, rightTitle string) string {
	if borderStyle.Top == "" || (leftTitle == "" && rightTitle == "") {
		return view
	}
	topLine := strings.IndexRune(view, '\n')
	headerTopBorder := view[:topLine]
	topRune := []rune(borderStyle.Top)[0]
	borderRunes := []rune(headerTopBorder)
	left := stdslices.Index(borderRunes, topRune)
	right := slices.LastIndex(borderRunes, topRune)
	if leftTitle != "" {
		text := []rune(fmt.Sprintf("╴%s╶", leftTitle))
		if left+len(text) < right {
			left += copy(borderRunes[left:], text)
		}
	}
	if rightTitle != "" {
		text := []rune(fmt.Sprintf("╴%s╶", rightTitle))
		if right-len(text) > left {
			copy(borderRunes[right-len(text)+1:], text)
		}
	}
	headerTopBorder = string(borderRunes)
	return headerTopBorder + view[topLine:]
}
