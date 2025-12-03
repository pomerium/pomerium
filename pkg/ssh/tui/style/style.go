package style

import (
	"image/color"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type AccentColor struct {
	Normal color.Color
	Bright color.Color

	// Color to use for text on a background of this accent color
	ContrastingText color.Color
}

type Colors struct {
	WindowBackground color.Color

	CardBackground       color.Color
	CardBorderBackground color.Color
	CardBorderForeground color.Color

	HeaderBackground color.Color
	FooterBackground color.Color

	TableHeaderBackground       color.Color
	TableHeaderForeground       color.Color
	TableCellBackground         color.Color
	TableCellForeground         color.Color
	TableSelectedCellBackground color.Color
	TableSelectedCellForeground color.Color

	TextNormal color.Color
	TextFaint1 color.Color
	TextFaint2 color.Color

	TextSuccess   color.Color
	TextWarning   color.Color
	TextError     color.Color
	TextTimestamp color.Color
	TextLink      color.Color

	BrandPrimary   AccentColor
	BrandSecondary AccentColor

	Accent1 AccentColor
	Accent2 AccentColor
	Accent3 AccentColor
	Accent4 AccentColor
	Accent5 AccentColor
	Accent6 AccentColor
}

type Theme struct {
	Colors Colors

	Card lipgloss.Style

	Header lipgloss.Style
	Footer lipgloss.Style

	TableHeader       lipgloss.Style
	TableCell         lipgloss.Style
	TableSelectedCell lipgloss.Style

	TextTimestamp lipgloss.Style
	TextSuccess   lipgloss.Style
	TextWarning   lipgloss.Style
	TextError     lipgloss.Style
	TextLink      lipgloss.Style

	TextStatusHealthy   lipgloss.Style
	TextStatusDegraded  lipgloss.Style
	TextStatusUnhealthy lipgloss.Style
	TextStatusUnknown   lipgloss.Style

	HelpKey       lipgloss.Style
	HelpDesc      lipgloss.Style
	HelpSeparator lipgloss.Style
}

func set(s *lipgloss.Style, fn func(lipgloss.Style, color.Color) lipgloss.Style, color color.Color) {
	if color != nil {
		*s = fn(*s, color)
	}
}

func NewTheme(colors Colors) *Theme {
	card := lipgloss.NewStyle().
		Border(RoundedBorder)
	set(&card, lipgloss.Style.Background, colors.CardBackground)
	set(&card, lipgloss.Style.BorderTopBackground, colors.CardBorderBackground)
	set(&card, lipgloss.Style.BorderRightBackground, colors.CardBorderBackground)
	set(&card, lipgloss.Style.BorderBottomBackground, colors.CardBorderBackground)
	set(&card, lipgloss.Style.BorderLeftBackground, colors.CardBorderBackground)
	set(&card, lipgloss.Style.BorderTopForeground, colors.CardBorderForeground)
	set(&card, lipgloss.Style.BorderRightForeground, colors.CardBorderForeground)
	set(&card, lipgloss.Style.BorderBottomForeground, colors.CardBorderForeground)
	set(&card, lipgloss.Style.BorderLeftForeground, colors.CardBorderForeground)

	header := lipgloss.NewStyle()
	set(&header, lipgloss.Style.Background, colors.HeaderBackground)

	footer := lipgloss.NewStyle()
	set(&footer, lipgloss.Style.Background, colors.FooterBackground)

	tableHeader := lipgloss.NewStyle().
		Bold(true)
	set(&tableHeader, lipgloss.Style.Background, colors.TableHeaderBackground)
	set(&tableHeader, lipgloss.Style.Foreground, colors.TableHeaderForeground)

	tableCell := lipgloss.NewStyle()
	set(&tableCell, lipgloss.Style.Background, colors.TableCellBackground)
	set(&tableCell, lipgloss.Style.Foreground, colors.TableCellForeground)

	tableSelectedCell := lipgloss.NewStyle().
		Inherit(tableCell)
	set(&tableSelectedCell, lipgloss.Style.Background, colors.TableSelectedCellBackground)
	set(&tableSelectedCell, lipgloss.Style.Foreground, colors.TableSelectedCellForeground)

	textTimestamp := lipgloss.NewStyle().
		Faint(colors.TextTimestamp == colors.TextNormal)
	set(&textTimestamp, lipgloss.Style.Foreground, colors.TextTimestamp)

	textSuccess := lipgloss.NewStyle()
	set(&textSuccess, lipgloss.Style.Foreground, colors.TextSuccess)

	textWarning := lipgloss.NewStyle()
	set(&textWarning, lipgloss.Style.Foreground, colors.TextWarning)

	textError := lipgloss.NewStyle()
	set(&textError, lipgloss.Style.Foreground, colors.TextError)

	textLink := lipgloss.NewStyle()
	set(&textLink, lipgloss.Style.Foreground, colors.TextLink)

	textStatusHealthy := lipgloss.NewStyle()
	set(&textStatusHealthy, lipgloss.Style.Foreground, colors.TextSuccess)

	textStatusDegraded := lipgloss.NewStyle()
	set(&textStatusDegraded, lipgloss.Style.Foreground, colors.TextWarning)

	textStatusUnhealthy := lipgloss.NewStyle()
	set(&textStatusUnhealthy, lipgloss.Style.Foreground, colors.TextError)

	textStatusUnknown := lipgloss.NewStyle().
		Faint(colors.TextFaint1 == colors.TextNormal)
	set(&textStatusUnknown, lipgloss.Style.Foreground, colors.TextFaint1)

	helpKey := lipgloss.NewStyle()
	set(&helpKey, lipgloss.Style.Foreground, colors.TextFaint1)

	helpDesc := lipgloss.NewStyle().
		Faint(colors.TextFaint2 == colors.TextFaint1)
	set(&helpDesc, lipgloss.Style.Foreground, colors.TextFaint2)

	helpSeparator := lipgloss.NewStyle().
		Faint(colors.TextFaint1 == colors.TextNormal)
	set(&helpSeparator, lipgloss.Style.Foreground, colors.TextFaint1)

	return &Theme{
		Colors:              colors,
		Card:                card,
		Header:              header,
		Footer:              footer,
		TableHeader:         tableHeader,
		TableCell:           tableCell,
		TableSelectedCell:   tableSelectedCell,
		TextTimestamp:       textTimestamp,
		TextSuccess:         textSuccess,
		TextWarning:         textWarning,
		TextError:           textError,
		TextLink:            textLink,
		TextStatusHealthy:   textStatusHealthy,
		TextStatusDegraded:  textStatusDegraded,
		TextStatusUnhealthy: textStatusUnhealthy,
		TextStatusUnknown:   textStatusUnknown,
		HelpKey:             helpKey,
		HelpDesc:            helpDesc,
		HelpSeparator:       helpSeparator,
	}
}

var Ansi16Colors = Colors{
	CardBorderForeground: ansi.White,
	TextNormal:           ansi.White,
	TextFaint1:           ansi.White,
	TextFaint2:           ansi.White,
	TextSuccess:          ansi.Green,
	TextWarning:          ansi.Yellow,
	TextError:            ansi.Red,
	TextTimestamp:        ansi.White,
	BrandPrimary: AccentColor{
		Normal:          ansi.White,
		Bright:          ansi.BrightWhite,
		ContrastingText: ansi.Black,
	},
	BrandSecondary: AccentColor{
		Normal:          ansi.Black,
		Bright:          ansi.Black,
		ContrastingText: ansi.White,
	},
	Accent1:                     AccentColor{Normal: ansi.Red, Bright: ansi.BrightRed, ContrastingText: ansi.Black},
	Accent2:                     AccentColor{Normal: ansi.Green, Bright: ansi.BrightGreen, ContrastingText: ansi.Black},
	Accent3:                     AccentColor{Normal: ansi.Yellow, Bright: ansi.BrightYellow, ContrastingText: ansi.Black},
	Accent4:                     AccentColor{Normal: ansi.Blue, Bright: ansi.BrightBlue, ContrastingText: ansi.Black},
	Accent5:                     AccentColor{Normal: ansi.Magenta, Bright: ansi.BrightMagenta, ContrastingText: ansi.Black},
	Accent6:                     AccentColor{Normal: ansi.Cyan, Bright: ansi.BrightCyan, ContrastingText: ansi.Black},
	TableSelectedCellBackground: ansi.BrightBlack,
}
