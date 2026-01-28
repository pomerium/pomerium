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

	ContextMenuBorder                  color.Color
	ContextMenuBackground              color.Color
	ContextMenuEntryForeground         color.Color
	ContextMenuSelectedEntryBackground color.Color
	ContextMenuSelectedEntryForeground color.Color

	DialogBorder      color.Color
	DialogBorderFlash color.Color
	DialogBackground  color.Color

	ButtonForeground         color.Color
	ButtonBackground         color.Color
	ButtonSelectedForeground color.Color
	ButtonSelectedBackground color.Color

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

type ThemeManager interface {
	ActiveTheme() *Theme
	OnThemeChanged(cb func(*Theme))
	SetTheme(newTheme *Theme) (prevTheme *Theme)
}

type themeManager struct {
	activeTheme *Theme
	callbacks   []func(*Theme)
}

// SetTheme implements ThemeManager.
func (tm *themeManager) SetTheme(newTheme *Theme) (prevTheme *Theme) {
	prev := tm.activeTheme
	tm.activeTheme = newTheme
	for _, cb := range tm.callbacks {
		cb(tm.activeTheme)
	}
	return prev
}

func (tm *themeManager) ActiveTheme() *Theme {
	return tm.activeTheme
}

func (tm *themeManager) OnThemeChanged(cb func(*Theme)) {
	cb(tm.activeTheme)
	tm.callbacks = append(tm.callbacks, cb)
}

func NewThemeManager(initialTheme *Theme) ThemeManager {
	return &themeManager{
		activeTheme: initialTheme,
	}
}

type ReactiveStyles[T any] struct {
	style            *T
	generate         func(*Theme) T
	derivedCallbacks []func(*T)
	enabled          bool
}

func (rt *ReactiveStyles[T]) Style() *T {
	return rt.style
}

func (rt *ReactiveStyles[T]) apply(theme *Theme) {
	if !rt.enabled {
		return
	}
	*rt.style = rt.generate(theme)
	for _, dc := range rt.derivedCallbacks {
		dc(rt.style)
	}
}

func (rt *ReactiveStyles[T]) Attach(other *T) {
	*other = *rt.style
	rt.style = other
}

func (rt *ReactiveStyles[T]) SetUpdateEnabled(enabled bool) *ReactiveStyles[T] {
	rt.enabled = enabled
	return rt
}

func Bind[Base, D any](base *ReactiveStyles[Base], fn func(base *Base) D) *ReactiveStyles[D] {
	initial := fn(base.style)
	rs := &ReactiveStyles[D]{
		style:   &initial,
		enabled: true,
	}
	base.derivedCallbacks = append(base.derivedCallbacks, func(b *Base) {
		if !rs.enabled {
			return
		}
		*rs.style = fn(b)
	})
	return rs
}

func Reactive[T any](tm ThemeManager, fn func(theme *Theme) T) *ReactiveStyles[T] {
	rs := &ReactiveStyles[T]{
		style:    new(T),
		generate: fn,
		enabled:  true,
	}
	tm.OnThemeChanged(rs.apply)
	return rs
}

type Theme struct {
	Colors Colors

	Card lipgloss.Style

	Header lipgloss.Style
	Footer lipgloss.Style

	TableHeader       lipgloss.Style
	TableCell         lipgloss.Style
	TableSelectedCell lipgloss.Style

	TextNormal    lipgloss.Style
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

	ContextMenu              lipgloss.Style
	ContextMenuEntry         lipgloss.Style
	ContextMenuSelectedEntry lipgloss.Style

	Dialog      lipgloss.Style
	DialogFlash lipgloss.Style

	Button         lipgloss.Style
	ButtonSelected lipgloss.Style
}

func set(s *lipgloss.Style, fn func(lipgloss.Style, color.Color) lipgloss.Style, color color.Color) {
	if color != nil {
		*s = fn(*s, color)
	}
}

type ThemeOptions struct {
	defaultStyle lipgloss.Style
}

type ThemeOption func(*ThemeOptions)

func (o *ThemeOptions) apply(opts ...ThemeOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithDefaultStyle(defaultStyle lipgloss.Style) ThemeOption {
	return func(o *ThemeOptions) {
		o.defaultStyle = defaultStyle
	}
}

func NewTheme(colors Colors, opts ...ThemeOption) *Theme {
	var options ThemeOptions
	options.apply(opts...)

	newStyle := func() lipgloss.Style {
		return lipgloss.NewStyle().Inherit(options.defaultStyle)
	}

	card := newStyle().
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

	header := newStyle()
	set(&header, lipgloss.Style.Background, colors.HeaderBackground)

	footer := newStyle()
	set(&footer, lipgloss.Style.Background, colors.FooterBackground)

	tableHeader := newStyle().
		Bold(true)
	set(&tableHeader, lipgloss.Style.Background, colors.TableHeaderBackground)
	set(&tableHeader, lipgloss.Style.Foreground, colors.TableHeaderForeground)

	tableCell := newStyle()
	set(&tableCell, lipgloss.Style.Background, colors.TableCellBackground)
	set(&tableCell, lipgloss.Style.Foreground, colors.TableCellForeground)

	tableSelectedCell := newStyle().
		Inherit(tableCell)
	set(&tableSelectedCell, lipgloss.Style.Background, colors.TableSelectedCellBackground)
	set(&tableSelectedCell, lipgloss.Style.Foreground, colors.TableSelectedCellForeground)

	textNormal := newStyle()
	set(&textNormal, lipgloss.Style.Foreground, colors.TextNormal)

	textTimestamp := newStyle().
		Faint(colors.TextTimestamp == colors.TextNormal)
	set(&textTimestamp, lipgloss.Style.Foreground, colors.TextTimestamp)

	textSuccess := newStyle()
	set(&textSuccess, lipgloss.Style.Foreground, colors.TextSuccess)

	textWarning := newStyle()
	set(&textWarning, lipgloss.Style.Foreground, colors.TextWarning)

	textError := newStyle()
	set(&textError, lipgloss.Style.Foreground, colors.TextError)

	textLink := newStyle()
	set(&textLink, lipgloss.Style.Foreground, colors.TextLink)

	textStatusHealthy := newStyle()
	set(&textStatusHealthy, lipgloss.Style.Foreground, colors.TextSuccess)

	textStatusDegraded := newStyle()
	set(&textStatusDegraded, lipgloss.Style.Foreground, colors.TextWarning)

	textStatusUnhealthy := newStyle()
	set(&textStatusUnhealthy, lipgloss.Style.Foreground, colors.TextError)

	textStatusUnknown := newStyle().
		Faint(colors.TextFaint1 == colors.TextNormal)
	set(&textStatusUnknown, lipgloss.Style.Foreground, colors.TextFaint1)

	helpKey := newStyle()
	set(&helpKey, lipgloss.Style.Foreground, colors.TextFaint1)

	helpDesc := newStyle().
		Faint(colors.TextFaint2 == colors.TextFaint1)
	set(&helpDesc, lipgloss.Style.Foreground, colors.TextFaint2)

	helpSeparator := newStyle().
		Faint(colors.TextFaint1 == colors.TextNormal)
	set(&helpSeparator, lipgloss.Style.Foreground, colors.TextFaint1)

	contextMenu := newStyle().
		Border(OuterBlockBorder)
	set(&contextMenu, lipgloss.Style.BorderTopForeground, colors.ContextMenuBorder)
	set(&contextMenu, lipgloss.Style.BorderRightForeground, colors.ContextMenuBorder)
	set(&contextMenu, lipgloss.Style.BorderBottomForeground, colors.ContextMenuBorder)
	set(&contextMenu, lipgloss.Style.BorderLeftForeground, colors.ContextMenuBorder)
	set(&contextMenu, lipgloss.Style.BorderTopBackground, colors.ContextMenuBackground)
	set(&contextMenu, lipgloss.Style.BorderRightBackground, colors.ContextMenuBackground)
	set(&contextMenu, lipgloss.Style.BorderBottomBackground, colors.ContextMenuBackground)
	set(&contextMenu, lipgloss.Style.BorderLeftBackground, colors.ContextMenuBackground)
	set(&contextMenu, lipgloss.Style.Background, colors.ContextMenuBackground)

	contextMenuEntry := newStyle().
		MarginLeft(2).
		MarginRight(2)
	set(&contextMenuEntry, lipgloss.Style.Background, colors.ContextMenuBackground)
	set(&contextMenuEntry, lipgloss.Style.MarginBackground, colors.ContextMenuBackground)
	set(&contextMenuEntry, lipgloss.Style.Foreground, colors.ContextMenuEntryForeground)

	contextMenuSelectedEntry := newStyle().
		Inherit(contextMenuEntry).
		PaddingLeft(1).
		PaddingRight(1).
		MarginLeft(1).
		MarginRight(1)
	set(&contextMenuSelectedEntry, lipgloss.Style.Background, colors.ContextMenuSelectedEntryBackground)
	set(&contextMenuSelectedEntry, lipgloss.Style.Foreground, colors.ContextMenuSelectedEntryForeground)

	dialog := newStyle().
		Border(OuterBlockBorder)
	set(&dialog, lipgloss.Style.BorderTopForeground, colors.DialogBorder)
	set(&dialog, lipgloss.Style.BorderRightForeground, colors.DialogBorder)
	set(&dialog, lipgloss.Style.BorderBottomForeground, colors.DialogBorder)
	set(&dialog, lipgloss.Style.BorderLeftForeground, colors.DialogBorder)
	set(&dialog, lipgloss.Style.BorderTopBackground, colors.DialogBackground)
	set(&dialog, lipgloss.Style.BorderRightBackground, colors.DialogBackground)
	set(&dialog, lipgloss.Style.BorderBottomBackground, colors.DialogBackground)
	set(&dialog, lipgloss.Style.BorderLeftBackground, colors.DialogBackground)
	set(&dialog, lipgloss.Style.Background, colors.DialogBackground)
	set(&dialog, lipgloss.Style.Foreground, colors.TextNormal)

	dialogFlash := newStyle().
		Inherit(dialog)
	set(&dialogFlash, lipgloss.Style.BorderTopForeground, colors.DialogBorderFlash)
	set(&dialogFlash, lipgloss.Style.BorderRightForeground, colors.DialogBorderFlash)
	set(&dialogFlash, lipgloss.Style.BorderBottomForeground, colors.DialogBorderFlash)
	set(&dialogFlash, lipgloss.Style.BorderLeftForeground, colors.DialogBorderFlash)

	button := newStyle().
		PaddingLeft(1).
		PaddingRight(1)
	set(&button, lipgloss.Style.Background, colors.ButtonBackground)
	set(&button, lipgloss.Style.Foreground, colors.ButtonForeground)

	buttonSelected := newStyle().
		Inherit(button).
		PaddingLeft(1).
		PaddingRight(1)
	set(&buttonSelected, lipgloss.Style.Background, colors.ButtonSelectedBackground)
	set(&buttonSelected, lipgloss.Style.Foreground, colors.ButtonSelectedForeground)

	return &Theme{
		Colors:                   colors,
		Card:                     card,
		Header:                   header,
		Footer:                   footer,
		TableHeader:              tableHeader,
		TableCell:                tableCell,
		TableSelectedCell:        tableSelectedCell,
		TextNormal:               textNormal,
		TextTimestamp:            textTimestamp,
		TextSuccess:              textSuccess,
		TextWarning:              textWarning,
		TextError:                textError,
		TextLink:                 textLink,
		TextStatusHealthy:        textStatusHealthy,
		TextStatusDegraded:       textStatusDegraded,
		TextStatusUnhealthy:      textStatusUnhealthy,
		TextStatusUnknown:        textStatusUnknown,
		HelpKey:                  helpKey,
		HelpDesc:                 helpDesc,
		HelpSeparator:            helpSeparator,
		ContextMenu:              contextMenu,
		ContextMenuEntry:         contextMenuEntry,
		ContextMenuSelectedEntry: contextMenuSelectedEntry,
		Dialog:                   dialog,
		DialogFlash:              dialogFlash,
		Button:                   button,
		ButtonSelected:           buttonSelected,
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
		Normal:          ansi.BrightBlack,
		Bright:          ansi.BrightBlack,
		ContrastingText: ansi.White,
	},
	Accent1:                            AccentColor{Normal: ansi.Red, Bright: ansi.BrightRed, ContrastingText: ansi.Black},
	Accent2:                            AccentColor{Normal: ansi.Green, Bright: ansi.BrightGreen, ContrastingText: ansi.Black},
	Accent3:                            AccentColor{Normal: ansi.Yellow, Bright: ansi.BrightYellow, ContrastingText: ansi.Black},
	Accent4:                            AccentColor{Normal: ansi.Blue, Bright: ansi.BrightBlue, ContrastingText: ansi.Black},
	Accent5:                            AccentColor{Normal: ansi.Magenta, Bright: ansi.BrightMagenta, ContrastingText: ansi.Black},
	Accent6:                            AccentColor{Normal: ansi.Cyan, Bright: ansi.BrightCyan, ContrastingText: ansi.Black},
	TableSelectedCellBackground:        ansi.BrightBlack,
	ContextMenuBorder:                  ansi.BrightBlack,
	ContextMenuBackground:              ansi.Black,
	ContextMenuEntryForeground:         ansi.White,
	ContextMenuSelectedEntryBackground: ansi.BrightBlack,
	ContextMenuSelectedEntryForeground: ansi.BrightWhite,
	DialogBorder:                       ansi.BrightBlack,
	DialogBorderFlash:                  ansi.Black,
	DialogBackground:                   ansi.Black,
	ButtonForeground:                   ansi.White,
	ButtonBackground:                   ansi.Black,
	ButtonSelectedBackground:           ansi.BrightBlack,
	ButtonSelectedForeground:           ansi.BrightWhite,
}

var Deemphasized = Colors{
	TableSelectedCellBackground:        ansi.BrightBlack,
	CardBorderForeground:               ansi.Black,
	FooterBackground:                   ansi.Black,
	TableHeaderForeground:              ansi.Black,
	TableCellForeground:                ansi.Black,
	TableSelectedCellForeground:        ansi.Black,
	ContextMenuBorder:                  ansi.Black,
	ContextMenuEntryForeground:         ansi.Black,
	ContextMenuSelectedEntryForeground: ansi.Black,
	DialogBorder:                       ansi.Black,
	ButtonForeground:                   ansi.Black,
	ButtonBackground:                   ansi.Black,
	ButtonSelectedForeground:           ansi.Black,
	ButtonSelectedBackground:           ansi.Black,
	TextNormal:                         ansi.Black,
	TextFaint1:                         ansi.Black,
	TextFaint2:                         ansi.Black,
	TextSuccess:                        ansi.Black,
	TextWarning:                        ansi.Black,
	TextError:                          ansi.Black,
	TextTimestamp:                      ansi.Black,
	TextLink:                           ansi.Black,
	BrandPrimary:                       AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	BrandSecondary:                     AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent1:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent2:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent3:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent4:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent5:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
	Accent6:                            AccentColor{Normal: ansi.Black, Bright: ansi.Black, ContrastingText: ansi.BrightBlack},
}
