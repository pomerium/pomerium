package tui

import (
	"context"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type PortalProgram struct {
	*tea.Program
}

func NewPortalProgram(ctx context.Context, routes []string, width, height int, opts ...tea.ProgramOption) *PortalProgram {
	items := []list.Item{}
	for _, route := range routes {
		items = append(items, item(route))
	}
	l := list.New(items, itemDelegate{}, width, height)
	l.Title = "Connect to which server?"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return &PortalProgram{
		Program: tea.NewProgram(portalModel{list: l}, append(opts,
			tea.WithContext(ctx),
			tea.WithoutSignalHandler(),
		)...),
	}
}

func (p *PortalProgram) Run() (string, error) {
	answer, err := p.Program.Run()
	if err != nil {
		return "", err
	}
	return answer.(portalModel).choice, nil
}

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles(true).PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles(true).HelpStyle.PaddingLeft(4).PaddingBottom(1)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type portalModel struct {
	list     list.Model
	choice   string
	quitting bool
}

func (m portalModel) Init() tea.Cmd {
	return nil
}

func (m portalModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(max(0, msg.Width-2), max(0, msg.Height-2))
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m portalModel) View() tea.View {
	return tea.NewView("\n" + m.list.View())
}
