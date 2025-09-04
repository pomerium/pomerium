package health

// TODO: WIP hierarchical definition of status checks, likely not good UX

type CheckV2 struct {
	Path     string
	Parent   *CheckV2
	Children map[string]*CheckV2
}

func newCheck(
	name string,
	parent *CheckV2,
) *CheckV2 {
	c := &CheckV2{
		Path:     name,
		Parent:   parent,
		Children: make(map[string]*CheckV2),
	}
	if parent != nil {
		fullPath := parent.Path + "." + name
		c.Path = fullPath
		parent.Children[name] = c
	}
	return c
}

var (
	Databroker            = newCheck("databroker", nil)
	DatabrokerConfig      = newCheck("config", Databroker)
	DatabrokerConfigBuild = newCheck("build", DatabrokerConfig)

	Storage                     = newCheck("storage", nil)
	StorageBackend2             = newCheck("backend", Storage)
	StorageBackendPing          = newCheck("ping", StorageBackend2)
	StorageBackendNotifications = newCheck("notifications", StorageBackend2)
	StorageBackendCleanup2      = newCheck("cleanup", StorageBackend2)
)

func ReportOkV2(check *CheckV2) {
	provider.ReportStatus(Check(check.Path), StatusRunning)
}

func ReportErrorV2(check *CheckV2, err error) {
	provider.ReportError(
		Check(check.Path),
		err,
	)
}
