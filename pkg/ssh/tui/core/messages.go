package core

import uv "github.com/charmbracelet/ultraviolet"

type LocalToGlobalTranslatable interface {
	TranslateLocalToGlobalCoordinates(fromRelative uv.Rectangle)
}
