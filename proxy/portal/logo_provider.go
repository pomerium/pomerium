package portal

import (
	"context"
	"encoding/base64"
	"errors"
)

// errors
var ErrLogoNotFound = errors.New("logo not found")

// A LogoProvider gets logo urls for routes.
type LogoProvider interface {
	GetLogoURL(ctx context.Context, from, to string) (string, error)
}

// NewLogoProvider creates a new LogoProvider.
func NewLogoProvider() LogoProvider {
	return multiLogoProvider{newWellKnownLogoProvider(), newFaviconDiscoveryLogoProvider()}
}

type multiLogoProvider []LogoProvider

func (p multiLogoProvider) GetLogoURL(ctx context.Context, from, to string) (string, error) {
	for _, pp := range p {
		url, err := pp.GetLogoURL(ctx, from, to)
		if errors.Is(err, ErrLogoNotFound) {
			continue
		} else if err != nil {
			return "", err
		}
		return url, nil
	}

	return "", ErrLogoNotFound
}

const (
	mediaTypePNG = "image/png"
	mediaTypeSVG = "image/svg+xml"
)

func isSupportedImageType(mtype string) bool {
	return mtype == "image/vnd.microsoft.icon" ||
		mtype == mediaTypePNG ||
		mtype == mediaTypeSVG ||
		mtype == "image/jpeg" ||
		mtype == "image/gif"
}

func dataURL(mimeType string, data []byte) string {
	return "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data)
}
