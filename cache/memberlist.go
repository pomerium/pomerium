package cache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"strings"

	"github.com/hashicorp/memberlist"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

type memberlistHandler struct {
	cfg        *memberlist.Config
	memberlist *memberlist.Memberlist
	log        zerolog.Logger
}

func (c *Cache) runMemberList(ctx context.Context) error {
	mh := new(memberlistHandler)
	mh.log = log.With().Str("service", "memberlist").Logger()

	pr, pw := io.Pipe()
	defer pw.Close()
	defer pr.Close()

	mh.cfg = memberlist.DefaultLANConfig()
	mh.cfg.Events = mh
	mh.cfg.Logger = stdlog.New(pw, "", 0)
	go mh.runLogHandler(pr)

	var err error
	mh.memberlist, err = memberlist.Create(mh.cfg)
	if err != nil {
		return fmt.Errorf("memberlist: error creating memberlist: %w", err)
	}

	// the only way memberlist would be empty here, following create is if
	// the current node suddenly died. Still, we check to be safe.
	if len(mh.memberlist.Members()) == 0 {
		return errors.New("memberlist: can't find self")
	}

	<-ctx.Done()
	return mh.memberlist.Shutdown()
}

func (mh *memberlistHandler) NotifyJoin(node *memberlist.Node) {
	mh.log.Debug().Interface("node", node).Msg("node joined")

	if mh.memberlist != nil && len(mh.memberlist.Members()) > 1 {
		mh.log.Error().Msg("detected multiple cache servers, which is not supported")
	}
}

func (mh *memberlistHandler) NotifyLeave(node *memberlist.Node) {
	mh.log.Debug().Interface("node", node).Msg("node left")
}

func (mh *memberlistHandler) NotifyUpdate(node *memberlist.Node) {
	mh.log.Debug().Interface("node", node).Msg("node updated")
}

func (mh *memberlistHandler) runLogHandler(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		str, err := br.ReadString('\n')
		if err != nil {
			break
		}
		mh.log.Debug().Msg(strings.TrimSpace(str))
	}
}
