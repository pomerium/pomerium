package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

func NewAdminCommand(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Admin tools",
	}

	cmd.AddCommand(NewAdminRequestsCmd(ic, ctrl))
	return cmd
}

func NewAdminRequestsCmd(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "Manage access requests",
	}

	cmd.AddCommand(NewAdminRequestsListCmd(ic, ctrl))
	cmd.AddCommand(NewAdminRequestsApproveCmd(ic, ctrl))
	cmd.AddCommand(NewAdminRequestsDenyCmd(ic, ctrl))

	return cmd
}

func NewAdminRequestsListCmd(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending access requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, ca := context.WithTimeout(cmd.Context(), 1*time.Second)
			defer ca()
			requests := ctrl.AccessRequestManager().ListPendingRequests(
				ctrl.GetArbitrationAuthorizedRoutes(ctx))
			fmt.Fprintf(ic.Stderr(), "%d pending access requests\n", len(requests))
			if len(requests) == 0 {
				return nil
			}
			for _, req := range requests {
				data, _ := protojson.Marshal(req)
				fmt.Fprintf(ic.Stderr(), "%s: %s\n", fmt.Sprintf("%x", req.StreamId), data)
			}
			return nil
		},
	}
	return cmd
}

func NewAdminRequestsApproveCmd(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve pending access requests",
		Args:  cobra.RangeArgs(1, 10),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, ca := context.WithTimeout(cmd.Context(), 100*time.Millisecond)
			defer ca()
			requests := ctrl.AccessRequestManager().ListPendingRequests(
				ctrl.GetArbitrationAuthorizedRoutes(ctx))
			currentSession, err := ctrl.GetSession(ctx)
			if err != nil {
				return err
			}
			for _, arg := range args {
				for _, pendingReq := range requests {
					if requestId := fmt.Sprintf("%x", pendingReq.StreamId); requestId == arg {
						if err := ctrl.AccessRequestManager().ApproveRequest(cmd.Context(), requestId, currentSession); err != nil {
							fmt.Fprintf(ic.Stderr(), "%s: error: %s\n", requestId, err)
						} else {
							fmt.Fprintf(ic.Stderr(), "%s: approved successfully\n", requestId)
						}
					}
				}
			}
			return nil
		},
	}
	return cmd
}

func NewAdminRequestsDenyCmd(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny",
		Short: "Deny pending access requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, ca := context.WithTimeout(cmd.Context(), 100*time.Millisecond)
			defer ca()
			requests := ctrl.AccessRequestManager().ListPendingRequests(
				ctrl.GetArbitrationAuthorizedRoutes(ctx))
			currentSession, err := ctrl.GetSession(ctx)
			if err != nil {
				return err
			}

			for _, arg := range args {
				for _, pendingReq := range requests {
					if requestId := fmt.Sprintf("%x", pendingReq.StreamId); requestId == arg {
						if err := ctrl.AccessRequestManager().DenyRequest(cmd.Context(), requestId, currentSession); err != nil {
							fmt.Fprintf(ic.Stderr(), "%s: error: %s\n", requestId, err)
						} else {
							fmt.Fprintf(ic.Stderr(), "%s: denied successfully\n", requestId)
						}
					}
				}
			}
			return nil
		},
	}
	return cmd
}
