package postgresproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	maxExtendedBatchMessages = 256
	maxExtendedBatchBytes    = 32 * 1024 * 1024
)

type preparedStatement struct {
	query string
}

type portalState struct {
	statement       string
	query           string
	parameterCount  int
	responseOpIndex int
}

func (s *Server) relay(ctx context.Context, session *Session, client *pgproto3.Backend, upstream *pgproto3.Frontend, upstreamConn net.Conn, recorder Recorder) error {
	statements := map[string]preparedStatement{}
	portals := map[string]portalState{}
	txStatus := byte('I')
	discardExtendedUntilSync := false
	syntheticFailedTx := false

	for {
		msg, err := client.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			upstream.Send(msg)
			_ = upstream.Flush()
			return nil
		}
		if discardExtendedUntilSync {
			if _, ok := msg.(*pgproto3.Sync); ok {
				discardExtendedUntilSync = false
				if err := writeReadyForQuery(client, txStatus); err != nil {
					return err
				}
			}
			continue
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			if err := s.handleSimpleQuery(ctx, session, client, upstream, upstreamConn, recorder, statements, portals, m.String, &txStatus, &syntheticFailedTx); err != nil {
				return err
			}
		case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Execute, *pgproto3.Describe, *pgproto3.Close, *pgproto3.Flush:
			recovering, err := s.handleExtendedCycle(ctx, session, client, upstream, upstreamConn, recorder, statements, portals, msg, &txStatus, &syntheticFailedTx)
			if err != nil {
				return err
			}
			discardExtendedUntilSync = recovering
		case *pgproto3.FunctionCall:
			if err := s.reauthorizeClient(ctx, client, session, txStatus); err != nil {
				return err
			}
			started := s.now()
			req := QueryRequest{
				Session:        session,
				Protocol:       QueryProtocolFunctionCall,
				SQL:            fmt.Sprintf("FunctionCall(%d)", m.Function),
				StatementClass: "FUNCTION_CALL",
				ParameterCount: len(m.Arguments),
				StartedAt:      started,
			}
			if err := s.denyQuery(ctx, client, recorder, req, Decision{
				Action: DecisionDeny,
				Reason: "PostgreSQL FunctionCall messages are not supported by the postgres proxy",
			}, started, &txStatus, &syntheticFailedTx); err != nil {
				return err
			}
		default:
			if err := writeErrorWithTxStatus(client, "0A000", "postgres frontend message is not supported", fmt.Sprintf("%T", msg), txStatus); err != nil {
				return err
			}
		}
	}
}

func (s *Server) handleSimpleQuery(ctx context.Context, session *Session, client *pgproto3.Backend, upstream *pgproto3.Frontend, upstreamConn net.Conn, recorder Recorder, statements map[string]preparedStatement, portals map[string]portalState, sql string, txStatus *byte, syntheticFailedTx *bool) error {
	started := s.now()
	if err := s.reauthorizeClient(ctx, client, session, *txStatus); err != nil {
		return err
	}
	req := QueryRequest{
		Session:        session,
		Protocol:       QueryProtocolSimple,
		SQL:            sql,
		StatementClass: classifySQL(sql),
		StartedAt:      started,
	}
	if *syntheticFailedTx && !isTransactionRecoveryStatement(req.StatementClass) {
		return s.rejectFailedTransaction(ctx, client, recorder, req, started)
	}
	if hasMultipleStatements(sql) {
		req.StatementClass = "MULTI"
		return s.denyQuery(ctx, client, recorder, req, Decision{
			Action: DecisionDeny,
			Reason: "multi-statement simple queries are not supported",
		}, started, txStatus, syntheticFailedTx)
	}
	if requiresParserSupport(req.StatementClass) {
		return s.denyQuery(ctx, client, recorder, req, Decision{
			Action: DecisionDeny,
			Reason: fmt.Sprintf("%s statements require SQL parser support before policy enforcement", req.StatementClass),
		}, started, txStatus, syntheticFailedTx)
	}
	decision := normalizeDecision(s.authorizeQuery(ctx, req))
	decision = constrainDecisionForStatement(req, decision)
	if decision.Action == DecisionDeny || decision.Action == DecisionStepUp {
		return s.denyQuery(ctx, client, recorder, req, decision, started, txStatus, syntheticFailedTx)
	}

	upstream.Send(&pgproto3.Query{String: sql})
	if err := upstream.Flush(); err != nil {
		return err
	}
	stats := &queryStats{}
	err := forwardUntilReady(client, upstream, stats, decision.RowCap)
	if stats.txStatus != 0 {
		*txStatus = stats.txStatus
	}
	if *syntheticFailedTx && *txStatus == 'I' {
		*syntheticFailedTx = false
	}
	delete(statements, "")
	delete(portals, "")
	clearPortalsIfIdle(portals, *txStatus)
	record := queryRecord(req, decision, stats, started, s.now())
	if errors.Is(err, errRowCapExceeded) {
		record.Status = "row_cap_exceeded"
		record.ErrorCode = "P0001"
		record.ErrorMessage = fmt.Sprintf("row cap exceeded: %d rows returned, cap is %d", stats.rows, decision.RowCap)
		recordQueryBestEffort(ctx, recorder, record)
		_ = upstreamConn.Close()
		_ = writeErrorWithTxStatus(client, "P0001", "postgres row cap exceeded", record.ErrorMessage, *txStatus)
		return errors.New(record.ErrorMessage)
	}
	if errors.Is(err, errCopyInUnsupported) {
		record.Status = "error"
		record.ErrorCode = "0A000"
		record.ErrorMessage = err.Error()
		recordQueryBestEffort(ctx, recorder, record)
		_ = upstreamConn.Close()
		_ = writeErrorWithTxStatus(client, "0A000", "postgres COPY FROM STDIN is not supported", record.ErrorMessage, *txStatus)
		return errors.New(record.ErrorMessage)
	}
	if errors.Is(err, errCopyOutRowCapUnsupported) {
		record.Status = "error"
		record.ErrorCode = "0A000"
		record.ErrorMessage = err.Error()
		recordQueryBestEffort(ctx, recorder, record)
		_ = upstreamConn.Close()
		_ = writeErrorWithTxStatus(client, "0A000", "postgres COPY TO STDOUT is not supported with row caps", record.ErrorMessage, *txStatus)
		return errors.New(record.ErrorMessage)
	}
	if err != nil {
		record.Status = "error"
		record.ErrorMessage = err.Error()
		recordQueryBestEffort(ctx, recorder, record)
		return err
	}
	recordQueryBestEffort(ctx, recorder, record)
	return nil
}

func (s *Server) handleExtendedCycle(ctx context.Context, session *Session, client *pgproto3.Backend, upstream *pgproto3.Frontend, upstreamConn net.Conn, recorder Recorder, statements map[string]preparedStatement, portals map[string]portalState, first pgproto3.FrontendMessage, txStatus *byte, syntheticFailedTx *bool) (bool, error) {
	started := s.now()
	state := extendedCycleState{
		session:           session,
		started:           started,
		statements:        statements,
		portals:           portals,
		pendingStatements: map[string]*preparedStatement{},
		pendingPortals:    map[string]*portalState{},
		failedResponseOp:  -1,
		syntheticFailedTx: syntheticFailedTx,
	}
	if err := s.reauthorizeClient(ctx, client, session, *txStatus); err != nil {
		return false, err
	}
	if err := s.appendExtendedMessage(ctx, &state, first); err != nil {
		return extendedAppendError(client, err)
	}

	for {
		msg, err := client.Receive()
		if err != nil {
			return false, err
		}
		switch m := msg.(type) {
		case *pgproto3.Sync:
			if denied := s.authorizeExtendedMetadata(ctx, &state); denied != nil {
				if denied.syntheticFailedTx {
					return false, s.rejectFailedTransaction(ctx, client, recorder, denied.req, started)
				}
				return false, s.denyQuery(ctx, client, recorder, denied.req, denied.decision, started, txStatus, syntheticFailedTx)
			}
			if state.denied != nil {
				if state.denied.syntheticFailedTx {
					return false, s.rejectFailedTransaction(ctx, client, recorder, state.denied.req, started)
				}
				return false, s.denyQuery(ctx, client, recorder, state.denied.req, state.denied.decision, started, txStatus, syntheticFailedTx)
			}
			state.batch = append(state.batch, m)
			for _, msg := range state.batch {
				upstream.Send(msg)
			}
			if err := upstream.Flush(); err != nil {
				return false, err
			}
			stats := &queryStats{}
			rowCap := 0
			exec := state.lastExecution()
			if exec != nil {
				rowCap = exec.decision.RowCap
			}
			err := forwardUntilReadyWithObserver(client, upstream, stats, rowCap, state.observeBackendMessage)
			if stats.txStatus != 0 {
				*txStatus = stats.txStatus
			}
			if *syntheticFailedTx && *txStatus == 'I' {
				*syntheticFailedTx = false
			}
			if exec != nil && state.executionReached(exec, err) {
				record := queryRecord(exec.req, exec.decision, stats, started, s.now())
				if errors.Is(err, errRowCapExceeded) {
					record.Status = "row_cap_exceeded"
					record.ErrorCode = "P0001"
					record.ErrorMessage = fmt.Sprintf("row cap exceeded: %d rows returned, cap is %d", stats.rows, exec.decision.RowCap)
					recordQueryBestEffort(ctx, recorder, record)
					_ = upstreamConn.Close()
					_ = writeErrorWithTxStatus(client, "P0001", "postgres row cap exceeded", record.ErrorMessage, *txStatus)
					return false, errors.New(record.ErrorMessage)
				}
				if errors.Is(err, errCopyInUnsupported) {
					record.Status = "error"
					record.ErrorCode = "0A000"
					record.ErrorMessage = err.Error()
					recordQueryBestEffort(ctx, recorder, record)
					_ = upstreamConn.Close()
					_ = writeErrorWithTxStatus(client, "0A000", "postgres COPY FROM STDIN is not supported", record.ErrorMessage, *txStatus)
					return false, errors.New(record.ErrorMessage)
				}
				if errors.Is(err, errCopyOutRowCapUnsupported) {
					record.Status = "error"
					record.ErrorCode = "0A000"
					record.ErrorMessage = err.Error()
					recordQueryBestEffort(ctx, recorder, record)
					_ = upstreamConn.Close()
					_ = writeErrorWithTxStatus(client, "0A000", "postgres COPY TO STDOUT is not supported with row caps", record.ErrorMessage, *txStatus)
					return false, errors.New(record.ErrorMessage)
				}
				if err != nil {
					record.Status = "error"
					record.ErrorMessage = err.Error()
					recordQueryBestEffort(ctx, recorder, record)
					return false, err
				}
				recordQueryBestEffort(ctx, recorder, record)
			}
			if stats.status == "error" {
				return false, nil
			}
			return false, err
		default:
			if err := s.reauthorizeExtendedExecute(ctx, client, state.session, msg, *txStatus); err != nil {
				return false, err
			}
			if err := s.appendExtendedMessage(ctx, &state, msg); err != nil {
				return extendedAppendError(client, err)
			}
		}
	}
}

func extendedAppendError(client *pgproto3.Backend, err error) (bool, error) {
	if errors.Is(err, errExtendedBatchLimitExceeded) {
		if writeErr := writeErrorResponse(client, "54000", "postgres extended query batch is too large", err.Error()); writeErr != nil {
			return false, writeErr
		}
		return false, err
	}
	return true, writeUnsupportedExtendedError(client, err)
}

func (s *Server) reauthorizeExtendedExecute(ctx context.Context, client *pgproto3.Backend, session *Session, msg pgproto3.FrontendMessage, txStatus byte) error {
	if _, ok := msg.(*pgproto3.Execute); !ok {
		return nil
	}
	return s.reauthorizeClient(ctx, client, session, txStatus)
}

func (s *Server) reauthorizeClient(ctx context.Context, client *pgproto3.Backend, session *Session, txStatus byte) error {
	if err := s.reauthorize(ctx, session); err != nil {
		_ = writeErrorWithTxStatus(client, "42501", "postgres session revoked", "session is no longer authorized", txStatus)
		return err
	}
	return nil
}

func writeUnsupportedExtendedError(client *pgproto3.Backend, err error) error {
	return writeErrorResponse(client, "0A000", "postgres extended query shape is not supported", err.Error())
}

type extendedCycleState struct {
	session           *Session
	started           time.Time
	statements        map[string]preparedStatement
	portals           map[string]portalState
	pendingStatements map[string]*preparedStatement
	pendingPortals    map[string]*portalState
	responseOps       []extendedResponseOperation
	nextResponseOp    int
	failedResponseOp  int
	syntheticFailedTx *bool
	batch             []pgproto3.FrontendMessage
	batchBytes        int
	executions        []extendedExecution
	describes         []QueryRequest
	denied            *extendedExecution
}

type extendedExecution struct {
	req                 QueryRequest
	decision            Decision
	responseOpIndex     int
	bindResponseOpIndex int
	syntheticFailedTx   bool
}

type extendedResponseOperation struct {
	kind    extendedResponseOperationKind
	apply   func()
	onError func()
}

type extendedResponseOperationKind int

const (
	extendedResponseOperationParse extendedResponseOperationKind = iota + 1
	extendedResponseOperationBind
	extendedResponseOperationDescribe
	extendedResponseOperationClose
	extendedResponseOperationExecute
)

func (s *Server) appendExtendedMessage(ctx context.Context, state *extendedCycleState, msg pgproto3.FrontendMessage) error {
	if state.denied != nil {
		return nil
	}
	if len(state.executions) > 0 {
		if _, ok := msg.(*pgproto3.Execute); ok {
			return errMultipleExecutesUnsupported
		}
		if _, ok := msg.(*pgproto3.Flush); ok {
			return errExtendedFlushUnsupported
		}
		return errExtendedMessageAfterExecuteUnsupported
	}
	switch m := msg.(type) {
	case *pgproto3.Parse:
		cp := cloneParse(m)
		stmt := preparedStatement{query: cp.Query}
		state.pendingStatements[cp.Name] = &stmt
		state.responseOps = append(state.responseOps, extendedResponseOperation{
			kind: extendedResponseOperationParse,
			apply: func() {
				state.statements[cp.Name] = stmt
			},
			onError: func() {
				if cp.Name == "" {
					delete(state.statements, cp.Name)
				}
			},
		})
		if err := state.appendBatchMessage(cp); err != nil {
			return err
		}
	case *pgproto3.Bind:
		cp := cloneBind(m)
		stmt := state.lookupStatement(cp.PreparedStatement)
		responseOpIndex := len(state.responseOps)
		portal := portalState{
			statement:       cp.PreparedStatement,
			query:           stmt.query,
			parameterCount:  len(cp.Parameters),
			responseOpIndex: responseOpIndex,
		}
		state.pendingPortals[cp.DestinationPortal] = &portal
		state.responseOps = append(state.responseOps, extendedResponseOperation{
			kind: extendedResponseOperationBind,
			apply: func() {
				committedPortal := portal
				committedPortal.responseOpIndex = -1
				state.portals[cp.DestinationPortal] = committedPortal
			},
			onError: func() {
				if cp.DestinationPortal == "" {
					delete(state.portals, cp.DestinationPortal)
				}
			},
		})
		if err := state.appendBatchMessage(cp); err != nil {
			return err
		}
	case *pgproto3.Execute:
		cp := cloneExecute(m)
		portal := state.lookupPortal(cp.Portal)
		req := QueryRequest{
			Session:        state.session,
			Protocol:       QueryProtocolExtended,
			SQL:            portal.query,
			StatementClass: classifySQL(portal.query),
			Portal:         cp.Portal,
			Statement:      portal.statement,
			ParameterCount: portal.parameterCount,
			StartedAt:      state.started,
		}
		var d Decision
		syntheticFailedTx := false
		if state.syntheticFailedTx != nil && *state.syntheticFailedTx && !isTransactionRecoveryStatement(req.StatementClass) {
			syntheticFailedTx = true
			d = Decision{
				Action: DecisionDeny,
				Reason: "current transaction is aborted, commands ignored until end of transaction block",
			}
		} else if requiresParserSupport(req.StatementClass) {
			d = Decision{
				Action: DecisionDeny,
				Reason: fmt.Sprintf("%s statements require SQL parser support before policy enforcement", req.StatementClass),
			}
		} else {
			d = normalizeDecision(s.authorizeQuery(ctx, req))
			d = constrainDecisionForStatement(req, d)
		}
		exec := extendedExecution{
			req:                 req,
			decision:            d,
			responseOpIndex:     -1,
			bindResponseOpIndex: portal.responseOpIndex,
			syntheticFailedTx:   syntheticFailedTx,
		}
		state.executions = append(state.executions, exec)
		if d.Action == DecisionRowCap && cp.MaxRows > 0 {
			return errRowCappedChunkedExecuteUnsupported
		}
		if d.Action == DecisionDeny || d.Action == DecisionStepUp {
			state.denied = &exec
			return nil
		}
		exec.responseOpIndex = len(state.responseOps)
		state.executions[len(state.executions)-1] = exec
		state.responseOps = append(state.responseOps, extendedResponseOperation{kind: extendedResponseOperationExecute})
		if err := state.appendBatchMessage(cp); err != nil {
			return err
		}
	case *pgproto3.Describe:
		req := state.describeRequest(m)
		state.describes = append(state.describes, req)
		state.responseOps = append(state.responseOps, extendedResponseOperation{kind: extendedResponseOperationDescribe})
		if err := state.appendBatchMessage(cloneDescribe(m)); err != nil {
			return err
		}
	case *pgproto3.Close:
		cp := cloneClose(m)
		op := extendedResponseOperation{kind: extendedResponseOperationClose}
		switch cp.ObjectType {
		case 'S':
			state.pendingStatements[cp.Name] = nil
			op.apply = func() {
				delete(state.statements, cp.Name)
			}
		case 'P':
			state.pendingPortals[cp.Name] = nil
			op.apply = func() {
				delete(state.portals, cp.Name)
			}
		}
		state.responseOps = append(state.responseOps, op)
		if err := state.appendBatchMessage(cp); err != nil {
			return err
		}
	case *pgproto3.Flush:
		return errExtendedFlushUnsupported
	default:
		return fmt.Errorf("extended query message %T before Sync is not supported by the postgres proxy", msg)
	}
	return nil
}

func (state *extendedCycleState) appendBatchMessage(msg pgproto3.FrontendMessage) error {
	if len(state.batch) >= maxExtendedBatchMessages {
		return errExtendedBatchLimitExceeded
	}
	size, err := frontendMessageLen(msg)
	if err != nil {
		return err
	}
	if state.batchBytes+size > maxExtendedBatchBytes {
		return errExtendedBatchLimitExceeded
	}
	state.batch = append(state.batch, msg)
	state.batchBytes += size
	return nil
}

func frontendMessageLen(msg pgproto3.FrontendMessage) (int, error) {
	encoded, err := msg.Encode(nil)
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

func (state *extendedCycleState) lookupStatement(name string) preparedStatement {
	if stmt, ok := state.pendingStatements[name]; ok {
		if stmt == nil {
			return preparedStatement{}
		}
		return *stmt
	}
	return state.statements[name]
}

func (state *extendedCycleState) lookupPortal(name string) portalState {
	if portal, ok := state.pendingPortals[name]; ok {
		if portal == nil {
			return portalState{responseOpIndex: -1}
		}
		return *portal
	}
	if portal, ok := state.portals[name]; ok {
		return portal
	}
	return portalState{responseOpIndex: -1}
}

func (state *extendedCycleState) describeRequest(msg *pgproto3.Describe) QueryRequest {
	req := QueryRequest{
		Session:        state.session,
		Protocol:       QueryProtocolExtended,
		StatementClass: "DESCRIBE",
		StartedAt:      state.started,
	}
	switch msg.ObjectType {
	case 'S':
		stmt := state.lookupStatement(msg.Name)
		req.SQL = stmt.query
		req.Statement = msg.Name
	case 'P':
		portal := state.lookupPortal(msg.Name)
		req.SQL = portal.query
		req.Portal = msg.Name
		req.Statement = portal.statement
		req.ParameterCount = portal.parameterCount
	}
	if req.SQL != "" {
		req.StatementClass = classifySQL(req.SQL)
	}
	return req
}

func (state *extendedCycleState) parseRequests() []QueryRequest {
	names := make([]string, 0, len(state.pendingStatements))
	for name, stmt := range state.pendingStatements {
		if stmt != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	requests := make([]QueryRequest, 0, len(names))
	for _, name := range names {
		stmt := state.pendingStatements[name]
		requests = append(requests, QueryRequest{
			Session:        state.session,
			Protocol:       QueryProtocolExtended,
			SQL:            stmt.query,
			StatementClass: classifySQL(stmt.query),
			Statement:      name,
			StartedAt:      state.started,
		})
	}
	return requests
}

func (s *Server) authorizeExtendedMetadata(ctx context.Context, state *extendedCycleState) *extendedExecution {
	var firstDenied *extendedExecution
	for _, req := range state.parseRequests() {
		denied := s.authorizeExtendedMetadataRequest(ctx, state, req, true)
		if denied != nil && firstDenied == nil {
			firstDenied = denied
		}
	}
	for _, req := range state.describes {
		denied := s.authorizeExtendedMetadataRequest(ctx, state, req, false)
		if denied != nil && firstDenied == nil {
			firstDenied = denied
		}
	}
	return firstDenied
}

func (s *Server) authorizeExtendedMetadataRequest(ctx context.Context, state *extendedCycleState, req QueryRequest, applyFailedTx bool) *extendedExecution {
	var decision Decision
	syntheticFailedTx := false
	if applyFailedTx && state.syntheticFailedTx != nil && *state.syntheticFailedTx && !isTransactionRecoveryStatement(req.StatementClass) {
		syntheticFailedTx = true
		decision = Decision{
			Action: DecisionDeny,
			Reason: "current transaction is aborted, commands ignored until end of transaction block",
		}
	} else if requiresParserSupport(req.StatementClass) {
		decision = Decision{
			Action: DecisionDeny,
			Reason: fmt.Sprintf("%s statements require SQL parser support before policy enforcement", req.StatementClass),
		}
	} else {
		decision = normalizeDecision(s.authorizeQuery(ctx, req))
		decision = constrainDecisionForStatement(req, decision)
	}
	if decision.Action != DecisionDeny && decision.Action != DecisionStepUp {
		return nil
	}
	return &extendedExecution{
		req:               req,
		decision:          decision,
		responseOpIndex:   -1,
		syntheticFailedTx: syntheticFailedTx,
	}
}

func (state *extendedCycleState) lastExecution() *extendedExecution {
	if len(state.executions) == 0 {
		return nil
	}
	return &state.executions[len(state.executions)-1]
}

func (state *extendedCycleState) executionReached(exec *extendedExecution, err error) bool {
	if exec.responseOpIndex < 0 {
		return true
	}
	if state.nextResponseOp > exec.responseOpIndex {
		return true
	}
	if state.failedResponseOp == exec.responseOpIndex ||
		(exec.bindResponseOpIndex >= 0 && state.failedResponseOp == exec.bindResponseOpIndex) {
		return true
	}
	return errors.Is(err, errRowCapExceeded) ||
		errors.Is(err, errCopyInUnsupported) ||
		errors.Is(err, errCopyOutRowCapUnsupported)
}

func (state *extendedCycleState) observeBackendMessage(msg pgproto3.BackendMessage) {
	switch m := msg.(type) {
	case *pgproto3.ParseComplete:
		state.completeResponseOperation(extendedResponseOperationParse)
	case *pgproto3.BindComplete:
		state.completeResponseOperation(extendedResponseOperationBind)
	case *pgproto3.CloseComplete:
		state.completeResponseOperation(extendedResponseOperationClose)
	case *pgproto3.ErrorResponse:
		state.failResponseOperation()
	case *pgproto3.RowDescription, *pgproto3.NoData:
		state.completeResponseOperation(extendedResponseOperationDescribe)
	case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
		state.completeResponseOperation(extendedResponseOperationExecute)
	case *pgproto3.ReadyForQuery:
		clearPortalsIfIdle(state.portals, m.TxStatus)
	}
}

func (state *extendedCycleState) completeResponseOperation(kind extendedResponseOperationKind) {
	if state.nextResponseOp >= len(state.responseOps) {
		return
	}
	op := state.responseOps[state.nextResponseOp]
	if op.kind != kind {
		return
	}
	state.nextResponseOp++
	if op.apply != nil {
		op.apply()
	}
}

func (state *extendedCycleState) failResponseOperation() {
	if state.nextResponseOp >= len(state.responseOps) {
		return
	}
	op := state.responseOps[state.nextResponseOp]
	state.failedResponseOp = state.nextResponseOp
	state.nextResponseOp++
	if op.onError != nil {
		op.onError()
	}
}

func clearPortalsIfIdle(portals map[string]portalState, txStatus byte) {
	if txStatus != 'I' {
		return
	}
	for name := range portals {
		delete(portals, name)
	}
}

func (s *Server) denyQuery(ctx context.Context, client *pgproto3.Backend, recorder Recorder, req QueryRequest, decision Decision, started time.Time, txStatus *byte, syntheticFailedTx *bool) error {
	status := byte('I')
	if txStatus != nil {
		status = *txStatus
	}
	if status == 'T' || status == 'E' {
		status = 'E'
		if txStatus != nil {
			*txStatus = status
		}
		if syntheticFailedTx != nil {
			*syntheticFailedTx = true
		}
	}
	record := queryRecord(req, decision, &queryStats{}, started, s.now())
	record.Status = "denied"
	record.ErrorCode = "42501"
	record.ErrorMessage = decision.Reason
	recordQueryBestEffort(ctx, recorder, record)
	return writeErrorWithTxStatus(client, "42501", "postgres query denied by policy", decision.Reason, status)
}

func (s *Server) rejectFailedTransaction(ctx context.Context, client *pgproto3.Backend, recorder Recorder, req QueryRequest, started time.Time) error {
	record := queryRecord(req, Decision{
		Action: DecisionDeny,
		Reason: "current transaction is aborted, commands ignored until end of transaction block",
	}, &queryStats{}, started, s.now())
	record.Status = "denied"
	record.ErrorCode = "25P02"
	record.ErrorMessage = record.Reason
	recordQueryBestEffort(ctx, recorder, record)
	return writeErrorWithTxStatus(client, "25P02", "current transaction is aborted", record.Reason, 'E')
}

func isTransactionRecoveryStatement(statementClass string) bool {
	return statementClass == "ROLLBACK" || statementClass == "ABORT"
}

func recordQueryBestEffort(ctx context.Context, recorder Recorder, record QueryRecord) {
	// BeginSession fails closed before the upstream connection is exposed. Once a
	// query is in flight, this PoC keeps the Postgres protocol outcome stable and
	// treats per-query recorder write errors as best-effort telemetry failures.
	// Recorder implementations should honor the context deadline.
	recorderCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = recorder.RecordQuery(recorderCtx, record)
}

type queryStats struct {
	rows         int
	commandTag   string
	status       string
	errorCode    string
	errorMessage string
	txStatus     byte
}

var (
	errRowCapExceeded                         = errors.New("row cap exceeded")
	errCopyInUnsupported                      = errors.New("COPY FROM STDIN is not supported by the postgres proxy")
	errCopyOutRowCapUnsupported               = errors.New("COPY TO STDOUT is not supported with row caps by the postgres proxy")
	errExtendedFlushUnsupported               = errors.New("extended query Flush before Sync is not supported by the postgres proxy")
	errMultipleExecutesUnsupported            = errors.New("multiple extended Execute messages before Sync are not supported by the postgres proxy")
	errExtendedMessageAfterExecuteUnsupported = errors.New("extended query messages after Execute before Sync are not supported by the postgres proxy")
	errRowCappedChunkedExecuteUnsupported     = errors.New("row-capped extended Execute with MaxRows is not supported by the postgres proxy")
	errExtendedBatchLimitExceeded             = errors.New("extended query batch before Sync exceeds postgres proxy limits")
)

func forwardUntilReady(client *pgproto3.Backend, upstream *pgproto3.Frontend, stats *queryStats, rowCap int) error {
	return forwardUntilReadyWithObserver(client, upstream, stats, rowCap, nil)
}

func forwardUntilReadyWithObserver(client *pgproto3.Backend, upstream *pgproto3.Frontend, stats *queryStats, rowCap int, observe func(pgproto3.BackendMessage)) error {
	for {
		msg, err := upstream.Receive()
		if err != nil {
			return err
		}
		if observe != nil {
			observe(msg)
		}
		if stats != nil {
			switch m := msg.(type) {
			case *pgproto3.DataRow:
				stats.rows++
				if rowCap > 0 && stats.rows > rowCap {
					return errRowCapExceeded
				}
			case *pgproto3.CommandComplete:
				stats.commandTag = string(m.CommandTag)
				if stats.rows == 0 {
					stats.rows = parseCommandRows(stats.commandTag)
				}
			case *pgproto3.ErrorResponse:
				stats.status = "error"
				stats.errorCode = m.Code
				stats.errorMessage = m.Message
			case *pgproto3.CopyInResponse:
				return errCopyInUnsupported
			case *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
				if rowCap > 0 {
					return errCopyOutRowCapUnsupported
				}
			}
		}
		client.Send(msg)
		if err := client.Flush(); err != nil {
			return err
		}
		if ready, ok := msg.(*pgproto3.ReadyForQuery); ok {
			if stats != nil {
				stats.txStatus = ready.TxStatus
			}
			if stats != nil && stats.status == "" {
				stats.status = "ok"
			}
			return nil
		}
	}
}

func queryRecord(req QueryRequest, decision Decision, stats *queryStats, start, end time.Time) QueryRecord {
	status := stats.status
	if status == "" {
		status = "ok"
	}
	return QueryRecord{
		SessionID:          req.Session.ID,
		Protocol:           req.Protocol,
		SQL:                req.SQL,
		StatementClass:     req.StatementClass,
		Decision:           decision.Action,
		Reason:             decision.Reason,
		RowCap:             decision.RowCap,
		Rows:               stats.rows,
		CommandTag:         stats.commandTag,
		Status:             status,
		ErrorCode:          stats.errorCode,
		ErrorMessage:       stats.errorMessage,
		ParameterCount:     req.ParameterCount,
		ParametersRedacted: req.ParameterCount > 0,
		StartedAt:          start,
		Duration:           end.Sub(start),
	}
}

func normalizeDecision(decision *Decision, err error) Decision {
	if err != nil {
		return Decision{Action: DecisionDeny, Reason: err.Error()}
	}
	if decision == nil || decision.Action == "" {
		return Decision{Action: DecisionDeny, Reason: "empty postgres policy decision"}
	}
	switch decision.Action {
	case DecisionAllow, DecisionDeny, DecisionStepUp:
		return *decision
	case DecisionRowCap:
		if decision.RowCap <= 0 {
			return Decision{Action: DecisionDeny, Reason: "row_cap decisions require a positive row cap"}
		}
		return *decision
	default:
		return Decision{Action: DecisionDeny, Reason: fmt.Sprintf("unsupported postgres policy decision action %q", decision.Action)}
	}
}

func constrainDecisionForStatement(req QueryRequest, decision Decision) Decision {
	if decision.Action == DecisionRowCap && req.StatementClass != "SELECT" {
		return Decision{
			Action: DecisionDeny,
			Reason: fmt.Sprintf("row caps are only supported for SELECT statements, not %s", req.StatementClass),
		}
	}
	return decision
}

func requiresParserSupport(statementClass string) bool {
	// Until a real SQL parser lands, only direct leading-keyword classes whose
	// policy meaning is explicit are allowed through to the policy adapter. This
	// is still lexical: SELECT can call volatile/write-capable functions, so
	// read-only semantics require the planned PostgreSQL parser.
	switch statementClass {
	case "ALTER", "BEGIN", "COMMIT", "DELETE", "DESCRIBE", "DROP", "EMPTY", "INSERT", "RELEASE", "RESET", "ROLLBACK", "SAVEPOINT", "SELECT", "SET", "SHOW", "START", "TRUNCATE", "UPDATE", "VALUES":
		return false
	default:
		return true
	}
}

func cloneSession(session *Session) *Session {
	if session == nil {
		return nil
	}
	cp := *session
	return &cp
}

func cloneParse(m *pgproto3.Parse) *pgproto3.Parse {
	return &pgproto3.Parse{
		Name:          m.Name,
		Query:         m.Query,
		ParameterOIDs: append([]uint32(nil), m.ParameterOIDs...),
	}
}

func cloneBind(m *pgproto3.Bind) *pgproto3.Bind {
	parameters := make([][]byte, len(m.Parameters))
	for i := range m.Parameters {
		parameters[i] = append([]byte(nil), m.Parameters[i]...)
	}
	return &pgproto3.Bind{
		DestinationPortal:    m.DestinationPortal,
		PreparedStatement:    m.PreparedStatement,
		ParameterFormatCodes: append([]int16(nil), m.ParameterFormatCodes...),
		Parameters:           parameters,
		ResultFormatCodes:    append([]int16(nil), m.ResultFormatCodes...),
	}
}

func cloneExecute(m *pgproto3.Execute) *pgproto3.Execute {
	return &pgproto3.Execute{Portal: m.Portal, MaxRows: m.MaxRows}
}

func cloneDescribe(m *pgproto3.Describe) *pgproto3.Describe {
	return &pgproto3.Describe{ObjectType: m.ObjectType, Name: m.Name}
}

func cloneClose(m *pgproto3.Close) *pgproto3.Close {
	return &pgproto3.Close{ObjectType: m.ObjectType, Name: m.Name}
}
