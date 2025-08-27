package databroker

// type Client interface {
// 	databrokerpb.DataBrokerServiceClient
// 	registrypb.RegistryClient
// }

// type ClientConnManager interface {
// 	GetClient(target string) Client
// 	OnConfigChange(ctx context.Context, cfg *config.Config)
// 	Stop()
// }

// type clientConnManager struct {
// 	mu    sync.RWMutex
// 	conns map[string]*grpc.ClientConn
// }

// // NewClientConnManager craetes a new ClientConnManager
// func NewClientConnManager() ClientConnManager {
// 	return &clientConnManager{}
// }

// // GetClient returns a client for the given target.
// func (pool *clientConnManager) GetClient(target string) Client {
// 	return clientPoolClient{pool, target}
// }

// // OnConfigChange reacts to any changes in configuration.
// func (pool *clientConnManager) OnConfigChange(ctx context.Context, cfg *config.Config) {
// }

// func (pool *clientConnManager) Stop() {
// }

// func (pool *clientConnManager) withClientConn(target string, fn func(*grpc.ClientConn) error) error {
// 	pool.mu.RLock()
// 	cc, ok := pool.conns[target]
// 	pool.mu.RUnlock()

// 	if ok {
// 		return fn(cc)
// 	}

// 	pool.mu.Lock()
// 	defer pool.mu.Unlock()

// 	cc, ok = pool.conns[target]
// 	if ok {
// 		return fn(cc)
// 	}

// 	cc, err := grpc.NewClient(target)
// 	if err != nil {
// 		return err
// 	}
// 	pool.conns[target] = cc

// 	return fn(cc)
// }

// type clientPoolClient struct {
// 	*clientConnManager
// 	target string
// }

// func (client clientPoolClient) AcquireLease(
// 	ctx context.Context,
// 	req *databrokerpb.AcquireLeaseRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.AcquireLeaseResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).AcquireLease(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Get(
// 	ctx context.Context,
// 	req *databrokerpb.GetRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.GetResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).Get(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) List(
// 	ctx context.Context,
// 	req *registrypb.ListRequest,
// 	opts ...grpc.CallOption,
// ) (res *registrypb.ServiceList, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = registrypb.NewRegistryClient(cc).List(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) ListTypes(
// 	ctx context.Context,
// 	req *emptypb.Empty,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.ListTypesResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).ListTypes(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Put(
// 	ctx context.Context,
// 	req *databrokerpb.PutRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.PutResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).Put(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Patch(
// 	ctx context.Context,
// 	req *databrokerpb.PatchRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.PatchResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).Patch(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Query(
// 	ctx context.Context,
// 	req *databrokerpb.QueryRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.QueryResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).Query(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) ReleaseLease(
// 	ctx context.Context,
// 	req *databrokerpb.ReleaseLeaseRequest,
// 	opts ...grpc.CallOption,
// ) (res *emptypb.Empty, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).ReleaseLease(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) RenewLease(
// 	ctx context.Context,
// 	req *databrokerpb.RenewLeaseRequest,
// 	opts ...grpc.CallOption,
// ) (res *emptypb.Empty, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).RenewLease(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Report(
// 	ctx context.Context,
// 	req *registrypb.RegisterRequest,
// 	opts ...grpc.CallOption,
// ) (res *registrypb.RegisterResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = registrypb.NewRegistryClient(cc).Report(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) ServerInfo(
// 	ctx context.Context,
// 	req *emptypb.Empty,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.ServerInfoResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) SetOptions(
// 	ctx context.Context,
// 	req *databrokerpb.SetOptionsRequest,
// 	opts ...grpc.CallOption,
// ) (res *databrokerpb.SetOptionsResponse, err error) {
// 	return res, client.withClientConn(client.target, func(cc *grpc.ClientConn) error {
// 		var err error
// 		res, err = databrokerpb.NewDataBrokerServiceClient(cc).SetOptions(ctx, req, opts...)
// 		return err
// 	})
// }

// func (client clientPoolClient) Sync(
// 	ctx context.Context,
// 	req *databrokerpb.SyncRequest,
// 	opts ...grpc.CallOption,
// ) (stream grpc.ServerStreamingClient[databrokerpb.SyncResponse], err error) {
// 	panic("not implemented") // TODO: Implement
// }

// func (client clientPoolClient) SyncLatest(
// 	ctx context.Context,
// 	req *databrokerpb.SyncLatestRequest,
// 	opts ...grpc.CallOption,
// ) (stream grpc.ServerStreamingClient[databrokerpb.SyncLatestResponse], err error) {
// 	panic("not implemented") // TODO: Implement
// }

// func (client clientPoolClient) Watch(
// 	ctx context.Context,
// 	req *registrypb.ListRequest,
// 	opts ...grpc.CallOption,
// ) (stream grpc.ServerStreamingClient[registrypb.ServiceList], err error) {
// 	panic("not implemented") // TODO: Implement
// 	append(opts, grpc.OnFinish(func(err error) {
// 	}))
// }

// type clientPoolStream struct {
// 	grpc.ClientStream
// }
