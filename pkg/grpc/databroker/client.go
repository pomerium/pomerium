package databroker

type ClientGetter interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
}

func NewStaticClientGetter(client DataBrokerServiceClient) ClientGetter {
	return staticClientGetter{
		client: client,
	}
}

type staticClientGetter struct {
	client DataBrokerServiceClient
}

func (w staticClientGetter) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return w.client
}
