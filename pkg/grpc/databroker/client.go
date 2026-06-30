package databroker

type ClientGetter interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
}

func NewStaticClientGetter(client DataBrokerServiceClient) ClientGetter {
	return ClientGetterFunc(func() DataBrokerServiceClient { return client })
}

type ClientGetterFunc func() DataBrokerServiceClient

func (f ClientGetterFunc) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return f()
}
