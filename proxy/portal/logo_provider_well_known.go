package portal

import (
	"context"
	_ "embed"
	"net"
	"path/filepath"

	"github.com/pomerium/pomerium/internal/urlutil"
)

var (
	//go:embed logos/activemq.svg
	activemqLogo []byte
	//go:embed logos/aerospike.svg
	aerospikeLogo []byte
	//go:embed logos/cassandra.svg
	cassandraLogo []byte
	//go:embed logos/clickhouse.svg
	clickhouseLogo []byte
	//go:embed logos/cloudera.svg
	clouderaLogo []byte
	//go:embed logos/cockroachdb.svg
	cockroachdbLogo []byte
	//go:embed logos/consul.svg
	consulLogo []byte
	//go:embed logos/couchbase.svg
	couchbaseLogo []byte
	//go:embed logos/couchdb.svg
	couchdbLogo []byte
	//go:embed logos/cratedb.svg
	cratedbLogo []byte
	//go:embed logos/elasticsearch.svg
	elasticsearchLogo []byte
	//go:embed logos/etcd.svg
	etcdLogo []byte
	//go:embed logos/ftp.svg
	ftpLogo []byte
	//go:embed logos/hadoop.svg
	hadoopLogo []byte
	//go:embed logos/hbase.svg
	hbaseLogo []byte
	//go:embed logos/ibmmq.svg
	ibmmqLogo []byte
	//go:embed logos/influxdb.svg
	influxdbLogo []byte
	//go:embed logos/kafka.svg
	kafkaLogo []byte
	//go:embed logos/machbase.png
	machbaseLogo []byte
	//go:embed logos/mariadb.svg
	mariadbLogo []byte
	//go:embed logos/meilisearch.svg
	meilisearchLogo []byte
	//go:embed logos/memcached.svg
	memcachedLogo []byte
	//go:embed logos/mongodb.svg
	mongodbLogo []byte
	//go:embed logos/mqtt.svg
	mqttLogo []byte
	//go:embed logos/nfs.svg
	nfsLogo []byte
	//go:embed logos/neo4j.svg
	neo4jLogo []byte
	//go:embed logos/opentext.svg
	opentextLogo []byte
	//go:embed logos/oracle.svg
	oracleLogo []byte
	//go:embed logos/postgres.svg
	postgresLogo []byte
	//go:embed logos/rabbitmq.svg
	rabbitmqLogo []byte
	//go:embed logos/redis.svg
	redisLogo []byte
	//go:embed logos/riak.svg
	riakLogo []byte
	//go:embed logos/sphinx.png
	sphinxLogo []byte
	//go:embed logos/ssh.svg
	sshLogo []byte
	//go:embed logos/typesense.svg
	typesenseLogo []byte
	//go:embed logos/zookeeper.svg
	zookeeperLogo []byte
)

type wellKnownLogoProvider struct{}

func newWellKnownLogoProvider() LogoProvider {
	return &wellKnownLogoProvider{}
}

func (p *wellKnownLogoProvider) GetLogoURL(_ context.Context, _, to string) (string, error) {
	u, err := urlutil.ParseAndValidateURL(to)
	if err != nil {
		return "", ErrLogoNotFound
	}

	if !(u.Scheme == "tcp" ||
		u.Scheme == "udp") {
		return "", ErrLogoNotFound
	}

	host := u.Host
	if len(u.Path) > 1 {
		_, host = filepath.Split(u.Path)
	}

	_, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return "", ErrLogoNotFound
	}

	switch portStr {
	case "21": // ftp
		return dataURL(mediaTypeSVG, ftpLogo), nil
	case "22": // ssh
		return dataURL(mediaTypeSVG, sshLogo), nil
	case "111", "2049": // nfs
		return dataURL(mediaTypeSVG, nfsLogo), nil
	case "1414": // ibmmq
		return dataURL(mediaTypeSVG, ibmmqLogo), nil
	case "1521": // oracle
		return dataURL(mediaTypeSVG, oracleLogo), nil
	case "1883", "8883", "14567":
		return dataURL(mediaTypeSVG, mqttLogo), nil
	case "2181": // zookeeper
		return dataURL(mediaTypeSVG, zookeeperLogo), nil
	case "2379": // etcd
		return dataURL(mediaTypeSVG, etcdLogo), nil
	case "3000": // aerospike
		return dataURL(mediaTypeSVG, aerospikeLogo), nil
	case "3306": // mariadb
		return dataURL(mediaTypeSVG, mariadbLogo), nil
	case "4200": // cratedb
		return dataURL(mediaTypeSVG, cratedbLogo), nil
	case "5432": // postgres
		return dataURL(mediaTypeSVG, postgresLogo), nil
	case "5433": // vertica
		return dataURL(mediaTypeSVG, opentextLogo), nil
	case "5652", "5653", "5654", "5655", "5656": // machbase
		return dataURL(mediaTypePNG, machbaseLogo), nil
	case "5672": // rabbitmq
		return dataURL(mediaTypeSVG, rabbitmqLogo), nil
	case "5984": // couchdb
		return dataURL(mediaTypeSVG, couchdbLogo), nil
	case "6379": // redis
		return dataURL(mediaTypeSVG, redisLogo), nil
	case "7180", "7183": // cloudera
		return dataURL(mediaTypeSVG, clouderaLogo), nil
	case "7474", "7473": // neo4j
		return dataURL(mediaTypeSVG, neo4jLogo), nil
	case "7700": // meilisearch
		return dataURL(mediaTypeSVG, meilisearchLogo), nil
	case "8020", "50070": // hadoop
		return dataURL(mediaTypeSVG, hadoopLogo), nil
	case "8086": // influxdb
		return dataURL(mediaTypeSVG, influxdbLogo), nil
	case "8070", "8085", "9090", "9095", "16000", "16010": // hbase
		return dataURL(mediaTypeSVG, hbaseLogo), nil
	case "8091": // couchbase
		return dataURL(mediaTypeSVG, couchbaseLogo), nil
	case "8098": // riak
		return dataURL(mediaTypeSVG, riakLogo), nil
	case "8108": // typesense
		return dataURL(mediaTypeSVG, typesenseLogo), nil
	case "8500", "8501", "8502", "8503": // consul
		return dataURL(mediaTypeSVG, consulLogo), nil
	case "9000", "9100": // clickhouse
		return dataURL(mediaTypeSVG, clickhouseLogo), nil
	case "9042", "9160", "9142": // cassandra
		return dataURL(mediaTypeSVG, cassandraLogo), nil
	case "9092": // kafka
		return dataURL(mediaTypeSVG, kafkaLogo), nil
	case "9200", "9300": // elasticsearch
		return dataURL(mediaTypeSVG, elasticsearchLogo), nil
	case "9306", "9312": // sphinx
		return dataURL(mediaTypePNG, sphinxLogo), nil
	case "11211": // memcached
		return dataURL(mediaTypeSVG, memcachedLogo), nil
	case "26257": // cockroachdb
		return dataURL(mediaTypeSVG, cockroachdbLogo), nil
	case "27017": // mongodb
		return dataURL(mediaTypeSVG, mongodbLogo), nil
	case "61616": // activemq
		return dataURL(mediaTypeSVG, activemqLogo), nil
	}

	return "", ErrLogoNotFound
}
