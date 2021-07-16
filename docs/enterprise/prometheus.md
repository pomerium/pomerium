---
title: Prometheus
sidebarDepth: 1
description: Use Prometheus as a metrics data store.
---

# Prometheus Metrics

The Pomerium Enterprise Console uses Prometheus as a metrics collection back-end. You can configure Pomerium and the Console to talk to an existing Prometheus server, or configure the embedded Prometheus backend.

## External Prometheus

1. In the Pomerium `config.yaml` define the `metrics_address` key to a network interface and port. For example:

   ```yaml
   metrics_address: localhost:9999
   ```

1. Add this listener to your Prometheus configurarion, usually via `prometheus.yml`:

   ```yaml
   - job_name: 'Pomerium'
      scrape_interval: 30s
      scrape_timeout: 5s
      static_configs:
         - targets: ['192.0.2.10:9999']

   ```

1. [Reload](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#configuration) the Prometheus configuration:

   ```bash
   curl -i -XPOST path.to.prometheus:port/-/reload
   ```

1. In the Pomerium Enterprise Console `config.yaml` file, define the `prometheus_url` key to point to your Prometheus instance(s):

   ```yaml
   prometheus_url: http://192.168.122.50:9090
   ```

1. Restart the Pomerium and Pomerium Enterprise Console services. You should now see route traffic data in the Enterprise Console:

   ![Traffic Data in Pomerium Enterprise Console](./img/console-route-traffic.png)

## Embedded Prometheus