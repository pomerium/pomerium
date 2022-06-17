window.BENCHMARK_DATA = {
  "lastUpdate": 1655493771103,
  "repoUrl": "https://github.com/pomerium/pomerium",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "pomerium",
            "username": "pomerium"
          },
          "committer": {
            "name": "pomerium",
            "username": "pomerium"
          },
          "id": "0889b2f22459ed58cac542b6b1eaa1d519517c96",
          "message": "add benchmark",
          "timestamp": "2022-06-17T05:38:44Z",
          "url": "https://github.com/pomerium/pomerium/pull/3433/commits/0889b2f22459ed58cac542b6b1eaa1d519517c96"
        },
        "date": 1655493770633,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkLoggedInUserAccess",
            "value": 16811746,
            "unit": "ns/op",
            "extra": "76 times\n2 procs"
          },
          {
            "name": "BenchmarkLoggedOutUserAccess",
            "value": 9927855,
            "unit": "ns/op",
            "extra": "123 times\n2 procs"
          }
        ]
      }
    ]
  }
}