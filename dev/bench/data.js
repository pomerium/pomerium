window.BENCHMARK_DATA = {
  "lastUpdate": 1655502897521,
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
      },
      {
        "commit": {
          "author": {
            "email": "cdoxsey@pomerium.com",
            "name": "Caleb Doxsey",
            "username": "calebdoxsey"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "64def90532b4ff87fe85a0607ecaac05d8d3ba72",
          "message": "add benchmark (#3433)\n\n* add benchmark\r\n\r\n* add benchmark github action\r\n\r\n* commit\r\n\r\n* permissions",
          "timestamp": "2022-06-17T15:52:35-06:00",
          "tree_id": "9cf5ded8d7ef5680a07d26f62dd08520ac01b543",
          "url": "https://github.com/pomerium/pomerium/commit/64def90532b4ff87fe85a0607ecaac05d8d3ba72"
        },
        "date": 1655502897186,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkLoggedInUserAccess",
            "value": 14089558,
            "unit": "ns/op",
            "extra": "81 times\n2 procs"
          },
          {
            "name": "BenchmarkLoggedOutUserAccess",
            "value": 8541071,
            "unit": "ns/op",
            "extra": "139 times\n2 procs"
          }
        ]
      }
    ]
  }
}