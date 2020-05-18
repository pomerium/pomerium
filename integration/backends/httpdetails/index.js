const http = require("http");

const requestListener = function (req, res) {
  const {
    pathname: path,
    hostname: host,
    port: port,
    search: query,
    hash: hash,
  } = new URL(req.url, `http://${req.headers.host}`);

  res.setHeader("Content-Type", "application/json");
  res.writeHead(200);
  res.end(
    JSON.stringify({
      headers: req.headers,
      method: req.method,
      host: host,
      port: port,
      path: path,
      query: query,
      hash: hash,
    })
  );
};

const server = http.createServer(requestListener);
console.log("starting http server on :8080");
server.listen(8080);
