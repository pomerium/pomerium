const WebSocket = require("ws");

console.log("starting websocket server on :8080");
const wss = new WebSocket.Server({ port: 8080 });
wss.on("connection", function connection(ws) {
  ws.on("message", function incoming(message) {
    console.log("received: %s", message);
    ws.send(message);
  });
});
