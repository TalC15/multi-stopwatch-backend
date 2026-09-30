import { Server } from "socket.io";

export function createSocketServer(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: "*" },
    allowEIO3: false,
  });

  // Validate every request, including upgrades of an existing polling session.
  // allowRequest only checks initial handshakes, which leaves sid upgrades out.
  io.engine.use((req, res, next) => {
    if (req._query.EIO !== "4") {
      return next(new Error("Unsupported Engine.IO protocol"));
    }
    next();
  });

  return io;
}
