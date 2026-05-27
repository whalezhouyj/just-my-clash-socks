import { createServer } from "http";
import handler from "./api/sub";

const PORT = 3456;

const server = createServer(handler);

server.listen(PORT, () => {
  console.log(`Dev server started at: http://localhost:${PORT}/api/sub?service={service}&id={id}`);
});
