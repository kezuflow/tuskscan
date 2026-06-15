import { createTuskscanApiServer, createTuskscanQueueWorker } from "./index.js";

const port = Number(process.env.PORT ?? 8787);

createTuskscanApiServer().listen(port, () => {
  console.log(`TuskScan API listening on http://localhost:${port}`);
  console.log("TuskScan API package owns the database queue worker in dev.");
});

createTuskscanQueueWorker().start();
