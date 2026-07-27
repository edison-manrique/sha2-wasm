import { join } from "path"

const basePort = Number(process.env.PORT) || 3000

function startServer(port: number) {
  try {
    const server = Bun.serve({
      port,
      async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url)
        const reqPath = url.pathname === "/" ? "/examples/index.html" : url.pathname
        const filePath = join(import.meta.dir, "..", reqPath)
        const file = Bun.file(filePath)

        if (!(await file.exists())) {
          return new Response(`404 Not Found: ${url.pathname}`, {
            status: 404,
            headers: { "Content-Type": "text/plain; charset=utf-8" }
          })
        }
        return new Response(file)
      }
    })

    console.log(`🚀 Servidor de ejemplo SHA2-WASM ejecutándose en http://localhost:${server.port}/examples/index.html`)
    return server
  } catch (err: any) {
    if (err?.code === "EADDRINUSE" && port < basePort + 10) {
      return startServer(port + 1)
    }
    throw err
  }
}

startServer(basePort)
