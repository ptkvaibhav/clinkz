// Discovery-ingestor fixture ONLY — a minimal reproduction of the factory-per-file
// SSRF shape: the request-controlled imageUrl flows into a server-side fetch, with the
// handler body living in this separate module (not inline in server.ts).
import { type Request, type Response, type NextFunction } from 'express'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const url = req.body.imageUrl
    const response = await fetch(url)
    res.send(await response.text())
  }
}
