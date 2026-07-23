// Discovery-ingestor fixture ONLY — a factory-per-file file-read shape: the
// request-controlled file flows into fs.readFile, handler body in this module.
import fs from 'node:fs'
import { type Request, type Response } from 'express'

export function download () {
  return (req: Request, res: Response) => {
    const file = req.query.file
    fs.readFile(file as string, 'utf8', (err, data) => {
      res.send(data)
    })
  }
}
