// Minimal ESM/TS Express backend — a discovery-ingestor fixture ONLY.
// Reproduces the real-world shape (used by OWASP Juice Shop): route paths are
// registered here, but each handler is a FACTORY imported from a separate routes
// file, often wrapped in middleware (`asyncHandler(...)`) with preceding middleware.
// The vulnerable sink lives in the routes file, NOT inline here.
import express from 'express'
import multer from 'multer'

import { profileImageUrlUpload } from './routes/profileImageUrlUpload'
import { download } from './routes/download'

const app = express()
const uploadToMemory = multer({ storage: multer.memoryStorage() })

app.use(express.json())

// SSRF: handler factory in ./routes/profileImageUrlUpload.ts, wrapped + middleware.
app.post('/profile/image/url', uploadToMemory.single('file'), asyncHandler(profileImageUrlUpload()))

// File read via app.use with a factory handler.
app.get('/download', download())

app.listen(3000)
