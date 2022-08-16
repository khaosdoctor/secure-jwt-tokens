import path from 'path'
import dotenv from 'dotenv'
import express from 'express'
import cookieParser from 'cookie-parser'

import { apiRoutes } from './handlers'

dotenv.config()

const app = express()
app.use(express.json())
app.use(cookieParser())

app.use('/site', express.static(path.resolve(__dirname, './frontend'), { cacheControl: false }))

app.use('/api', apiRoutes)

app.listen(3000, () => console.log('JWT example listening on port 3000!'))

// NOTE: Essa ideia de JWT seguro pode virar uma lib que é um middleware do express que faz automaticamente o setup de JWT seguro
