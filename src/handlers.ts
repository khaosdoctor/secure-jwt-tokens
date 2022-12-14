import { createHmac } from 'crypto'
import { NextFunction, Request, Response, Router } from 'express'
import jwt, { JwtPayload } from 'jsonwebtoken'
import { User, users } from './users'

interface ExtendedResponse extends Response<any, { user: Partial<User>; refreshHash: string }> {}
interface AccessTokenPayload extends JwtPayload, Omit<User, 'username' | 'password'> {}

const refreshTokenDB = new Map<string, string>()

/**
 * UTILITY FUNCTIONS
 */
const createAccessToken = (user: User) => {
  return jwt.sign(
    { sub: user.username, name: user.name, age: user.age, social: user.social },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      audience: 'urn:jwt:type:access',
      issuer: 'urn:system:token-issuer:type:access',
      expiresIn: `${process.env.ACCESS_TOKEN_DURATION_MINUTES}m`
    }
  )
}

const createRefreshToken = (user: User) => {
  const token = jwt.sign({ sub: user.username }, process.env.ACCESS_TOKEN_SECRET!, {
    audience: 'urn:jwt:type:refresh',
    issuer: 'urn:system:token-issuer:type:refresh',
    expiresIn: `${process.env.REFRESH_TOKEN_DURATION_MINUTES}m`
  })
  const tokenHash = createHmac('sha512', process.env.REFRESH_TOKEN_SECRET!).update(token).digest('hex')

  refreshTokenDB.set(tokenHash, user.username)
  setTimeout(() => {
    refreshTokenDB.delete(tokenHash)
    console.log(`Refresh token ${tokenHash} expired`)
    console.table(refreshTokenDB.entries())
  }, 5 * 60 * 1000)

  console.table(refreshTokenDB.entries())
  return token
}

const setRefreshCookie = (res: ExtendedResponse, token: string) => {
  res.cookie('refresh-token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    expires: new Date(Date.now() + Number(process.env.REFRESH_TOKEN_DURATION_MINUTES) * 60 * 1000)
  })
}

/**
 * MIDDLEWARES
 */
const withAccessAuth = (req: Request, res: ExtendedResponse, next: NextFunction) => {
  const token = req.headers['authorization']?.split('Bearer ')[1]
  if (!token) return res.status(401).send('Unauthorized')
  try {
    const { sub, name, age, social } = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, {
      audience: 'urn:jwt:type:access'
    }) as AccessTokenPayload

    res.locals.user = { username: sub!, name, age, social }
    next()
  } catch (error) {
    return res.status(401).send('Unauthorized')
  }
}

const withRefreshAuth = (req: Request, res: ExtendedResponse, next: NextFunction) => {
  const token = req.cookies['refresh-token']
  if (!token) return res.status(401).send('Unauthorized')
  try {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, {
      audience: 'urn:jwt:type:refresh'
    })
    const tokenHash = createHmac('sha512', process.env.REFRESH_TOKEN_SECRET!).update(token).digest('hex')
    res.locals.refreshHash = tokenHash
    next()
  } catch (error) {
    return res.status(401).send('Unauthorized')
  }
}

/**
 * ROUTES
 */
const router = Router()

router.post('/login', (req, res: ExtendedResponse) => {
  const { username, password } = req.body
  const user = users.find((user) => user.username === username && user.password === password)
  if (!user) return res.status(401).send('Unauthorized')

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken(user)

  setRefreshCookie(res, refreshToken)
  res.json({ accessToken })
})

router.post('/refresh', withRefreshAuth, (_, res) => {
  const username = refreshTokenDB.get(res.locals.refreshHash)
  const user = users.find((user) => user.username === username)
  if (!username || !user) return res.status(403).send('Could not find user for this refresh token')

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken(user)

  setRefreshCookie(res, refreshToken)
  res.json({ accessToken })
})

router.get('/users/:username', withAccessAuth, (req, res) => {
  const user = users.find((user) => user.username === req.params.username)
  if (!user) return res.status(404).send('User not found')

  res.json(user)
})

router.get('/ping', (_, res) => res.send('pong'))

export const apiRoutes = router
