import { NextFunction, Request, RequestHandler, Response, Router } from 'express'
import jwt, { JwtPayload } from 'jsonwebtoken'
import { User, users } from './users'

interface ExtendedResponse extends Response<any, { token: string; user: Partial<User> }> {}

export interface AccessTokenPayload extends JwtPayload, Omit<User, 'username' | 'password'> {}

const withAccessAuth = (req: Request, res: ExtendedResponse, next: NextFunction) => {
  const token = req.headers['authorization']?.split('Bearer ')[1]
  if (!token) return res.status(401).send('Unauthorized')
  try {
    const { sub, name, age, social } = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, {
      audience: 'urn:jwt:type:access'
    }) as AccessTokenPayload

    res.locals.token = token
    res.locals.user = { username: sub!, name, age, social }
    next()
  } catch (error) {
    return res.status(401).send('Unauthorized')
  }
}

const withRefreshAuth = (req: Request, res: ExtendedResponse, next: NextFunction) => {
  const token = req.cookies['refresh-token']
  console.table(req.cookies)
  if (!token) return res.status(401).send('Unauthorized')
  try {
    const { sub } = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, {
      audience: 'urn:jwt:type:refresh'
    })
    res.locals.user = { username: sub as string }
    next()
  } catch (error) {
    return res.status(401).send('Unauthorized')
  }
}

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
  return jwt.sign({ sub: user.username }, process.env.ACCESS_TOKEN_SECRET!, {
    audience: 'urn:jwt:type:refresh',
    issuer: 'urn:system:token-issuer:type:refresh',
    expiresIn: `${process.env.REFRESH_TOKEN_DURATION_MINUTES}m`
  })
}

const router = Router()

router.post('/login', (req, res) => {
  const { username, password } = req.body
  const user = users.find((user) => user.username === username && user.password === password)
  if (!user) return res.status(401).send('Unauthorized')

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken(user)

  res.cookie('refresh-token', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' })
  res.json({ accessToken })
})

router.post('/refresh', withRefreshAuth, (_, res) => {
  const user = users.find((user) => user.username === res.locals.user.username)
  if (!user) return res.status(403).send('Could not find user for this refresh token')

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken(user)

  res.cookie('refresh-token', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' })
  res.json({ accessToken })
})

router.get('/users/:username', withAccessAuth, (req, res) => {
  const user = users.find((user) => user.username === req.params.username)
  if (!user) return res.status(404).send('User not found')

  res.json(user)
})

router.get('/ping', (_, res) => res.send('pong'))

export const apiRoutes = router
