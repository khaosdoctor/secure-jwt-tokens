// GLOBAL PROXY
const tokenSymbol = Symbol.for('accessToken')
const refreshIntervalMinutes = 4.5 * 60 * 1000
let internalToken = new Proxy(
  { [tokenSymbol]: null },
  {
    get(target, prop) {
      const primitive = Reflect.get(target, tokenSymbol)
      const value = primitive[prop]
      return typeof value === 'function' ? value.bind(primitive) : value
    },
    set(target, _, value) {
      document.querySelector('#rawToken').innerHTML = value

      const header = atob(value.split('.')[0])
      const payload = JSON.parse(atob(value.split('.')[1]))
      document.querySelector(
        '#decodedToken'
      ).innerHTML = `<strong>Header:</strong>${header}<br>---<br><strong>Payload</strong>: ${JSON.stringify(
        payload,
        null,
        2
      )}<br> <b>Expires at ${new Date(payload.exp * 1000).toLocaleTimeString()}</b>`
      document.querySelector('#refreshAction').disabled = false
      return Reflect.set(target, tokenSymbol, value)
    }
  }
)

// UTILS

function updateMessage(message, selector = '.login-result') {
  const infoBox = document.querySelector(selector)
  infoBox.innerHTML = message
}

function refreshToken() {
  updateMessage('Refreshing token...')
  fetch('/api/refresh', {
    method: 'POST'
  })
    .then((res) => (res.ok ? res.json() : Promise.reject(res.statusText)))
    .then(({ accessToken }) => {
      internalToken[tokenSymbol] = accessToken
      updateMessage('Next refresh at ' + new Date(Date.now() + refreshInternalMinutes).toLocaleTimeString())
    })
    .catch((err) => {
      updateMessage('Error refreshing token: ' + err)
    })
}

// ACTIONS

document.querySelector('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  updateMessage('Logging in...')

  const form = new FormData(e.target)
  const data = Object.fromEntries(form.entries())
  const result = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })

  updateMessage(result.ok ? 'Login successful' : `Login failed with ${result.status}`)
  if (result.status === 200) {
    const response = await result.json()
    internalToken[tokenSymbol] = response.accessToken
    setInterval(refreshToken, refreshIntervalMinutes)
    updateMessage('Next refresh at ' + new Date(Date.now() + refreshIntervalMinutes).toLocaleTimeString())
  }
})

document.querySelector('#userForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  if (!internalToken) return updateMessage('Login first', '.user-result')
  updateMessage('Searching user...', '.user-result')

  const form = new FormData(e.target)
  const data = Object.fromEntries(form.entries())
  const result = await fetch(`/api/users/${data.username}`, {
    headers: {
      Authorization: `Bearer ${internalToken}`
    }
  })
  updateMessage(result.ok ? 'User found' : `Search failed with ${result.status}`, '.user-result')
  if (result.status === 200) {
    const response = await result.json()
    updateMessage(JSON.stringify(response, null, 2), '.user-result')
  }
})

document.querySelector('#refreshAction').addEventListener('click', refreshToken)
