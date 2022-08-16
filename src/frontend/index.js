// GLOBAL PROXY
const accessSymbol = Symbol.for('accessToken')
document[accessSymbol] = null

Object.defineProperty(document, 'accessToken', {
  get() {
    return document[accessSymbol]
  },
  set(v) {
    document.querySelector('#rawToken').innerHTML = v

    const header = atob(v.split('.')[0])
    const payload = JSON.parse(atob(v.split('.')[1]))
    document.querySelector(
      '#decodedToken'
    ).innerHTML = `<strong>Header:</strong>${header}<br>---<br><strong>Payload</strong>: ${JSON.stringify(
      payload,
      null,
      2
    )}<br> <b>Expires at ${new Date(payload.exp * 1000).toLocaleTimeString()}</b>`

    document[accessSymbol] = v
    return v
  }
})

// UTILS

function updateMessage(message, selector = '.login-result') {
  const infoBox = document.querySelector(selector)
  // if (infoBox.innerHTML.length > 0 && infoBox.innerHTML !== message) {
  //   return setTimeout(() => (infoBox.innerHTML = message), 600)
  // }
  infoBox.innerHTML = message
}

function refreshToken() {
  updateMessage('Refreshing token...')
  fetch('/api/refresh', {
    method: 'POST'
  })
    .then((res) => res.json())
    .then(({ accessToken }) => {
      document.accessToken = accessToken
      updateMessage(
        'Refreshing token every 4.5 minutes. Next refresh at ' +
          new Date(Date.now() + 4.5 * 60 * 1000).toLocaleTimeString()
      )
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
    document.accessToken = response.accessToken
    setInterval(refreshToken, 4.5 * 60 * 1000)
    updateMessage(
      'Refreshing token every 4.5 minutes. Next refresh at ' +
        new Date(Date.now() + 4.5 * 60 * 1000).toLocaleTimeString()
    )
  }
})

document.querySelector('#userForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  if (!document.accessToken) return updateMessage('Login first', '.user-result')
  updateMessage('Searching user...', '.user-result')

  const form = new FormData(e.target)
  const data = Object.fromEntries(form.entries())
  const result = await fetch(`/api/users/${data.username}`, {
    headers: {
      Authorization: `Bearer ${document.accessToken}`
    }
  })
  updateMessage(result.ok ? 'User found' : `Search failed with ${result.status}`, '.user-result')
  if (result.status === 200) {
    const response = await result.json()
    updateMessage(JSON.stringify(response, null, 2), '.user-result')
  }
})
