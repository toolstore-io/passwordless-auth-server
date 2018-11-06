// Load up env from now.json
require('now-env')

const { send, json } = require('micro')
const cors = require('micro-cors')()
const { router, post } = require('microrouter')

const parse = require('urlencoded-body-parser')
const sgMail = require('@sendgrid/mail')
const { generate: shortId } = require('shortid')

const { promisifyAll } = require('bluebird')
const redis = require('redis')
promisifyAll(redis.RedisClient.prototype)
promisifyAll(redis.Multi.prototype)

const jwt = require('jsonwebtoken')

const { flow } = require('lodash')
const { encode, decode } = require('base64url')

// Initialize redis
const client = redis.createClient()

// Get environement variables
const {
  SENDGRID_API_KEY,
  SENDGRID_TEMPLATE_ID,
  FROM_EMAIL,
  JWT_SECRET
} = process.env

sgMail.setApiKey(SENDGRID_API_KEY)

const getMsg = (to, username, auth_link) => ({
  to,
  from: FROM_EMAIL,
  templateId: SENDGRID_TEMPLATE_ID,
  dynamic_template_data: {
    username,
    auth_link
  }
})

const base64UrlEncode = flow(
  JSON.stringify,
  encode
)
const base64UrlDecode = flow(
  decode,
  JSON.parse
)

async function register(req, res) {
  const { email } = await parse(req)

  const tmpAuthToken = shortId()

  const payload = base64UrlEncode({
    tok: tmpAuthToken,
    usr: email
  })

  const authUrl = `http://localhost:3000/auth?payload=${payload}`
  const authenticateMsg = getMsg(email, email, authUrl)

  await sgMail.send(authenticateMsg)

  // Set a token that expires in 3 minutes
  client.set(`tmp:${email}`, tmpAuthToken, 'EX', 3 * 60)

  send(res, 200, 'Email sent, please validate your email.')
}

async function confirm(req, res) {
  const { payload } = await json(req)

  if (!payload) {
    send(res, 400, 'Payload is required')
    return
  }

  const { tok: tempToken, usr: username } = base64UrlDecode(payload)

  if (!tempToken || !username) {
    send(res, 400, 'Token and username required')
    return
  }

  const storedTempToken = await client.getAsync(`tmp:${username}`)

  if (storedTempToken === tempToken) {
    const token = jwt.sign({ username }, JWT_SECRET)
    send(res, 200, token)
  } else {
    send(res, 401, 'Invalid or expired temporary token')
  }
}

module.exports = cors(
  router(post('/register', register), post('/confirm', confirm))
)
