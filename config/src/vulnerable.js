// Intentional insecure patterns for Semgrep testing
const express = require('express')
const app = express()

app.get('/user', (req, res) => {
  // SQL injection style
  const q = `SELECT * FROM users WHERE id = '${req.query.id}'`
  res.send(q)
})

app.get('/page', (req, res) => {
  // XSS
  res.send('<div>' + req.query.name + '</div>')
})

eval(req.query.code) // dangerous
