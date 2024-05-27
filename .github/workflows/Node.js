const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());

const SECRET = 'your_webhook_secret';

function verifySignature(req, res, buf, encoding) {
  const signature = req.headers['x-sonarqube-token'];
  if (!signature) {
    return res.status(401).send('Missing signature');
  }

  const expectedSignature = crypto
    .createHmac('sha256', SECRET)
    .update(buf)
    .digest('hex');

  if (signature !== expectedSignature) {
    return res.status(401).send('Invalid signature');
  }
}

app.post('/webhook', bodyParser.json({ verify: verifySignature }), (req, res) => {
  const { projectKey, status } = req.body;

  if (status === 'completed') {
    // Fetch and display SonarQube warnings for the project
    console.log(`SonarQube analysis completed for project: ${projectKey}`);
    // Add more logic to fetch and display the specific warnings
  }

  res.status(200).send('Webhook received');
});

app.listen(3000, () => {
  console.log('Webhook receiver listening on port 3000');
});
