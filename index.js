const express = require('express');
const dns = require('dns').promises;
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());

app.get('/check', async (req, res) => {
  const domain = req.query.domain;

  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' });

  const results = {
    spf: 'unknown',
    dmarc: 'unknown',
    dkim: 'manual check'
  };

  try {
    const txtRecords = await dns.resolveTxt(domain);
    const flat = txtRecords.flat().join('');
    results.spf = flat.includes('v=spf1') ? 'valid' : 'missing';
  } catch {
    results.spf = 'error';
  }

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = dmarcRecords.flat().join('');
    results.dmarc = flat.includes('v=DMARC1') ? 'valid' : 'missing';
  } catch {
    results.dmarc = 'error';
  }

  // DKIM kræver selector og er svær at tjekke uden ekstra info
  res.json(results);
});

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
