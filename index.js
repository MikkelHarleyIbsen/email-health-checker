const express = require('express');
const dns = require('dns');
const app = express();
const port = 3000;

// Middleware til at håndtere JSON-body
app.use(express.json());

// API-endpoint til at tjekke domænet
app.post('/check-domain', (req, res) => {
  const domain = req.body.domain;

  // Tjek om domænet findes i DNS
  dns.resolveTxt(domain, (err, records) => {
    if (err) {
      return res.status(400).json({ message: 'Fejl ved opdatering af DNS-poster', valid: false });
    }

    // Tjek SPF-posten
    let spfValid = false;
    let dkimValid = false;
    let dmarcValid = false;

    // Gennemgå TXT-posterne og tjek for SPF, DKIM og DMARC
    records.forEach((record) => {
      if (record[0].startsWith('v=spf1')) {
        spfValid = true;
      }
      if (record[0].startsWith('v=DMARC1')) {
        dmarcValid = true;
      }
      if (record[0].startsWith('v=DKIM1')) {
        dkimValid = true;
      }
    });

    // Returnér resultatet
    if (spfValid && dkimValid && dmarcValid) {
      return res.status(200).json({ message: 'Domænet er sundt!', valid: true });
    } else {
      return res.status(200).json({
        message: 'Domænet har fejl i SPF, DKIM eller DMARC.',
        valid: false,
        errors: { spf: spfValid, dkim: dkimValid, dmarc: dmarcValid }
      });
    }
  });
});

app.listen(port, () => {
  console.log(`Server kører på http://localhost:${port}`);
});
