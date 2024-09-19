
async function calculateSHA256(file) {
  const fileReader = new FileReader();

  return new Promise((resolve, reject) => {
    fileReader.onload = async function(event) {
      try {
        const arrayBuffer = event.target.result;
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        resolve(hashHex);
      } catch (error) {
        reject(error);
        console.log("Error occured while hashing: "+error);
      }
    };
    fileReader.readAsArrayBuffer(file);
  });
}

async function checkFileHashWithVirusTotal(hash) {
  const apiKey = '9c420b58ed889d3cc9ae3529d2a9745868e9f8dac65da74673230158f12dcabd'; 

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'accept': 'application/json'
      }
    });
    const data = await response.json();

    if (data.data && data.data.attributes) {
      const positives = data.data.attributes.last_analysis_stats.malicious;
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'folder.png',
        title: 'Scan Complete',
        message: positives > 0 ? 
          `Warning: File may contain a virus.` : 
          `File is clean.`
      });
    } else {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'folder.png',
        title: 'Scan Result',
        message: 'No scan results available.'
      });
    }
  } catch (error) {
    console.error('Error checking file hash:', error);
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'folder.png',
      title: 'Scan Failed',
      message: 'Error checking file hash with VirusTotal.'
    });
  }
}


chrome.downloads.onCreated.addListener(async (downloadItem) => {
  try {
   
    // reteive file data
    const response = await fetch(downloadItem.url);
    const blob = await response.blob();

    // clculate SHA-256
    const hash = await calculateSHA256(blob);

    // Messege 
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'folder.png',
      title: 'Scan in Progress',
      message: `File SHA-256 hash: ${hash}`
    });

    // Check hash with VirusTotal
    await checkFileHashWithVirusTotal(hash);

  } catch (error) {
    console.error('Error processing download:', error);
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'folder.png',
      title: 'Scan Failed',
      message: 'Error processing download.'
    });
  }
});
