document.getElementById('filterButton').addEventListener('click', async () => {
  const statusDiv = document.getElementById('status');
  statusDiv.textContent = 'Scanning emails...';

  try {
    // Get the active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      throw new Error('No active tab found');
    }

    // Ensure we're on Gmail
    if (!tab.url.includes('mail.google.com')) {
      statusDiv.textContent = 'Please open Gmail to scan emails';
      return;
    }

    // Inject content script if not already injected
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content.js']
    });

    // Send message to content script to start scanning
    chrome.tabs.sendMessage(tab.id, { action: 'SCAN_EMAILS' }, (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError);
        statusDiv.textContent = 'Error: Please refresh Gmail and try again';
        return;
      }
      
      if (response && response.success) {
        if (response.newFound > 0) {
          statusDiv.textContent = `Found ${response.newFound} new phishing emails (Total: ${response.count})`;
        } else {
          statusDiv.textContent = `No new phishing emails found (Total: ${response.count})`;
        }
      } else {
        statusDiv.textContent = 'No phishing emails detected';
      }
    });
  } catch (error) {
    console.error('Error:', error);
    statusDiv.textContent = 'Error: Please refresh Gmail and try again';
  }
});

// Update phishing count when popup opens
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const tab = tabs[0];
  if (tab.url.includes('mail.google.com')) {
    try {
      // Get the current phishing count from the content script
      chrome.tabs.sendMessage(tab.id, { action: 'GET_COUNT' }, (response) => {
        if (response && response.success) {
          document.getElementById('phishingCount').textContent = response.count;
        }
      });
    } catch (error) {
      console.error('Error:', error);
    }
  }
});

// Listen for updates from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'PHISHING_COUNT_UPDATE') {
    document.getElementById('phishingCount').textContent = request.count;
  }
  return true;
}); 