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