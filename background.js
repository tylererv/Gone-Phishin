// Listen for installation event of the Chrome extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phishing Email Detector installed'); // Log a message when the extension is installed
});

// Listen for messages from the content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Check if the message type is 'PHISHING_DETECTED'
    if (request.type === 'PHISHING_DETECTED') {
        // Handle phishing detection notification by logging the details
        console.log('Phishing email detected:', request.details);
    }
    return true; // Keep the message channel open for asynchronous response
});
