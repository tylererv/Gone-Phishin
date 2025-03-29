// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phishing Email Detector installed');
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'PHISHING_DETECTED') {
        // Handle phishing detection notification
        console.log('Phishing email detected:', request.details);
    }
    return true;
}); 