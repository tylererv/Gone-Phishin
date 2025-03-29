// Phishing detection patterns
const PHISHING_PATTERNS = {
    urgentAction: /(urgent|immediate|action required|account suspended|verify account)/i,
    suspiciousLinks: /(bit\.ly|goo\.gl|tinyurl\.com|click here)/i,
    suspiciousSender: /(noreply|support@|account@|security@)/i,
    poorGrammar: /(dear valued customer|dear user|dear account holder)/i
};

// Warning messages for each pattern
const WARNING_MESSAGES = {
    urgentAction: {
        title: 'Urgent Action Required',
        details: 'This email contains urgent or threatening language, which is a common phishing tactic.'
    },
    suspiciousLinks: {
        title: 'Suspicious Links Detected',
        details: 'Contains shortened URLs or generic "click here" links, which may hide malicious destinations.'
    },
    suspiciousSender: {
        title: 'Suspicious Sender Pattern',
        details: 'The sender address matches common phishing patterns (noreply, support, account, security).'
    },
    poorGrammar: {
        title: 'Generic or Suspicious Greeting',
        details: 'Uses generic greetings or poor grammar, which are common in phishing attempts.'
    }
};

// Store phishing email IDs and their warnings
let phishingEmails = new Map();

// Function to analyze email content for phishing indicators
function analyzeEmail(emailElement) {
    const emailContent = emailElement.textContent;
    const warnings = [];

    // Check for urgent action requests
    if (PHISHING_PATTERNS.urgentAction.test(emailContent)) {
        warnings.push('urgentAction');
    }

    // Check for suspicious links
    if (PHISHING_PATTERNS.suspiciousLinks.test(emailContent)) {
        warnings.push('suspiciousLinks');
    }

    // Check for suspicious sender patterns
    if (PHISHING_PATTERNS.suspiciousSender.test(emailContent)) {
        warnings.push('suspiciousSender');
    }

    // Check for poor grammar or generic greetings
    if (PHISHING_PATTERNS.poorGrammar.test(emailContent)) {
        warnings.push('poorGrammar');
    }

    return warnings;
}

// Function to toggle warning details
function toggleWarningDetails(warningDiv) {
    const contentDiv = warningDiv.querySelector('.warning-content');
    const isExpanded = contentDiv.classList.contains('expanded');
    
    // Toggle the expanded class
    contentDiv.classList.toggle('expanded');
    
    // If we're expanding, ensure the content is visible before animating
    if (!isExpanded) {
        contentDiv.style.display = 'block';
        // Force a reflow
        contentDiv.offsetHeight;
        contentDiv.classList.add('expanded');
    } else {
        // If we're collapsing, wait for the animation to complete
        contentDiv.addEventListener('transitionend', function handler() {
            contentDiv.style.display = 'none';
            contentDiv.removeEventListener('transitionend', handler);
        }, { once: true });
    }
}

// Function to add warning label to email
function addWarningLabel(emailElement, warnings) {
    if (warnings.length > 0) {
        const warningDiv = document.createElement('div');
        warningDiv.className = 'phishing-warning';
        
        // Create warning messages
        const warningMessages = warnings.map(warning => WARNING_MESSAGES[warning]);
        
        warningDiv.innerHTML = `
            <div class="warning-icon">⚠️</div>
            <div class="warning-content">
                <div class="warning-text">
                    <strong>Potential Phishing Email</strong>
                    <div class="warning-details">
                        ${warningMessages.map(msg => `
                            <div>• ${msg.title}: ${msg.details}</div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
        
        emailElement.insertBefore(warningDiv, emailElement.firstChild);
        
        // Store the email ID and warnings
        const emailId = emailElement.getAttribute('data-message-id') || Date.now().toString();
        emailElement.setAttribute('data-message-id', emailId);
        phishingEmails.set(emailId, warnings);
    }
}

// Function to update phishing count display
function updatePhishingCount() {
    let counterDisplay = document.getElementById('phishing-counter');
    if (!counterDisplay) {
        counterDisplay = document.createElement('div');
        counterDisplay.id = 'phishing-counter';
        counterDisplay.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: #dc3545;
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            z-index: 9999;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        `;
        document.body.appendChild(counterDisplay);
    }
    counterDisplay.textContent = `Phishing Emails Detected: ${phishingEmails.size}`;
}

// Function to scan all visible emails
function scanAllEmails() {
    const emailElements = document.querySelectorAll('.zA');
    let newPhishingCount = 0;

    emailElements.forEach((emailElement) => {
        const emailId = emailElement.getAttribute('data-message-id');
        if (!emailId || !phishingEmails.has(emailId)) {
            const warnings = analyzeEmail(emailElement);
            if (warnings.length > 0) {
                addWarningLabel(emailElement, warnings);
                newPhishingCount++;
            }
        }
    });

    if (newPhishingCount > 0) {
        updatePhishingCount();
        // Notify popup of the update
        chrome.runtime.sendMessage({
            type: 'PHISHING_COUNT_UPDATE',
            count: phishingEmails.size
        });
    }

    return newPhishingCount;
}

// Function to remove phishing email from tracking
function removePhishingEmail(emailElement) {
    const emailId = emailElement.getAttribute('data-message-id');
    if (emailId && phishingEmails.has(emailId)) {
        phishingEmails.delete(emailId);
        const warningDiv = emailElement.querySelector('.phishing-warning');
        if (warningDiv) {
            warningDiv.remove();
        }
    }
}

// Observer to watch for email actions
const emailObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        mutation.removedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE && node.classList.contains('zA')) {
                removePhishingEmail(node);
            }
        });
    });
});

// Start observing the Gmail inbox for email actions
const inboxContainer = document.querySelector('.AO');
if (inboxContainer) {
    emailObserver.observe(inboxContainer, {
        childList: true,
        subtree: true
    });
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'GET_COUNT') {
        sendResponse({ 
            success: true, 
            count: phishingEmails.size
        });
    }
    return true;
});

// Handle email open events
document.addEventListener('click', (event) => {
    const emailElement = event.target.closest('.zA');
    if (emailElement) {
        const emailId = emailElement.getAttribute('data-message-id');
        if (emailId && phishingEmails.has(emailId)) {
            // Remove the warning when email is opened
            removePhishingEmail(emailElement);
        }
    }
});

// Start automatic scanning
function startAutoScan() {
    // Initial scan
    scanAllEmails();
    
    // Set up periodic scanning
    setInterval(scanAllEmails, 5000);
    
    // Set up observer for new emails
    const inboxObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.addedNodes.length > 0) {
                scanAllEmails();
            }
        });
    });

    // Start observing the inbox for new emails
    const inboxContainer = document.querySelector('.AO');
    if (inboxContainer) {
        inboxObserver.observe(inboxContainer, {
            childList: true,
            subtree: true
        });
    }
}

// Start the automatic scanning when the page loads
if (document.readyState === 'complete') {
    startAutoScan();
} else {
    window.addEventListener('load', startAutoScan);
} 