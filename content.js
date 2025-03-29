// Function to extract email content and sender from Gmail's DOM.
// Adjust selectors based on Gmail's structure.
function extractEmailData(emailElement) {
    const content = emailElement.innerText;
    const senderElement = emailElement.querySelector('.gD');
    const sender = senderElement ? senderElement.getAttribute('email') : '';
    const emailId = emailElement.getAttribute('data-message-id') || Date.now().toString();
    return { id: emailId, content, sender };
  }
  
  // Function to send a single email for phishing detection
  function analyzeEmail(emailData) {
    return fetch("http://127.0.0.1:5002/api/detect-phishing", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email: emailData })
    })
    .then(response => response.json())
    .catch(err => {
      console.error("Error calling phishing detection API:", err);
      return null;
    });
  }
  
  // Function to display the analysis result as an overlay on Gmail
  function displayResult(result) {
    let overlay = document.getElementById("phishingOverlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "phishingOverlay";
      overlay.style.position = "fixed";
      overlay.style.top = "0";
      overlay.style.left = "0";
      overlay.style.width = "100%";
      overlay.style.height = "100%";
      overlay.style.backgroundColor = "rgba(0, 0, 0, 0.8)";
      overlay.style.color = "white";
      overlay.style.zIndex = "10000";
      overlay.style.padding = "20px";
      overlay.style.overflowY = "auto";
      document.body.appendChild(overlay);
    }
    // Build the overlay content
    overlay.innerHTML = `<h2>Phishing Detection Result</h2>`;
    if (result && result.risk_level) {
      overlay.innerHTML += `<p><strong>Risk Level:</strong> ${result.risk_level}</p>`;
      if (result.warnings && result.warnings.length > 0) {
        overlay.innerHTML += `<h3>Warnings:</h3>`;
        result.warnings.forEach(warning => {
          overlay.innerHTML += `<p><strong>${warning.title}:</strong> ${warning.details}</p>`;
        });
      }
    } else {
      overlay.innerHTML += `<p>Error: No valid result received.</p>`;
    }
    // Add a close button
    const closeButton = document.createElement("button");
    closeButton.innerText = "Close";
    closeButton.style.marginTop = "20px";
    closeButton.style.padding = "10px 20px";
    closeButton.style.backgroundColor = "#dc004e";
    closeButton.style.color = "white";
    closeButton.style.border = "none";
    closeButton.style.borderRadius = "5px";
    closeButton.addEventListener("click", () => overlay.remove());
    overlay.appendChild(closeButton);
  }
  
  // Example: Add a button to Gmail for scanning the currently selected/opened email
  function addScanButton() {
    const button = document.createElement("button");
    button.innerText = "Scan This Email for Phishing";
    button.style.position = "fixed";
    button.style.bottom = "20px";
    button.style.right = "20px";
    button.style.zIndex = "10001";
    button.style.padding = "10px 20px";
    button.style.backgroundColor = "#1976d2";
    button.style.color = "white";
    button.style.border = "none";
    button.style.borderRadius = "5px";
    button.style.cursor = "pointer";
    button.addEventListener("click", () => {
      // Find the currently open email container in Gmail (adjust selector as needed)
      const emailElement = document.querySelector(".ii.gt");
      if (!emailElement) {
        alert("No open email found. Please open an email.");
        return;
      }
      const emailData = extractEmailData(emailElement);
      analyzeEmail(emailData).then(result => {
        displayResult(result);
      });
    });
    document.body.appendChild(button);
  }
  
  // Initialize extension functionality
  addScanButton();
  