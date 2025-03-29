// Function to extract email content and sender from Gmail's DOM.
// Adjust selectors based on Gmail's current structure.
function extractEmailData(emailElement) {
    const content = emailElement.innerText;
    const senderElement = emailElement.querySelector('.gD');
    const sender = senderElement ? senderElement.getAttribute('email') : '';
    const emailId = emailElement.getAttribute('data-message-id') || Date.now().toString();
    return { id: emailId, content, sender };
  }
  
  // Function to send a single email for phishing analysis via AI.
  function analyzeEmail(emailData) {
    return fetch("http://127.0.0.1:5002/api/detect-phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailData })
    })
      .then(response => response.json())
      .catch(err => {
        console.error("Error calling phishing detection API:", err);
        return null;
      });
  }
  
  // Map the risk level to a verdict string.
  function getVerdict(riskLevel) {
    if (riskLevel === "risky" || riskLevel === "high") {
      return "Scam";
    } else if (riskLevel === "medium") {
      return "Unsure";
    } else if (riskLevel === "none") {
      return "Legit";
    }
    return "Unsure";
  }
  
  // Function to display the analysis result in a centered, transparent popup that fits the text.
  function displayResult(result) {
    let popup = document.getElementById("phishingPopup");
    if (!popup) {
      popup = document.createElement("div");
      popup.id = "phishingPopup";
      // Centered popup styling
      popup.style.position = "fixed";
      popup.style.top = "50%";
      popup.style.left = "50%";
      popup.style.transform = "translate(-50%, -50%)";
      popup.style.backgroundColor = "rgba(0, 0, 0, 0.7)"; // semi-transparent black
      popup.style.padding = "20px";
      popup.style.borderRadius = "8px";
      popup.style.boxShadow = "0 0 10px rgba(0,0,0,0.5)";
      popup.style.maxWidth = "80%";
      popup.style.zIndex = "10000";
      popup.style.color = "white";
      document.body.appendChild(popup);
    }
    
    // Determine verdict from risk_level
    const verdict = getVerdict(result.risk_level);
  
    // Build the popup content. Add a line break after the title.
    popup.innerHTML = `<h2>Phishing Detection Result: ${verdict}</h2><br>`;
    
    // Display the risk summary (assumed to be in the details of the first warning)
    if (result && result.warnings && result.warnings.length > 0 && result.warnings[0].details) {
      // Display the AI's risk summary as a flowing sentence.
      popup.innerHTML += `<p>${result.warnings[0].details}</p>`;
    } else {
      popup.innerHTML += `<p>The email appears safe.</p>`;
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
    closeButton.style.cursor = "pointer";
    closeButton.addEventListener("click", () => popup.remove());
    popup.appendChild(closeButton);
  }
  
  // Example: Add a button to Gmail for scanning the currently open email.
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
  
  // Initialize extension functionality.
  addScanButton();
  